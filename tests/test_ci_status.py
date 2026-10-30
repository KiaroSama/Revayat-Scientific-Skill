"""Native commit statuses must reflect every real hosted validation job."""
import importlib.util
import io
import logging
from pathlib import Path
import unittest
from unittest import mock
from urllib.error import HTTPError

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('ci_status', ROOT / 'tools/publish-ci-status.py')
STATUS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(STATUS)
REPO = 'example/project'
SHA = 'a' * 40
RUN = 123


def job(name, identifier, conclusion='success', attempt=1):
    return {'id': identifier, 'name': name, 'run_id': RUN, 'run_attempt': attempt,
            'head_sha': SHA, 'status': 'completed', 'conclusion': conclusion,
            'html_url': f'https://github.com/{REPO}/actions/runs/{RUN}/job/{identifier}'}


class GitHubFixture:
    """Only the external GitHub boundary is replaced; reporter policy is real."""
    def __init__(self, jobs=None, previous=None):
        self.jobs = jobs if jobs is not None else [
            job(name, index + 1) for index, name in enumerate(STATUS.REQUIRED_JOBS)]
        self.previous = previous or []
        self.run = {'id': RUN, 'head_sha': SHA, 'run_attempt': 1,
                    'event': 'workflow_dispatch', 'path': '.github/workflows/ci.yml',
                    'repository': {'full_name': REPO}}
        self.published = []
        self.gets = []
        self.fail_context = None

    def get(self, path):
        self.gets.append(path)
        if '/jobs?' in path:
            page = int(path.rsplit('page=', 1)[1])
            return {'total_count': len(self.jobs), 'jobs': self.jobs[(page - 1) * 100:page * 100]}
        if '/status?' in path:
            page = int(path.rsplit('page=', 1)[1])
            return {'total_count': len(self.previous),
                    'statuses': self.previous[(page - 1) * 100:page * 100]}
        return dict(self.run)

    def post(self, path, body):
        if body['context'] == self.fail_context:
            raise RuntimeError('controlled API failure')
        self.published.append((path, dict(body)))
        return {'state': body['state'], 'context': body['context']}


class CiStatusTest(unittest.TestCase):
    def report(self, api, phase='final', attempt=1):
        return STATUS.publish(api, REPO, SHA, RUN, attempt, phase, logging.getLogger('ci-test'))

    def states(self, api):
        return {body['context']: body for _, body in api.published}

    def test_required_census_matches_all_existing_matrix_and_reusable_jobs(self):
        self.assertEqual(set(STATUS.REQUIRED_JOBS), {
            'security / linux-security', 'security / windows-security',
            'codeql / analyse', 'dependency-review / review',
            'portable (ubuntu-latest, 3.11)', 'portable (macos-latest, 3.14)',
            'portable (windows-latest, 3.13)', 'scientific', 'quality',
        })
        self.assertEqual(len(STATUS.REQUIRED_JOBS), 9)

    def test_all_real_jobs_have_their_own_true_result_and_direct_link(self):
        api = GitHubFixture()
        api.jobs[0]['conclusion'] = 'failure'
        api.jobs += [job('additional validation', 40, 'failure'),
                     job('status-final', 41, None), job('status-pending', 42)]
        self.report(api)
        states = self.states(api)
        self.assertEqual(len(states), 11)
        self.assertEqual(states['ci/security / linux-security']['state'], 'failure')
        self.assertEqual(states['ci/scientific']['state'], 'success')
        self.assertEqual(states['ci/additional validation']['state'], 'failure')
        self.assertEqual(states['ci/additional validation']['target_url'],
                         'https://github.com/example/project/actions/runs/123/job/40')
        self.assertEqual(states['ci/manual-summary']['state'], 'failure')
        self.assertIn('8 passed, 2 failed', states['ci/manual-summary']['description'])
        self.assertNotIn('ci/status-final', states)
        self.assertTrue(all(path == f'repos/{REPO}/statuses/{SHA}' for path, _ in api.published))

    def test_pending_resets_expected_and_old_contexts_without_claiming_results(self):
        api = GitHubFixture(previous=[{'context': 'ci/old validation'}, {'context': 'external/check'}])
        self.report(api, 'pending')
        states = self.states(api)
        self.assertIn('ci/old validation', states)
        self.assertNotIn('external/check', states)
        self.assertEqual(len(states), 11)
        self.assertEqual({body['state'] for body in states.values()}, {'pending'})

    def test_every_non_success_conclusion_stays_non_green(self):
        for conclusion, expected in [('failure', 'failure'), ('timed_out', 'failure'),
                                     ('action_required', 'failure'), ('cancelled', 'error'),
                                     ('skipped', 'error'), ('neutral', 'error'),
                                     ('stale', 'error'), ('unexpected', 'error'), (None, 'error')]:
            with self.subTest(conclusion=conclusion):
                api = GitHubFixture()
                api.jobs[0]['conclusion'] = conclusion
                self.report(api)
                self.assertEqual(self.states(api)['ci/security / linux-security']['state'], expected)
                self.assertNotEqual(self.states(api)['ci/manual-summary']['state'], 'success')
        api = GitHubFixture()
        api.jobs[0].update(status='in_progress', conclusion=None)
        self.report(api)
        self.assertEqual(self.states(api)['ci/security / linux-security']['state'], 'pending')
        self.assertEqual(self.states(api)['ci/manual-summary']['state'], 'pending')

    def test_missing_and_retired_jobs_are_explicit_errors(self):
        api = GitHubFixture(previous=[{'context': 'ci/retired'}])
        api.jobs.pop(0)
        self.assertEqual(self.report(api), 'error')
        states = self.states(api)
        self.assertEqual(states['ci/security / linux-security']['state'], 'error')
        self.assertEqual(states['ci/retired']['state'], 'error')
        self.assertEqual(states['ci/manual-summary']['state'], 'error')

    def test_complete_pagination_and_partial_rerun_successes_are_retained(self):
        api = GitHubFixture()
        api.run['run_attempt'] = 2
        api.jobs += [job(f'validation {index}', index + 100, attempt=2) for index in range(105)]
        self.report(api, attempt=2)
        self.assertEqual(len(self.states(api)), 115)
        self.assertIn('ci/validation 104', self.states(api))
        self.assertEqual(self.states(api)['ci/scientific']['state'], 'success')
        self.assertEqual(sum('/jobs?' in path for path in api.gets), 2)
        self.assertTrue(all('filter=all' in path for path in api.gets if '/jobs?' in path))

    def test_rerun_replaces_only_jobs_with_a_newer_actual_result(self):
        api = GitHubFixture()
        api.run['run_attempt'] = 2
        api.jobs[0]['conclusion'] = 'failure'
        api.jobs.extend([job('security / linux-security', 60, 'success', 2),
                         job('quality', 61, 'failure', 2)])
        self.report(api, attempt=2)
        states = self.states(api)
        self.assertEqual(len(states), 10)
        self.assertEqual(states['ci/security / linux-security']['state'], 'success')
        self.assertEqual(states['ci/security / linux-security']['target_url'],
                         'https://github.com/example/project/actions/runs/123/job/60')
        self.assertEqual(states['ci/quality']['state'], 'failure')
        self.assertIn('attempt 1', states['ci/scientific']['description'])

    def test_only_latest_pending_publisher_outcome_affects_summary(self):
        api = GitHubFixture()
        api.run['run_attempt'] = 2
        api.jobs.extend([job('status-pending', 60, 'failure'),
                         job('status-pending', 61, 'success', 2)])
        self.report(api, attempt=2)
        self.assertEqual(self.states(api)['ci/manual-summary']['state'], 'success')
        api = GitHubFixture()
        api.jobs.append(job('status-pending', 60, 'failure'))
        self.report(api)
        self.assertEqual(self.states(api)['ci/manual-summary']['state'], 'error')

    def test_wrong_run_revision_attempt_event_repository_or_workflow_never_publishes(self):
        for key, value in [('id', 124), ('head_sha', 'b' * 40), ('run_attempt', 2),
                           ('event', 'push'), ('path', '.github/workflows/other.yml'),
                           ('repository', {'full_name': 'another/project'})]:
            with self.subTest(key=key):
                api = GitHubFixture()
                api.run[key] = value
                with self.assertRaises(ValueError):
                    self.report(api)
                self.assertEqual(api.published, [])

    def test_bad_job_identity_urls_and_context_collisions_fail_without_green(self):
        for change in [{'run_id': 999}, {'head_sha': 'b' * 40}, {'run_attempt': 2},
                       {'html_url': 'https://outside.invalid/job/1'}, {'name': 'manual-summary'},
                       {'name': 'unsafe\nlabel'}, {'id': 0}]:
            with self.subTest(change=change):
                api = GitHubFixture()
                api.jobs[0].update(change)
                with self.assertRaises(ValueError):
                    self.report(api)
                self.assertFalse(any(body['state'] == 'success' for _, body in api.published))
        api = GitHubFixture()
        api.jobs.append(job('SCIENTIFIC', 99))
        with self.assertRaises(ValueError):
            self.report(api)

    def test_inconsistent_or_unbounded_pages_are_rejected(self):
        api = GitHubFixture()
        original = api.get
        for result in [{'total_count': 1001, 'jobs': []}, {'total_count': 2, 'jobs': []},
                       {'total_count': 1, 'jobs': [job('one', 1), job('two', 2)]}]:
            with self.subTest(result=result):
                api.get = lambda path: result if '/jobs?' in path else original(path)
                with self.assertRaises(ValueError):
                    self.report(api)
                self.assertFalse(any(body['state'] == 'success' for _, body in api.published))

    def test_superseded_attempt_never_overwrites_new_results_with_failure(self):
        api = GitHubFixture()
        original = api.get

        def changed_attempt(path):
            value = original(path)
            if '/jobs?' in path:
                api.run['run_attempt'] = 2
            return value

        api.get = changed_attempt
        with self.assertRaises(ValueError):
            self.report(api)
        self.assertEqual(len(api.published), 1)
        self.assertEqual(api.published[0][1]['state'], 'pending')

    def test_partial_write_failure_leaves_aggregate_error_and_propagates(self):
        api = GitHubFixture()
        api.fail_context = 'ci/scientific'
        with self.assertRaises(RuntimeError):
            self.report(api)
        self.assertEqual(self.states(api)['ci/manual-summary']['state'], 'error')
        self.assertEqual(api.published[0][1]['state'], 'pending')

    def test_http_timeout_cap_utf8_and_secret_safe_errors(self):
        response = mock.MagicMock()
        response.__enter__.return_value = response
        response.read.return_value = b'{"ok": true}'
        opener = mock.Mock()
        opener.open.return_value = response
        with mock.patch.object(STATUS, 'build_opener', return_value=opener):
            api = STATUS.GitHub('private-test-token')
            self.assertEqual(api.get('repos/example/project'), {'ok': True})
            self.assertEqual(opener.open.call_args.kwargs['timeout'], 15)
            self.assertEqual(response.read.call_args.args, (8 * 1024 * 1024 + 1,))
            response.read.return_value = b'\xff'
            with self.assertRaises(ValueError):
                api.get('repos/example/project')
            response.read.return_value = b'x' * (8 * 1024 * 1024 + 1)
            with self.assertRaises(ValueError):
                api.get('repos/example/project')
            opener.open.side_effect = HTTPError('private-test-token', 403, 'secret response', {}, io.BytesIO())
            with self.assertRaisesRegex(RuntimeError, 'HTTP 403') as caught:
                api.get('repos/example/project')
            self.assertNotIn('private-test-token', str(caught.exception))
            self.assertNotIn('secret response', str(caught.exception))

    def test_redirects_never_forward_credentials(self):
        redirect = STATUS.NoRedirect()
        self.assertIsNone(redirect.redirect_request(None, None, 302, 'Found', {},
                                                   'https://outside.invalid/'))

    def test_workflow_retains_manual_trigger_and_complete_final_dependency_set(self):
        source = (ROOT / '.github/workflows/ci.yml').read_text(encoding='utf-8')
        self.assertIn('  workflow_dispatch:', source)
        self.assertNotIn('  workflow_run:', source)
        final = source.split('  status-final:\n', 1)[1]
        self.assertIn('    if: ${{ always() }}', final)
        self.assertIn('needs: [status-pending, security, codeql, dependency-review, portable, scientific, quality]', final)
        self.assertIn('statuses: write', final)
        self.assertIn('actions: read', final)
        self.assertNotIn('continue-on-error', final)
        self.assertIn('tools/publish-ci-status.py final', final)


if __name__ == '__main__':
    unittest.main()
