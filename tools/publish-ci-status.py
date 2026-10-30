#!/usr/bin/env python3
"""Mirror real manual-CI job outcomes into native commit-status contexts."""
import argparse
from collections import Counter
import json
import os
from pathlib import Path
import re
import sys
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, Request, build_opener

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'skills/revayat-scientific/scripts'))
from runtime import operation_log

REQUIRED_JOBS = (
    'security / linux-security', 'security / windows-security', 'codeql / analyse',
    'dependency-review / review', 'portable (ubuntu-latest, 3.11)',
    'portable (macos-latest, 3.14)', 'portable (windows-latest, 3.13)',
    'scientific', 'quality',
)
META_JOBS = {'status-pending', 'status-final'}
SUMMARY = 'ci/manual-summary'
MAX_ITEMS = 1000


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class GitHub:
    def __init__(self, token):
        if not token or any(character.isspace() for character in token):
            raise ValueError('a nonempty GitHub token is required')
        self.token = token
        self.opener = build_opener(NoRedirect())

    def request(self, path, body=None):
        if not re.fullmatch(r'[A-Za-z0-9_./?=&,()-]+', path) or not path.startswith('repos/'):
            raise ValueError('invalid GitHub API path')
        data = None if body is None else json.dumps(body, ensure_ascii=True).encode('utf-8')
        request = Request('https://api.github.com/' + path, data=data, headers={
            'Authorization': 'Bearer ' + self.token,
            'Accept': 'application/vnd.github+json',
            'Content-Type': 'application/json; charset=utf-8',
            'X-GitHub-Api-Version': '2026-03-10',
            'User-Agent': 'revayat-ci-status',
        })
        try:
            with self.opener.open(request, timeout=15) as response:
                raw = response.read(8 * 1024 * 1024 + 1)
        except HTTPError as error:
            code = error.code
            error.close()
            raise RuntimeError(f'GitHub status API returned HTTP {code}') from None
        except (URLError, OSError, ValueError):
            raise RuntimeError('GitHub status API request failed') from None
        if len(raw) > 8 * 1024 * 1024:
            raise ValueError('GitHub status API response exceeded 8 MiB')
        try:
            value = json.loads(raw.decode('utf-8'))
        except (UnicodeError, ValueError):
            raise ValueError('GitHub status API response is not UTF-8 JSON') from None
        if not isinstance(value, dict):
            raise ValueError('GitHub status API response must be an object')
        return value

    def get(self, path):
        return self.request(path)

    def post(self, path, body):
        return self.request(path, body)


def pages(api, path, field):
    items, total = [], None
    separator = '&' if '?' in path else '?'
    for page in range(1, 11):
        response = api.get(f'{path}{separator}per_page=100&page={page}')
        count, batch = response.get('total_count'), response.get(field)
        if (type(count) is not int or not 0 <= count <= MAX_ITEMS or
                not isinstance(batch, list) or len(batch) > 100 or
                not all(isinstance(item, dict) for item in batch) or
                (total is not None and total != count)):
            raise ValueError('inconsistent or excessive GitHub result count')
        total = count
        items.extend(batch)
        if len(items) == total:
            return items
        if not batch or len(items) > total:
            raise ValueError('incomplete GitHub result pagination')
    raise ValueError('GitHub result pagination exceeded ten pages')


def context_for(name):
    if (not isinstance(name, str) or not 1 <= len(name) <= 137 or
            any(not 32 <= ord(character) <= 126 for character in name) or
            name.strip() != name or name.casefold() == 'manual-summary'):
        raise ValueError('invalid or reserved CI validation job name')
    return 'ci/' + name


def validate_run(api, repository, sha, run_id, attempt):
    run = api.get(f'repos/{repository}/actions/runs/{run_id}')
    if (run.get('id') != run_id or run.get('head_sha') != sha or
            run.get('run_attempt') != attempt or run.get('event') != 'workflow_dispatch' or
            run.get('path') != '.github/workflows/ci.yml' or
            run.get('repository', {}).get('full_name', '').casefold() != repository.casefold()):
        raise ValueError('CI run repository, revision, workflow or attempt changed')


def job_results(jobs, repository, sha, run_id, attempt):
    latest, ids, generations = {}, set(), set()
    for job in jobs:
        identifier, name = job.get('id'), job.get('name')
        context = context_for(name)
        job_attempt = job.get('run_attempt')
        url = f'https://github.com/{repository}/actions/runs/{run_id}/job/{identifier}'
        generation = (context.casefold(), job_attempt)
        if (type(identifier) is not int or identifier <= 0 or identifier in ids or
                job.get('run_id') != run_id or job.get('head_sha') != sha or
                type(job_attempt) is not int or not 1 <= job_attempt <= attempt or
                generation in generations or job.get('html_url') != url):
            raise ValueError('CI job identity, context, revision, attempt or link is invalid')
        ids.add(identifier)
        generations.add(generation)
        previous = latest.get(context.casefold())
        if previous is None or job_attempt > previous['run_attempt']:
            latest[context.casefold()] = job
    result = {}
    for job in latest.values():
        name = job['name']
        if name in META_JOBS:
            continue
        context, job_attempt, url = context_for(name), job['run_attempt'], job['html_url']
        conclusion = job.get('conclusion')
        if job.get('status') != 'completed':
            state, label = 'pending', 'not completed'
        elif conclusion == 'success':
            state, label = 'success', 'success'
        elif conclusion in ('failure', 'timed_out', 'action_required'):
            state, label = 'failure', conclusion
        else:
            state = 'error'
            label = conclusion if conclusion in ('cancelled', 'skipped', 'neutral', 'stale') else 'unknown'
        result[context] = {'state': state, 'target_url': url,
                           'description': f'Run {run_id}, attempt {job_attempt}: {label}'}
    return result


def publish(api, repository, sha, run_id, attempt, phase, logger):
    if (not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9-]*/[A-Za-z0-9_.-]+', repository) or
            not re.fullmatch(r'[0-9a-f]{40}', sha) or type(run_id) is not int or run_id <= 0 or
            type(attempt) is not int or attempt <= 0 or phase not in ('pending', 'final')):
        raise ValueError('invalid CI reporting identity or phase')
    validate_run(api, repository, sha, run_id, attempt)
    run_url = f'https://github.com/{repository}/actions/runs/{run_id}'
    path = f'repos/{repository}/statuses/{sha}'

    def send(context, body):
        api.post(path, {'context': context, **body})
        logger.info('published context=%s state=%s run=%d attempt=%d',
                    context, body['state'], run_id, attempt)
        print(f'CI status: {context} = {body["state"]}', flush=True)

    try:
        send(SUMMARY, {'state': 'pending', 'target_url': run_url,
                       'description': f'Run {run_id}, attempt {attempt}: publishing job outcomes'})
        prior = pages(api, f'repos/{repository}/commits/{sha}/status', 'statuses')
        contexts = {context_for(name).casefold(): context_for(name) for name in REQUIRED_JOBS}
        for status in prior:
            context = status.get('context', '')
            if context.casefold().startswith('ci/') and context.casefold() != SUMMARY:
                contexts.setdefault(context.casefold(), context_for(context[3:]))
        reporting_failed = False
        if phase == 'pending':
            results = {context: {'state': 'pending', 'target_url': run_url,
                                'description': f'Run {run_id}, attempt {attempt}: awaiting CI results'}
                       for context in contexts.values()}
        else:
            jobs = pages(api, f'repos/{repository}/actions/runs/{run_id}/jobs?filter=all', 'jobs')
            results = job_results(jobs, repository, sha, run_id, attempt)
            pending = max((job for job in jobs if job['name'] == 'status-pending'),
                          key=lambda job: job['run_attempt'], default=None)
            reporting_failed = pending is not None and (
                pending.get('status'), pending.get('conclusion')) != ('completed', 'success')
            seen = {context.casefold() for context in results}
            for key, context in contexts.items():
                if key not in seen:
                    results[context] = {'state': 'error', 'target_url': run_url,
                                        'description': f'Run {run_id}: job missing from latest results'}
        # A partial rerun retains successes from earlier attempts, but a
        # superseded reporter must not publish over a newer attempt.
        validate_run(api, repository, sha, run_id, attempt)
        for context, body in sorted(results.items()):
            send(context, body)
        counts = Counter(body['state'] for body in results.values())
        state = next((value for value in ('error', 'failure', 'pending') if counts[value]), 'success')
        description = (f'{counts["success"]} passed, {counts["failure"]} failed, '
                       f'{counts["error"]} unavailable, {counts["pending"]} pending')
        if reporting_failed:
            state, description = 'error', 'Initial CI status publisher failed; inspect status-pending'
        send(SUMMARY, {'state': state, 'target_url': run_url, 'description': description})
    except Exception:
        try:
            validate_run(api, repository, sha, run_id, attempt)
            send(SUMMARY, {'state': 'error', 'target_url': run_url,
                           'description': 'CI status publication failed; inspect the reporting job'})
        except Exception:
            logger.error('could not publish reporting failure')
        raise
    logger.info('report_complete phase=%s jobs=%d state=%s', phase, len(results), state)
    print(f'CI statuses: {len(results)} individual jobs; aggregate={state}')
    return state


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('phase', choices=('pending', 'final'))
    args = parser.parse_args()
    with operation_log('ci-status', ROOT / 'logs') as logger:
        try:
            state = publish(GitHub(os.environ.get('GH_TOKEN', '')), os.environ.get('GITHUB_REPOSITORY', ''),
                    os.environ.get('GITHUB_SHA', ''), int(os.environ.get('GITHUB_RUN_ID', '0')),
                    int(os.environ.get('GITHUB_RUN_ATTEMPT', '0')), args.phase, logger)
        except Exception as error:
            logger.error('reporting_failed type=%s', type(error).__name__)
            print('CI status publication failed; inspect the reporting job and content-free log.', file=sys.stderr)
            return 1
    return int(args.phase == 'final' and state in ('error', 'pending'))


if __name__ == '__main__':
    raise SystemExit(main())
