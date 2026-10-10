"""Run fixed security scenarios only after the image-owned control probe passes."""
from datetime import datetime, timezone
import json
import logging
from pathlib import Path
import runpy
import time


def main():
    # /tmp and /run are read-only. All dependent caches and logs stay in scratch.
    home = Path('/scratch/home')
    for name in ('logs', 'libreoffice'):
        home.joinpath(name).mkdir(exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime('%Y-%m-%d_%H-%M-%S')
    logger = logging.Logger('security-worker', logging.INFO)
    handler = logging.FileHandler(home / 'logs' / ('security-worker_' + stamp + '_UTC.log'), mode='x', encoding='utf-8')
    formatter = logging.Formatter('[%(asctime)s UTC] [%(levelname)s] [%(name)s] %(message)s', '%Y-%m-%d %H:%M:%S')
    formatter.converter = time.gmtime
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    started = time.monotonic()
    try:
        logger.info('started isolated_target_phase=true')
        failed = []
        for name in ('admissions.py', 'tex_output.py'):
            logger.info('scenario_started name=%s', name)
            print(json.dumps({'phase': name, 'status': 'started'}), flush=True)
            try:
                runpy.run_path('/target/tests/security/' + name, run_name='__main__')
            except (AssertionError, OSError, ValueError, RuntimeError) as error:
                failed.append(name)
                logger.error('scenario_failed name=%s type=%s', name, type(error).__name__)
                print(json.dumps({'phase': name, 'status': 'failed', 'reason': str(error)[:512]}))
            else:
                logger.info('scenario_completed name=%s', name)
        print(json.dumps({'phase': 'scenarios', 'status': 'failed' if failed else 'passed',
                          'failed': failed, 'target_execution': 'offline scratch-only'}))
        if failed:
            raise RuntimeError('security scenario failures: ' + ', '.join(failed))
    except BaseException as error:
        logger.error('scenario_failed type=%s', type(error).__name__)
        raise
    finally:
        logger.info('finished duration_seconds=%.3f', time.monotonic() - started)
        handler.close()
        logger.removeHandler(handler)


if __name__ == '__main__':
    main()
