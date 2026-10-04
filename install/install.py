#!/usr/bin/env python3
"""Install a real, self-contained skill copy for detected or selected agents."""
import argparse
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / 'skills/revayat-scientific'
sys.path.insert(0, str(SOURCE / 'scripts'))
from runtime import operation_log
sys.path.insert(0, str(ROOT / 'install'))
from install_paths import directory_path, linked
from install_transaction import install_targets

AGENTS = {
    'claude': ('.claude/skills', '.claude/skills'),
    'codex': ('.agents/skills', '.agents/skills'),
    'cursor': ('.cursor/skills', '.cursor/skills'),
    'kiro': ('.kiro/skills', '.kiro/skills'),
    'cline': ('.cline/skills', '.cline/skills'),
    'hermes': ('.hermes/skills', '.hermes/skills'),
    'opencode': ('.config/opencode/skills', '.opencode/skills'),
    'antigravity': ('.gemini/config/skills', '.agents/skills'),
}
SKILL_FILES = {'SKILL.md', 'LICENSE', 'NOTICE.md', 'requirements.txt'}
SKILL_DIRECTORIES = {'scripts', 'references', 'assets', 'agents'}
CONTENT_SUFFIXES = {'.py', '.ps1', '.sh', '.md', '.tex', '.html', '.tsv', '.yaml', '.txt'}
EXCLUDED = {'__pycache__', 'logs', 'fonts', '.git', '.ai', '.ignoreme',
            'secrets.md', 'explain-AI.md', 'AGENTS.md', 'CLAUDE.md'}


def payload_files():
    directory_path(SOURCE)
    for path in sorted(SOURCE.rglob('*')):
        relative = path.relative_to(SOURCE)
        if linked(path):
            raise ValueError('the distributable skill must not contain symbolic links')
        if (not path.is_file() or any(part in EXCLUDED or part.startswith('.') for part in relative.parts)
                or path.suffix in ('.pyc', '.log') or path.name.startswith('.env')):
            continue
        if (relative.parts[0] in SKILL_DIRECTORIES and path.suffix in CONTENT_SUFFIXES) or str(relative) in SKILL_FILES:
            yield path, relative


def install(destination: Path, force: bool, logger):
    return install_targets([destination], force, logger, source=SOURCE, repository=ROOT,
                           payload_factory=payload_files)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--agent', choices=['all', *AGENTS], default='all')
    parser.add_argument('--scope', choices=['user', 'project'], default='user')
    parser.add_argument('--path', type=Path, help='project root, required with --scope project')
    parser.add_argument('--dest', type=Path, help='explicit final skill directory for another host')
    parser.add_argument('--force', action='store_true')
    args = parser.parse_args(argv)
    if args.scope == 'project' and args.path is None:
        parser.error('--scope project requires --path')
    with operation_log('install', ROOT / 'logs') as logger:
        try:
            if args.dest is not None:
                destinations = [args.dest]
            else:
                base = directory_path(args.path if args.scope == 'project' else Path.home())
                if not base.is_dir():
                    raise ValueError('project or user root does not exist')
                index = 1 if args.scope == 'project' else 0
                names = list(AGENTS) if args.agent == 'all' else [args.agent]
                destinations = []
                for name in names:
                    parent = base / AGENTS[name][index]
                    detected = parent.parent.is_dir()
                    if name == 'codex':
                        detected = detected or (base / '.codex').is_dir()
                    if args.agent != 'all' or detected:
                        destinations.append(parent / 'revayat-scientific')
                destinations = list(dict.fromkeys(destinations))
            if not destinations:
                raise ValueError('no agents detected; select --agent or an explicit --dest')
            install_targets(destinations, args.force, logger, source=SOURCE, repository=ROOT,
                            payload_factory=payload_files)
            return 0
        except (OSError, ValueError, RuntimeError) as error:
            logger.error('installation_failed type=%s', type(error).__name__)
            print(f'install: {error}', file=sys.stderr)
            return 1


if __name__ == '__main__':
    if hasattr(sys.stdout, 'reconfigure'):
        sys.stdout.reconfigure(encoding='utf-8')
        sys.stderr.reconfigure(encoding='utf-8')
    sys.exit(main())
