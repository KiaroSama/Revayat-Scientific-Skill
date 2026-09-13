#!/usr/bin/env python3
"""Install a real, self-contained skill copy for detected or selected agents."""
import argparse
from pathlib import Path
import shutil
import sys
import tempfile
import uuid

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / 'skills/revayat-scientific'
sys.path.insert(0, str(SOURCE / 'scripts'))
from runtime import operation_log

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
    for path in sorted(SOURCE.rglob('*')):
        relative = path.relative_to(SOURCE)
        if path.is_symlink():
            raise ValueError('the distributable skill must not contain symbolic links')
        if (not path.is_file() or any(part in EXCLUDED or part.startswith('.') for part in relative.parts)
                or path.suffix in ('.pyc', '.log') or path.name.startswith('.env')):
            continue
        if (relative.parts[0] in SKILL_DIRECTORIES and path.suffix in CONTENT_SUFFIXES) or str(relative) in SKILL_FILES:
            yield path, relative


def install(destination: Path, force: bool, logger):
    if destination.is_symlink() or (destination.exists() and not destination.is_dir()):
        raise ValueError('installation destination must be a real directory')
    destination = destination.resolve()
    source = SOURCE.resolve()
    if destination == source or source in destination.parents or destination in source.parents:
        raise ValueError('installation destination overlaps the source skill')
    if destination.exists() and not force:
        raise FileExistsError('skill already exists; use --force to replace it and retain a backup')
    destination.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix='.revayat-scientific-stage-', dir=destination.parent))
    backup = None
    try:
        for path, relative in payload_files():
            target = staging / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path, target)
        if not (staging / 'SKILL.md').is_file():
            raise ValueError('source SKILL.md is missing')
        if destination.exists():
            backup_root = destination.parent.parent / 'skill-backups'
            backup_root.mkdir(parents=True, exist_ok=True)
            backup = backup_root / ('revayat-scientific-' + uuid.uuid4().hex[:12])
            destination.rename(backup)
        try:
            staging.rename(destination)
        except BaseException:
            if backup is not None:
                backup.rename(destination)
            raise
        logger.info('installation_completed backup_retained=%s', backup is not None)
        print(f'Installed revayat-scientific: {destination}')
        if backup:
            print(f'Previous installation retained: {backup}')
    finally:
        if staging.exists():
            shutil.rmtree(staging)


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
                base = (args.path if args.scope == 'project' else Path.home()).resolve()
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
            for destination in destinations:
                install(destination, args.force, logger)
            return 0
        except (OSError, ValueError) as error:
            logger.error('installation_failed type=%s', type(error).__name__)
            print(f'install: {error}', file=sys.stderr)
            return 1


if __name__ == '__main__':
    if hasattr(sys.stdout, 'reconfigure'):
        sys.stdout.reconfigure(encoding='utf-8')
        sys.stderr.reconfigure(encoding='utf-8')
    sys.exit(main())
