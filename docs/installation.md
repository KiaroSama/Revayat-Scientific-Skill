# Installation and host paths

The installed payload includes native DOCX/PDF helpers and the optional parallel
agent workflow. Install `skills/revayat-scientific/requirements.txt` into the same
interpreter used by the dispatcher. DOCX creation uses python-docx; PDF operations
use PyMuPDF. Chromium rendering additionally uses Playwright with an existing
browser executable; set `REVAYAT_CHROMIUM` to an explicit executable when needed.
WeasyPrint rendering requires its fatal URL-fetcher API (version68 or newer;
version70 is exercised in CI), installed in that same interpreter.
Automatic TeX requires local Docker/Podman and the prebuilt toolchain image;
follow the [isolated TeX setup](../skills/revayat-scientific/references/pdf-output.md).
The helper never installs a container runtime or pulls an image automatically.
OCR requires Tesseract and the requested language data; `TESSERACT_CMD` can name
an explicitly configured absolute executable. Helpers never install these tools.

No separate DOCX or PDF Processing Pro skill installation is required. Parallel
translation/editing uses available host subagents only after affirmative user
consent; a host without subagents follows the same workflow sequentially.

Installers make real copies. `--agent all` installs only for detected configuration directories; an explicit agent can create its skill directory. `--scope project` requires `--path`. `--dest` names an explicit final skill directory for other hosts. Existing installations are refused unless `--force` is given; replacements are staged completely, with the old copy retained in a backup outside the skill discovery directory. Installation does not modify agent configuration or install dependencies.

| Agent | User skill parent | Project skill parent |
| --- | --- | --- |
| Claude Code | `~/.claude/skills` | `.claude/skills` |
| Codex | `~/.agents/skills` | `.agents/skills` |
| Cursor | `~/.cursor/skills` | `.cursor/skills` |
| Kiro | `~/.kiro/skills` | `.kiro/skills` |
| Cline | `~/.cline/skills` | `.cline/skills` |
| Hermes | `~/.hermes/skills` | `.hermes/skills` |
| OpenCode | `~/.config/opencode/skills` | `.opencode/skills` |
| Antigravity | `~/.gemini/config/skills` | `.agents/skills` |

Every target contains `revayat-scientific/SKILL.md`. Codex and Antigravity share one copy in project scope. A host using additional configured directories can use `--dest`. Native host discovery may require refreshing its skill inventory; CI verifies installed layout and execution, not every application's UI.

```bash
python install/install.py --agent codex --scope project --path /path/to/project
python install/install.py --dest /custom/skills/revayat-scientific
python install/install.py --agent claude --force
```

The Bash and PowerShell entry points forward these same options. Paths with spaces must be quoted. They never download dependencies; Python 3.10+ is required before installation.

For a standalone upload, run `python tools/package.py` and use `dist/revayat-scientific.skill` in a host that accepts ZIP skill uploads. Extract it into the host skill parent otherwise. The package includes the required license notices.

Discovery references: [Agent Skills](https://agentskills.io/specification), [Claude Code](https://code.claude.com/docs/en/skills), [Codex](https://developers.openai.com/codex/skills), [Cursor](https://cursor.com/docs/context/skills), [Kiro](https://kiro.dev/docs/skills/), [Cline](https://docs.cline.bot/customization/skills), [OpenCode](https://opencode.ai/docs/skills/), [Hermes](https://hermes-agent.nousresearch.com/docs/user-guide/features/skills), [Antigravity](https://antigravity.google/docs/migration/workflows-to-skills).
