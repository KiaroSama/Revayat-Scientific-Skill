# Literal HTML contexts and protected metadata

## HTML tokenizer scope

Literal text in `textarea` and `title` cannot manufacture comments, assets or
active elements. Character references are decoded once, retaining source offset
mapping. Literal angle-bracket text survives isolate extraction, and a printed
`scaleX(-1)` example is not mistaken for active image-mirroring CSS. A self-closing
slash closes supported foreign SVG/MathML elements and HTML void elements, but
not ordinary HTML `span`, `div` or `textarea`. Foreign breakout tags return to
HTML context; integration points retain their distinct behavior. Quotes in an
unquoted end-tag attribute do not turn the following text into a quoted value.
The parser uses explicit raw/RCDATA handling across older and newer patch versions;
native RCDATA support also exists in later Python 3.10 patches.

`template` and obsolete `plaintext` are explicitly unsupported in HTML input.
Make a separately reviewed static document instead. Template contents can be
hidden by the default WeasyPrint stylesheet yet become visible through author
CSS; treating them as universally inert would certify the wrong source. This
restriction includes declarative shadow-root templates. Do not silently discard
these elements or insert their content into the document. Unterminated raw/RCDATA
contexts also fail explicitly. The parser remains a bounded source model, not a
complete HTML5 DOM implementation. Existing renderer sandbox and resource-access
checks still apply; parsing is not a sandbox.

Only actual `<!-- ... -->` comments may grant the documented narrowly scoped
lint exception. Comment-like text inside a literal context cannot grant it.
Standard `-->` and `--!>` endings and abrupt empty-comment endings are recognized
consistently across supported Python patches. Whitespace in `-- >` is not a
terminator: the remaining input stays comment content until a genuine ending or
EOF, rather than exposing text the renderer hides.

## Git administrative destinations

A package output must not replace a Git index, configuration, reference, object,
hook or worktree pointer. The packager resolves private/common administrative
roots, the active index, object directory and hook directory through Git, rather
than assuming metadata always lives in one `.git` directory. Parent repositories,
linked worktrees, separate Git directories and supported environment/configuration
relocations are covered. Conventional `.git` path components are reserved.

Git administrative-path discovery must succeed before publication in a checkout.
It is repeated after ZIP staging. A genuinely exported source tree without a Git
context remains packagable. This uses Git's `--path-format=absolute` support; an
older/incompatible Git fails explicitly rather than guessing paths. The policy is
not a filesystem-wide lock against arbitrary hostile concurrent mutation.

## DOCX signature metadata

OPC producers may choose nonconventional signature-part names. Inspection reports
package digital-signature metadata by its standard relationship or content type,
in addition to retaining the conventional-directory check. Edits refuse such
packages before publication. MIME type matching is ASCII case-insensitive;
relationship identifiers use exact standard URIs. An unrelated word or a foreign
URI containing `digital-signature` does not become a package signature.

These checks do not authenticate a signature, certificate, signer or full OPC
schema. Preserve the original. Any removal, re-signing or conversion requires an
explicitly authorized separate workflow; the editor never does it implicitly.

## Research used for these contracts

- [WHATWG parsing](https://html.spec.whatwg.org/multipage/parsing.html): tokenizer
  states and self-closing semantics; do not equate a callback parser with a DOM.
- [CPython HTMLParser](https://github.com/python/cpython/blob/3.14/Lib/html/parser.py):
  account for version-specific RCDATA and start/end-tag dispatch.
- [tinyhtml5](https://github.com/Kozea/tinyhtml5) and
  [html5lib tests](https://github.com/html5lib/html5lib-tests): independent parsing
  and corpus-based regression design, not a new mandatory runtime dependency.
- [WeasyPrint stylesheet](https://github.com/Kozea/WeasyPrint/blob/v68.0/weasyprint/css/html5_ua.css):
  distinguish default CSS hiding from browser-inert template contents. The local
  cross-engine probe was version-bound; required CI must repeat current-pin tests.
- [Git rev-parse](https://git-scm.com/docs/git-rev-parse) and
  [worktrees](https://git-scm.com/docs/git-worktree): resolve actual metadata roots
  and relocated paths rather than deriving them from filenames.
- [Microsoft OPC signatures](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/opc/digital-signatures-overview)
  and [ECMA-376](https://ecma-international.org/publications-and-standards/standards/ecma-376/):
  signature origin names are configurable and signature metadata is separate from
  authentication. No third-party code, credentials, documents or fonts are bundled.
