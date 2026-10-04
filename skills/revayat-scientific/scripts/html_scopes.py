"""Supported HTML implied closures; ambiguous tree repair requires a static source.

This is not a general HTML5 tree builder. Ordinary optional sibling boundaries
are modeled; active-formatting reconstruction and table foster parenting are
refused rather than granting exemptions using a different tree from a renderer.
"""
P_CLOSERS = {'address', 'article', 'aside', 'blockquote', 'center', 'details', 'dialog',
             'dir', 'div', 'dl', 'fieldset', 'figcaption', 'figure', 'footer', 'form',
             'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'header', 'hgroup', 'hr', 'listing',
             'main', 'menu', 'nav', 'ol', 'p', 'pre', 'search', 'section', 'summary',
             'table', 'ul', 'li', 'dt', 'dd', 'xmp'}
HEAD_CONTENT = {'base', 'basefont', 'bgsound', 'link', 'meta', 'title', 'noframes',
                'style', 'script', 'template'}
FORMATTING = {'a', 'b', 'big', 'code', 'em', 'font', 'i', 'nobr', 's', 'small',
              'strike', 'strong', 'tt', 'u'}
SCOPE = {'applet', 'caption', 'html', 'table', 'td', 'th', 'marquee', 'object', 'template'}
TABLE_PARTS = {'caption', 'colgroup', 'col', 'thead', 'tbody', 'tfoot', 'tr', 'td', 'th'}
TABLE_CONTEXT = {'table', 'thead', 'tbody', 'tfoot', 'tr', 'colgroup'}
HEADINGS = {'h1', 'h2', 'h3', 'h4', 'h5', 'h6'}
SPECIAL = P_CLOSERS | TABLE_PARTS | HEADINGS | SCOPE | {
    'area', 'base', 'basefont', 'bgsound', 'body', 'br', 'button', 'embed', 'head',
    'iframe', 'img', 'input', 'keygen', 'link', 'meta', 'noembed', 'noframes',
    'noscript', 'object', 'optgroup', 'option', 'param', 'plaintext', 'script',
    'select', 'source', 'style', 'textarea', 'title', 'track', 'wbr'}
CONTAINER_ENDS = (P_CLOSERS - {'p', 'li', 'dt', 'dd', 'hr', 'table', 'xmp'}
                  - HEADINGS) | {'button'}


def scoped_index(stack, targets, fences):
    for index in range(len(stack) - 1, -1, -1):
        node = stack[index]
        if node['namespace'] != 'html':
            return None
        if node['tag'] in targets:
            return index
        if node['tag'] in fences:
            return None
    return None


def close_from(parser, index, start, end=None):
    if index is None:
        return
    # An omitted formatting end tag may be reconstructed by an HTML5 renderer.
    # Never drop its language/identity state using a simpler stack approximation.
    if any(node['tag'] in FORMATTING for node in parser.stack[index + 1:]):
        raise ValueError('HTML formatting reconstruction requires explicitly nested markup')
    for node in reversed(parser.stack[index:]):
        parser.finish(node, start, start if end is None else end)
    del parser.stack[index:]


def before_start(parser, tag, start):
    if parser.namespace_for(tag) != 'html':
        return
    stack = parser.stack
    if tag in {'a', 'button', 'form', 'select'} and any(
            node['tag'] == tag and node['namespace'] == 'html' for node in stack):
        raise ValueError('nested interactive HTML requires an explicitly reviewed static source')
    if tag in {'html', 'body', 'head'} and any(
            node['tag'] == tag and node['namespace'] == 'html' for node in parser.nodes):
        raise ValueError('duplicate HTML document containers require a normalized source')
    head = scoped_index(stack, {'head'}, {'html', 'body'})
    if head is not None and tag not in HEAD_CONTENT:
        close_from(parser, head, start)
    if tag in P_CLOSERS:
        close_from(parser, scoped_index(stack, {'p'}, SCOPE | {'button'}), start)
    if tag == 'li':
        close_from(parser, scoped_index(stack, {'li'}, SPECIAL - {'address', 'div', 'p'}), start)
    elif tag in {'dt', 'dd'}:
        close_from(parser, scoped_index(stack, {'dt', 'dd'}, SPECIAL - {'address', 'div', 'p'}), start)
    elif tag in HEADINGS:
        heading = scoped_index(stack, HEADINGS, SCOPE)
        if heading is not None:
            if heading != len(stack) - 1:
                raise ValueError('misnested HTML heading requires explicit end tags')
            close_from(parser, heading, start)
    select = scoped_index(stack, {'select'}, {'html', 'table'})
    if tag == 'hr' and select is not None:
        raise ValueError('HTML select separators require an explicit renderer-compatible source')
    if tag in {'option', 'optgroup'}:
        close_from(parser, scoped_index(stack, {'option'}, {'select', 'optgroup', 'html'}), start)
        if tag == 'optgroup':
            close_from(parser, scoped_index(stack, {'optgroup'}, {'select', 'html'}), start)
    select = scoped_index(stack, {'select'}, {'html', 'table'})
    if select is not None and tag not in {'option', 'optgroup', 'hr', 'script'}:
        raise ValueError('unsupported HTML select content requires a static reviewed source')
    table = scoped_index(stack, {'table'}, {'html'})
    if table is None and tag in TABLE_PARTS:
        raise ValueError('HTML table parts outside a table require normalization')
    if table is not None and tag != 'col':
        close_from(parser, scoped_index(stack, {'colgroup'}, {'table', 'td', 'th'}), start)
    if table is not None and tag in TABLE_PARTS:
        close_from(parser, scoped_index(stack, {'caption'}, {'table'}), start)
        if tag in {'td', 'th', 'tr', 'thead', 'tbody', 'tfoot', 'caption', 'colgroup'}:
            close_from(parser, scoped_index(stack, {'td', 'th'}, {'table'}), start)
        if tag in {'tr', 'thead', 'tbody', 'tfoot', 'caption', 'colgroup'}:
            close_from(parser, scoped_index(stack, {'tr'}, {'table'}), start)
        if tag in {'thead', 'tbody', 'tfoot', 'caption', 'colgroup'}:
            close_from(parser, scoped_index(stack, {'thead', 'tbody', 'tfoot', 'caption', 'colgroup'}, {'table'}), start)
    parent = stack[-1] if stack else None
    if parent and parent['namespace'] == 'html' and parent['tag'] in TABLE_CONTEXT:
        allowed = {
            'table': {'caption', 'colgroup', 'col', 'thead', 'tbody', 'tfoot', 'tr', 'td', 'th'},
            'thead': {'tr', 'td', 'th'}, 'tbody': {'tr', 'td', 'th'},
            'tfoot': {'tr', 'td', 'th'}, 'tr': {'td', 'th'}, 'colgroup': {'col'},
        }[parent['tag']] | {'script', 'style'}
        if tag not in allowed:
            raise ValueError('HTML table foster parenting requires explicit cell structure')


def before_text(parser, data, start):
    if not data.strip() or parser.cdata_elem is not None:
        return
    head = scoped_index(parser.stack, {'head'}, {'html', 'body'})
    if head is not None:
        close_from(parser, head, start)
    if (parser.stack and parser.stack[-1]['namespace'] == 'html'
            and parser.stack[-1]['tag'] in TABLE_CONTEXT):
        raise ValueError('HTML table foster parenting requires text inside cells')


def end_index(parser, tag):
    """Locate only an in-scope target; body/html end tags do not pop the body tree."""
    if tag in {'body', 'html'}:
        return None
    for index in range(len(parser.stack) - 1, -1, -1):
        node = parser.stack[index]
        if node['tag'] == tag and node['namespace'] != 'html':
            return index
    if tag in HEADINGS:
        index = scoped_index(parser.stack, HEADINGS, SCOPE)
        if index is not None and parser.stack[index]['tag'] != tag:
            raise ValueError('mismatched HTML heading end tag requires normalization')
    if tag in FORMATTING:
        return scoped_index(parser.stack, {tag}, set())
    fences = (SCOPE | {'ul', 'ol', 'menu'} if tag == 'li' else
              SCOPE | {'button'} if tag == 'p' else
              {'html', 'table'} if tag in TABLE_PARTS | {'table', 'select'} else
              SCOPE if tag in {'dt', 'dd', 'form'} | HEADINGS | CONTAINER_ENDS else SPECIAL)
    index = scoped_index(parser.stack, {tag}, fences)
    if tag == 'form' and index is not None and index != len(parser.stack) - 1:
        raise ValueError('HTML form removal requires explicitly nested markup')
    return index
