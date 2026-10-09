"""Page-link copying contract, separate from document outlines."""
import math

from pdf_outlines import _destination


def page_link_plan(document, first=0, last=None, offset=0):
    """Refuse named navigation that insert_pdf does not copy."""
    import pymupdf
    last = document.page_count - 1 if last is None else last
    pages = {document.page_xref(number): number for number in range(document.page_count)}
    result = []
    for number in range(first, last + 1):
        page = document[number]
        links = page.get_links()
        annotations = [xref for xref, kind, _ in page.annot_xrefs() if kind == pymupdf.PDF_ANNOT_LINK]
        if len(annotations) != len(links) or any(not link.get('xref') for link in links):
            raise ValueError('unresolved page-link annotations require a separately reviewed copy')
        for link in links:
            if document.xref_get_key(link['xref'], 'A/Next')[0] != 'null':
                raise ValueError('chained page-link actions require a separately reviewed copy')
            if link['kind'] == pymupdf.LINK_NAMED:
                raise ValueError('named page links require a separately reviewed page-only copy')
            if link['kind'] == pymupdf.LINK_GOTOR:
                raise ValueError('remote page links require a separately reviewed page-only copy')
            if link['kind'] == pymupdf.LINK_GOTO and not first <= link['page'] <= last:
                raise ValueError('page link target is outside the copied range; preserve the referenced pages')
            detail = {key: value for key, value in link.items() if key not in ('xref', 'id')}
            if link['kind'] == pymupdf.LINK_GOTO:
                direct = document.xref_get_key(link['xref'], 'Dest')
                action = document.xref_get_key(link['xref'], 'A/D')
                if direct[0] != 'null' and action[0] != 'null':
                    raise ValueError('ambiguous page-link destinations require review')
                destination = action if direct[0] == 'null' else direct
                if destination[0] in ('name', 'string'):
                    raise ValueError('named page links require a separately reviewed page-only copy')
                target, tail, signature = _destination(document, *destination, pages)
                if target != link['page']:
                    raise ValueError('page-link destination disagrees with parsed navigation')
                detail.update(page=target - first + offset, destination=signature, tail=tail,
                              destination_key='A/D' if direct[0] == 'null' else 'Dest')
            result.append((number - first + offset, detail))
    return result


def _same_value(wanted, found):
    if isinstance(wanted, (int, float)) and isinstance(found, (int, float)):
        return math.isfinite(wanted) and math.isfinite(found) and math.isclose(
            wanted, found, rel_tol=0, abs_tol=1e-5)
    if isinstance(wanted, str) or isinstance(found, str):
        return wanted == found
    try:
        return len(wanted) == len(found) and all(
            _same_value(a, b) for a, b in zip(wanted, found))
    except TypeError:
        return wanted == found


def apply_page_destinations(document, plan):
    """Restore exact PDF-space local targets instead of get_links' lossy zoom."""
    by_page = {}
    for number, detail in plan:
        by_page.setdefault(number, []).append(detail)
    for number, wanted in by_page.items():
        page = document[number]
        links = page.get_links()
        if len(links) != len(wanted):
            raise ValueError('copied PDF lost page links')
        for detail, link in zip(wanted, links):
            if detail['kind'] != link['kind'] or not link.get('xref'):
                raise ValueError('copied PDF changed page-link kinds')
            if 'destination' in detail:
                target = f"[{document.page_xref(detail['page'])} 0 R {detail['tail']}]"
                if detail['destination_key'] == 'Dest':
                    document.xref_set_key(link['xref'], 'A', 'null')
                    document.xref_set_key(link['xref'], 'Dest', target)
                else:
                    document.xref_set_key(link['xref'], 'A/D', target)
        document.reload_page(page)


def verify_page_links(document, expected):
    actual = page_link_plan(document)
    if len(actual) != len(expected):
        raise ValueError('staged PDF lost page links')
    for (page, wanted), (number, found) in zip(expected, actual):
        if (page != number or wanted.keys() != found.keys()
                or any(not _same_value(value, found[key]) for key, value in wanted.items())):
            raise ValueError('staged PDF changed page-link navigation or rectangles')
