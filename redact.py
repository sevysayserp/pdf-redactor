#!/usr/bin/env python3
"""Redact personal data out of PDFs (tax forms, statements, letters) into
sanitized .txt extracts and true-redacted .redacted.pdf copies.

Built so that documents can be handed to an AI assistant or another third
party without ever exposing the originals: only the redacted output leaves
the raw folder. Two-stage flow: a preview report of every planned redaction
(with reasons), then — on confirmation — output written to --out (default
<folder>/redacted/). Source PDFs are opened read-only and never modified.

Keep raw documents in a private folder outside any repository; point --out
at the place the sanitized copies should live.

Usage:
    python redact.py <folder|file.pdf> [--out DIR] [--preview] [--yes]
                     [--no-ocr] [--no-pdf] [--report PATH] [--list PATH]
    python redact.py <folder>/redacted --audit   # leak-audit extracts + PDFs
    pdf-redact ...                                # same, after `pip install .`

The redaction list (--list, default redaction_list.txt in the folder, then one
or two levels up) is created on first run if none is found, and every run
appends candidate entries found on name-labeled lines. To reject a candidate,
comment it out — it is then never re-added.

--audit prints category + file + line number ONLY — never the matched text —
so it is safe to run (and read the output of) on real redacted extracts.
"""

import argparse
from datetime import date
import functools
import re
import sys
from collections import defaultdict
from pathlib import Path

import pdfplumber

# --------------------------------------------------------------- pattern list
# Reviewed under CLAUDE.md rule 8 — changes here require plan-mode review.
SSN_SEP = re.compile(r"(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)")
SSN_SPACED = re.compile(r"(?<!\d)\d{3} \d{2} \d{4}(?!\d)")
SSN_BARE = re.compile(r"(?<!\d)\d{9}(?!\d)")
SSN_CONTEXT = re.compile(r"SSN|SOCIAL\s+SECURITY|\bTIN\b|\bEIN\b", re.I)
EIN = re.compile(r"(?<!\d)\d{2}-\d{7}(?!\d)")
EMAIL = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+")
PHONE = re.compile(r"\(?\d{3}\)?[-. ]\s?\d{3}[-. ]\d{4}(?!\d)")
ACCT = re.compile(r"(?<!\d)\d{8,}(?!\d)")

DOB_CONTEXT = re.compile(r"\bDOB\b|DATE\s+OF\s+BIRTH|BIRTH\s?DATE", re.I)
DOB_NUM = re.compile(r"(?<!\d)\d{1,2}[/-]\d{1,2}[/-]\d{2,4}(?!\d)")
DOB_WORD = re.compile(
    r"(?:JAN|FEB|MAR|APR|MAY|JUN|JUL|AUG|SEP|OCT|NOV|DEC)[A-Z]*\.?\s+\d{1,2},?\s+\d{4}",
    re.I)

ID_CONTEXT = re.compile(
    r"DRIVER'?S?\s?LIC|LICENSE\s?(?:NO|NUMBER|#)|\bDL\b|STATE\s+ID|\bID\s?(?:NO|NUMBER|#)",
    re.I)
ID_TOKEN = re.compile(r"(?<![A-Za-z0-9])[A-Z]{0,2}\d[A-Z0-9-]{4,14}(?![A-Za-z0-9])")

ROUTING_CONTEXT = re.compile(r"ROUTING|\bABA\b|\bRTN\b", re.I)
ROUTING = re.compile(r"(?<!\d)\d{9}(?!\d)")

_STREET_SUFFIX = (
    "STREET|AVENUE|AVE|ROAD|RD|DRIVE|DR|LANE|LN|WAY|BLVD|BOULEVARD|"
    "COURT|CT|CIRCLE|CIR|PLACE|PL|TERRACE|TER|ST"
)
# Long-form suffixes are unlikely to be the tail of an ordinary word, so they
# may follow the street name with no space (OCR-dropped). Short abbreviations
# (ST, CT, DR, RD, LN, PL, ...) must be preceded by a real space: ocr_rx relaxes
# \s+ to \s*, and without this guard "direCT" / "intereST" match as suffixes.
# The lookbehind uses [ \t], which ocr_rx leaves untouched.
_STREET_SUFFIX_LONG = "STREET|AVENUE|DRIVE|LANE|BLVD|BOULEVARD|COURT|CIRCLE|PLACE|TERRACE"
_UNIT = r"(?:,?\s*(?:(?:APT|UNIT|STE|SUITE)\b\.?|#)\s*[\w-]+)?"
_STREET = (r"\d+\s+(?:[A-Za-z0-9'.\-]+\s+){1,4}"
           r"(?:(?<=[ \t])(?:%s)|(?:%s))%s"
           % (_STREET_SUFFIX, _STREET_SUFFIX_LONG, _UNIT))
_CITY_ZIP = r",\s*[A-Za-z .]+,?\s+[A-Za-z]{2}\s+\d{5}(?:-\d{4})?"
ADDR = re.compile(
    r"(?<!\w)(?:%s(?:%s)?|%s)(?!\w)" % (_STREET, _CITY_ZIP, _CITY_ZIP), re.I
)
POBOX = re.compile(r"\bP\.?\s?O\.?\s?BOX\s+\d+(?:%s)?" % _CITY_ZIP, re.I)
# Line 2 of a two-line address ("SAMPLETOWN, CA 90000") — whole-line match only,
# and never on lines carrying form vocabulary, so return-page text is safe.
US_STATE = ("AL|AK|AZ|AR|CA|CO|CT|DE|DC|FL|GA|HI|ID|IL|IN|IA|KS|KY|LA|ME|MD|MA|"
            "MI|MN|MS|MO|MT|NE|NV|NH|NJ|NM|NY|NC|ND|OH|OK|OR|PA|RI|SC|SD|TN|TX|"
            "UT|VT|VA|WA|WV|WI|WY")
CITY_LINE = re.compile(
    r"^\s*[A-Za-z][A-Za-z .]{1,40},?\s+(?:%s)\s+\d{5}(?:-\d{4})?\s*$" % US_STATE)
# OCR rows merge side-by-side fragments (two-space joiner) and stray wording
# ("IMPORTANT TAX RETURN DOCUMENT ENCLOSED  CITY, ST 12345"), so on OCR text
# the city/state/zip may be a line PREFIX or SUFFIX rather than the whole
# line. City capped at 3 words, real state codes only, re.I so an OCR read
# like "Ca" still matches. Applied to OCR-derived text only (OCR_ONLY_RULES).
_CITY_CORE = (r"[A-Za-z][A-Za-z.]*(?:\s[A-Za-z.]+){0,2},?\s+(?:%s)\s+\d{5}(?:-\d{4})?"
              % US_STATE)
CITY_EDGE_OCR = re.compile(
    r"(?:^\s*%s(?=\s\s|\s*$))|(?:(?<=\s)%s\s*$)" % (_CITY_CORE, _CITY_CORE), re.I)
FORM_VOCAB = re.compile(r"SCHEDULE|\bFORM\b|\bBOX\b|\bLINE\b|\bPAGE\b", re.I)

# (pattern, token kind, reason tag, required line context, excluding line context)
PATTERN_RULES = [
    (SSN_SEP, "SSN", "[PATTERN:SSN]", None, None),
    (SSN_SPACED, "SSN", "[PATTERN:SSN]", None, None),
    (SSN_BARE, "SSN", "[PATTERN:SSN]", SSN_CONTEXT, None),
    (EIN, "EIN", "[PATTERN:EIN]", None, None),
    (EMAIL, "EMAIL", "[PATTERN:EMAIL]", None, None),
    (PHONE, "PHONE", "[PATTERN:PHONE]", None, None),
    (DOB_NUM, "DOB", "[PATTERN:DOB]", DOB_CONTEXT, None),
    (DOB_WORD, "DOB", "[PATTERN:DOB]", DOB_CONTEXT, None),
    (ROUTING, "ROUTING", "[PATTERN:ROUTING]", ROUTING_CONTEXT, None),
    (ID_TOKEN, "ID", "[PATTERN:ID]", ID_CONTEXT, None),
    (ACCT, "ACCT", "[PATTERN:ACCT]", None, None),
    (POBOX, "ADDR", "[PATTERN:ADDR]", None, None),
    (ADDR, "ADDR", "[PATTERN:ADDR]", None, None),
    (CITY_LINE, "ADDR", "[PATTERN:ADDR]", None, FORM_VOCAB),
    (CITY_EDGE_OCR, "ADDR", "[PATTERN:ADDR]", None, FORM_VOCAB),
]
OCR_ONLY_RULES = {CITY_EDGE_OCR}  # skipped unless the text is OCR-derived

# OCR text only: digit-lookalike letters adjacent to digits are shadow-mapped
# (l/I->1, O->0) and the digit-bearing patterns re-run against the shadow, so
# a garbled scan like "l23-45-6789" still gets redacted.
_LOOKALIKE = {"O": "0", "o": "0", "l": "1", "I": "1"}
SHADOW_KINDS = {"SSN", "EIN", "PHONE", "ROUTING", "ACCT"}


@functools.lru_cache(maxsize=None)
def _ocr_rx_cached(pattern, flags):
    return re.compile(pattern.replace(r"\s+", r"\s*").replace(r"\s?", r"\s*"), flags)


def ocr_rx(rx):
    """OCR often drops spaces between words ("DATEOFBIRTH:JOHNASAMPLE"), so on
    OCR-derived text every whitespace-flexible regex is matched space-optional."""
    return _ocr_rx_cached(rx.pattern, rx.flags)

LIST_CATEGORIES = {"name": "NAME", "addr": "ADDR", "acct": "ACCT", "employer": "EMPLOYER"}


class TokenMap:
    """Stable value -> token assignment across every file in one run."""

    def __init__(self):
        self._map = {}
        self._counters = defaultdict(int)
        self._acct_by_last4 = defaultdict(dict)

    @staticmethod
    def _normalize(kind, value):
        if kind in ("SSN", "EIN", "ACCT", "ROUTING"):
            return re.sub(r"\D", "", value)
        return re.sub(r"\s+", " ", value).strip().upper()

    def token(self, kind, value):
        norm = self._normalize(kind, value)
        key = (kind, norm)
        if key in self._map:
            return self._map[key]
        if kind == "ACCT":
            last4 = norm[-4:]
            variants = self._acct_by_last4[last4]
            tok = (f"[ACCT-...{last4}]" if not variants
                   else f"[ACCT-{len(variants) + 1}-...{last4}]")
            variants[norm] = tok
        else:
            self._counters[kind] += 1
            tok = f"[{kind}-{self._counters[kind]}]"
        self._map[key] = tok
        return tok


def _name_variants(category, value):
    """A name: entry also matches common re-orderings, all -> the same token."""
    yield value
    if category != "name":
        return
    words = value.split()
    if len(words) >= 3:
        yield f"{words[0]} {words[-1]}"                    # middle dropped
        yield f"{words[-1]}, {' '.join(words[:-1])}"       # LAST, FIRST MIDDLE
    if len(words) >= 2:
        yield f"{words[-1]}, {words[0]}"                   # LAST, FIRST


def _literal_rx(value):
    """Whole-value literal match, case-insensitive, whitespace-collapsed;
    ocr_rx() makes it space-optional on OCR text."""
    words = [re.escape(w) for w in value.split()]
    return re.compile(r"(?<!\w)" + r"\s+".join(words) + r"(?!\w)", re.I)


def load_list(path):
    """Parse redaction_list.txt -> [(category, canonical, variant, regex)].

    Lines: optional 'name:'/'addr:'/'acct:'/'employer:' prefix (default name),
    '#' comments. Matching is case-insensitive with collapsed whitespace;
    name entries also match generated variants (see _name_variants), and every
    variant maps to the canonical entry's token.
    """
    entries = []
    if path is None or not Path(path).is_file():
        return entries
    for raw in Path(path).read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        category, value = "name", line
        head, sep, tail = line.partition(":")
        if sep and head.strip().lower() in LIST_CATEGORIES:
            category, value = head.strip().lower(), tail.strip()
        if not value:
            continue
        for variant in dict.fromkeys(_name_variants(category, value)):
            rx = _literal_rx(variant)
            entries.append((category, value, variant, rx))
    entries.sort(key=lambda e: len(e[3].pattern), reverse=True)  # longest wins
    return entries


def _norm_value(value):
    return " ".join(value.split()).upper()


def list_seen_values(path):
    """Normalized values of every entry line in the list, active OR commented
    out, so a candidate the user rejected by commenting it out is never
    re-suggested."""
    seen = set()
    if path is None or not Path(path).is_file():
        return seen
    for raw in Path(path).read_text().splitlines():
        line = raw.strip().lstrip("#").strip()
        if not line:
            continue
        head, sep, tail = line.partition(":")
        value = tail.strip() if sep and head.strip().lower() in LIST_CATEGORIES else line
        if value:
            seen.add(_norm_value(value))
    return seen


def append_list_entries(path, suggestions, source):
    """Create the list (with the template header) if missing, then append
    suggestions under a dated header. Returns True if the file was created."""
    path = Path(path)
    created = not path.is_file()
    if created:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(LIST_TEMPLATE)
    if suggestions:
        text = path.read_text()
        block = (("" if text.endswith("\n") or not text else "\n")
                 + f"\n# auto-added {date.today().isoformat()} from {source} "
                 "— review; comment out any that are wrong\n"
                 + "".join(f"{sug}\n" for sug in suggestions))
        with path.open("a") as f:
            f.write(block)
    return created


def _shadow(s):
    chars = list(s)
    for i, ch in enumerate(chars):
        if ch in _LOOKALIKE and (
                (i > 0 and s[i - 1].isdigit())
                or (i + 1 < len(s) and s[i + 1].isdigit())):
            chars[i] = _LOOKALIKE[ch]
    return "".join(chars)


def redact_text(text, entries, tokens, findings, ocr=False, spans=None, sweep=()):
    """Redact one document's text. findings[(reason, original, token)] += n.

    sweep = [(kind, value, rx)]: literal values a pattern found elsewhere in
    this run (see main); redacted everywhere with reason [SWEEP:kind].

    ocr=True (OCR-derived text) matches list entries, contexts and address
    patterns space-optionally and adds the digit-lookalike shadow pass.
    spans, if a list, receives (line_index, start, end, token) for every
    substitution; start/end index the ORIGINAL line, so the same match that
    produced the token can be located on the page (see redaction_rects).
    """
    flex = ocr_rx if ocr else (lambda rx: rx)
    out_lines = []
    for li, line in enumerate(text.splitlines()):
        s = line
        # orig_of[i] = index in `line` of s[i], or None inside an inserted token
        orig_of = list(range(len(line)))

        def substitute(rx, kind, reason, s, orig_of, canonical=None, shadow=False):
            src = _shadow(s) if shadow else s  # _shadow keeps length
            parts, omap, last = [], [], 0
            for m in rx.finditer(src):
                a, b = m.start(), m.end()
                tok_val = canonical if canonical is not None else m.group(0)
                rep_val = canonical if canonical is not None else s[a:b]
                tok = tokens.token(kind, tok_val)
                findings[(reason, rep_val, tok)] += 1
                if spans is not None:
                    idx = [o for o in orig_of[a:b] if o is not None]
                    if idx:
                        spans.append((li, min(idx), max(idx) + 1, tok))
                parts += [s[last:a], tok]
                omap += orig_of[last:a] + [None] * len(tok)
                last = b
            if not last:
                return s, orig_of
            return "".join(parts) + s[last:], omap + orig_of[last:]

        for category, canonical, _variant, rx in entries:
            s, orig_of = substitute(flex(rx), LIST_CATEGORIES[category],
                                    f"[LIST:{category}]", s, orig_of,
                                    canonical=canonical)
        for rx, kind, reason, req_ctx, exc_ctx in PATTERN_RULES:
            if rx in OCR_ONLY_RULES and not ocr:
                continue
            if req_ctx and not flex(req_ctx).search(line):
                continue
            if exc_ctx and flex(exc_ctx).search(line):
                continue
            s, orig_of = substitute(flex(rx), kind, reason, s, orig_of)

        if ocr:
            for rx, kind, reason, req_ctx, _exc in PATTERN_RULES:
                if kind not in SHADOW_KINDS:
                    continue
                if req_ctx and not flex(req_ctx).search(line):
                    continue
                if _shadow(s) == s:
                    break  # no lookalike chars left on this line
                s, orig_of = substitute(rx, kind, reason[:-1] + ":OCR]",
                                        s, orig_of, shadow=True)
        # last, so patterns keep credit in the report and the sweep shows
        # only the occurrences nothing else caught
        for kind, value, rx in sweep:
            s, orig_of = substitute(flex(rx), kind, f"[SWEEP:{kind}]", s, orig_of,
                                    canonical=value)
        out_lines.append(s)
    return "\n".join(out_lines)


# ------------------------------------------------------------- page extraction
# A document is a list of pages; a page is a list of lines; a line is
# (text, boxes) where boxes[i] is the (x0, top, x1, bottom) box, in PDF points
# from the page's top-left, of text[i] — or None for whitespace that was
# inserted from layout rather than drawn. pages_to_text() joins this into the
# plain string every text function works on, and _line_map() maps that
# string's line numbers back to (page, line), so a redaction span found in the
# text can be boxed on the page it came from.
PAGE_SEP = "===== PAGE {n} ====="
_LINE_TERMS = "\r\n\x0b\x0c\x1c\x1d\x1e\x85\u2028\u2029"


def _split_lines_with_boxes(text, boxes):
    """Split a page's text exactly like str.splitlines(), carrying each
    character's box along. An empty page yields one empty line."""
    lines, pos = [], 0
    for piece in text.splitlines(keepends=True):
        content = piece.rstrip(_LINE_TERMS)
        lines.append((content, boxes[pos:pos + len(content)]))
        pos += len(piece)
    return lines or [("", [])]


def extract_pdf_pages(pdf_path):
    """Text-layer pages, built from the same textmap page.extract_text()
    returns, so the joined text is what the text path has always seen."""
    pages = []
    with pdfplumber.open(pdf_path) as pdf:
        for page in pdf.pages:
            tm = page.get_textmap()
            text = "".join(ch for ch, _obj in tm.tuples)
            boxes = [None if obj is None
                     else (obj["x0"], obj["top"], obj["x1"], obj["bottom"])
                     for _ch, obj in tm.tuples]
            pages.append(_split_lines_with_boxes(text, boxes))
    return pages


def pages_to_text(pages):
    parts, multi = [], len(pages) > 1
    for i, lines in enumerate(pages, 1):
        if multi:
            parts.append(PAGE_SEP.format(n=i))
        parts.append("\n".join(t for t, _b in lines))
    return "\n".join(parts)


def extract_pdf_text(pdf_path):
    return pages_to_text(extract_pdf_pages(pdf_path))


def _line_map(pages):
    """Line index of pages_to_text(pages) -> (page_idx, line_idx), or None for
    a page-separator line."""
    out, multi = [], len(pages) > 1
    for pi, lines in enumerate(pages):
        if multi:
            out.append(None)
        out.extend((pi, lj) for lj in range(len(lines)))
    return out


def _union(boxes):
    return (min(b[0] for b in boxes), min(b[1] for b in boxes),
            max(b[2] for b in boxes), max(b[3] for b in boxes))


def redaction_rects(pages, spans):
    """spans from redact_text(pages_to_text(pages), ..., spans=[...]) ->
    {page_idx: [((x0, top, x1, bottom), token), ...]}. A span whose characters
    carry no boxes yields no rect — the PDF verification then fails loudly
    rather than silently leaving the value in place."""
    lmap = _line_map(pages)
    rects = defaultdict(list)
    for li, a, b, tok in spans:
        loc = lmap[li] if li < len(lmap) else None
        if loc is None:
            continue
        pi, lj = loc
        bx = [x for x in pages[pi][lj][1][a:b] if x]
        if bx:
            rects[pi].append((_union(bx), tok))
    return rects


# ------------------------------------------------------------------------ OCR
_OCR_ENGINE = None
_OCR_SCALE = 300 / 72  # render DPI / PDF points per inch


def _ocr_page_lines(result):
    """RapidOCR boxes -> lines (text, boxes) ordered top-to-bottom,
    left-to-right. Boxes are per character, in pixels of the rendered page;
    the two-space joiner between fragments carries None."""
    items = []
    for box, text, _score in result:
        xs = [p[0] for p in box]
        ys = [p[1] for p in box]
        rect = (min(xs), min(ys), max(xs), max(ys))
        items.append((sum(ys) / len(ys), min(xs), max(ys) - min(ys), text, rect))
    items.sort(key=lambda it: (it[0], it[1]))
    lines = []
    for y, x, h, text, rect in items:
        if lines and abs(y - lines[-1][0]) <= max(lines[-1][1], h) * 0.6:
            lines[-1][2].append((x, text, rect))
        else:
            lines.append([y, h, [(x, text, rect)]])
    out = []
    for _y, _h, frags in lines:
        frags.sort()
        text, boxes = "", []
        for _x, t, rect in frags:
            if text:
                text += "  "
                boxes += [None, None]
            text += t
            boxes += [rect] * len(t)
        out.append((text, boxes))
    return out or [("", [])]


def ocr_pdf_pages(pdf_path):
    """OCR every page (no text layer expected); boxes converted to PDF points."""
    global _OCR_ENGINE
    import numpy as np
    import pypdfium2 as pdfium
    from rapidocr_onnxruntime import RapidOCR
    if _OCR_ENGINE is None:
        _OCR_ENGINE = RapidOCR()
    doc = pdfium.PdfDocument(str(pdf_path))
    try:
        pages = []
        for i in range(len(doc)):
            pil = doc[i].render(scale=_OCR_SCALE).to_pil()
            result, _elapse = _OCR_ENGINE(np.array(pil))
            lines = []
            for text, boxes in _ocr_page_lines(result or []):
                lines.append((text, [None if b is None
                                     else tuple(v / _OCR_SCALE for v in b)
                                     for b in boxes]))
            pages.append(lines)
        return pages
    finally:
        doc.close()


def ocr_pdf_text(pdf_path):
    return pages_to_text(ocr_pdf_pages(pdf_path))


# --------------------------------------------------------------- redacted PDF
PDF_SKIP_HINT = ("flatten it (print to PDF) and re-run; note its .txt extract "
                 "may also be missing values typed into form fields")


def write_redacted_pdf(src, dst, rects_by_page, ocr_layer=()):
    """True-redact src into dst: a black box with the white token label over
    each rect, the underlying text and image pixels removed, then metadata,
    attachments, links and hidden text scrubbed. ocr_layer =
    [(page_idx, (x0, top, x1, bottom), text)] of REDACTED OCR lines written
    back as invisible text so a scanned PDF stays searchable. Returns None on
    success, else a reason the PDF was skipped: fillable/annotated, rotated
    or cropped pages are not safely redactable by this path."""
    import pymupdf
    doc = pymupdf.open(str(src))
    try:
        if doc.is_form_pdf:
            return "has fillable form fields"
        for page in doc:
            if page.rotation != 0:
                return "has rotated pages"
            if page.cropbox != page.mediabox:
                return "has a crop box"
            if (next(page.widgets(), None) is not None
                    or next(page.annots(), None) is not None):
                return "has form fields or annotations"
        for pi, page in enumerate(doc):
            rects = rects_by_page.get(pi, ())
            for (x0, top, x1, bottom), tok in rects:
                inset = min(0.5, (bottom - top) / 4)  # spare neighbouring glyphs
                rect = pymupdf.Rect(x0, top + inset, x1, bottom - inset)
                page.add_redact_annot(rect, text=tok, fill=(0, 0, 0),
                                      text_color=(1, 1, 1), cross_out=False,
                                      fontsize=max(3.0, min(8.0, 0.7 * rect.height)))
            if rects:
                page.apply_redactions(images=pymupdf.PDF_REDACT_IMAGE_PIXELS)
        doc.scrub(redactions=False)  # metadata, attachments, links, hidden text
        for pi, (x0, top, _x1, bottom), text in ocr_layer:
            if not text.strip():
                continue
            h = bottom - top
            safe = text.encode("latin-1", "replace").decode("latin-1")
            doc[pi].insert_text((x0, bottom - 0.2 * h), safe,
                                fontsize=max(4.0, 0.8 * h), render_mode=3)
        doc.save(str(dst), garbage=4, deflate=True)
    finally:
        doc.close()
    return None


def verify_redacted_pdf(dst, entries, ocr=False, sweep=()):
    """Re-extract the saved PDF with the same extractor and audit it with the
    same rules; also require that no metadata, widgets, annotations or
    embedded files remain. -> list of (line, reason) FAILs; empty = clean."""
    import pymupdf
    fails, _warns = audit_text(extract_pdf_text(dst), entries, ocr=ocr, sweep=sweep)
    doc = pymupdf.open(str(dst))
    try:
        for key in ("author", "title", "subject", "keywords"):
            if doc.metadata.get(key):
                fails.append((0, f"metadata:{key} remains"))
        for page in doc:
            if (next(page.widgets(), None) is not None
                    or next(page.annots(), None) is not None):
                fails.append((page.number + 1, "annotations remain"))
        if doc.embfile_count():
            fails.append((0, "embedded files remain"))
    finally:
        doc.close()
    return fails


# ---------------------------------------------------------------------- audit
# Second-opinion scan of already-redacted text. Reports category + line number
# only — never the matched text — so its output is safe to share/read even for
# real documents. FAIL = a redaction rule still matches (bare >=8-digit runs
# included via ACCT). WARN = heuristic: a name-labeled line still carrying an
# all-caps phrase that is not a [TOKEN] — likely an unlisted name; verify the
# line locally and extend redaction_list.txt.
TOKEN_RX = re.compile(r"\[[A-Z]+[A-Z0-9.\-]*\]")
NAME_LABEL = re.compile(
    r"PAYER|EMPLOYER|EMPLOYEE|RECIPIENT|TAXPAYER|SPOUSE|CUSTOMER|\bNAME\b", re.I)
CAPS_RUN = re.compile(r"\b[A-Z][A-Z&'.\-]+(?:\s+[A-Z][A-Z&'.\-]*)+")
# OCR drops word spaces, so a long unbroken caps blob is suspicious there.
CAPS_BLOB = re.compile(r"\b[A-Z][A-Z&'.\-]{7,}\b")
AUDIT_STOPWORDS = set(
    "PAYER PAYERS EMPLOYER EMPLOYERS EMPLOYEE RECIPIENT RECIPIENTS TAXPAYER "
    "SPOUSE CUSTOMER NAME ADDRESS HOME MAILING STREET SSN TIN EIN ID NO "
    "NUMBER ACCT ACCOUNT STATE FILING STATUS DOB DATE OF BIRTH DRIVER "
    "LICENSE ROUTING ABA RTN AND OR THE FAKE TEST DOCUMENT ALL VALUES "
    "FABRICATED".split())


_STOPWORD_SEGMENTS = AUDIT_STOPWORDS | {w + "S" for w in AUDIT_STOPWORDS}


@functools.lru_cache(maxsize=None)
def _segments_into_stopwords(w):
    """True if w is a concatenation of stopwords (plural/possessive S allowed),
    e.g. OCR-glued "PAYERSTIN" = PAYERS+TIN. Guarded so short real names like
    NOOR (NO+OR) stay significant: total length >= 6 and one segment >= 4."""
    def walk(i, long_seen):
        if i == len(w):
            return long_seen
        return any(walk(j, long_seen or j - i >= 4)
                   for j in range(i + 2, len(w) + 1)
                   if w[i:j] in _STOPWORD_SEGMENTS)
    return len(w) >= 6 and walk(0, False)


def _significant_caps(word):
    w = word.rstrip(".,:'-")
    if w.endswith("'S"):
        w = w[:-2]
    if len(w) <= 1 or w in AUDIT_STOPWORDS:
        return False
    # OCR glue: "PAYER'STIN" / "RECIPIENTSNAME" are form vocabulary, not names
    return not _segments_into_stopwords(w.replace("'", ""))


def audit_text(text, entries, ocr=False, sweep=()):
    """-> (fails, warns): lists of (line_number, category). No values, ever."""
    flex = ocr_rx if ocr else (lambda rx: rx)
    fails, warns = [], []
    for ln, line in enumerate(text.splitlines(), 1):
        if line.startswith("#"):  # extract header
            continue
        hit = set()
        for category, _canonical, _variant, rx in entries:
            if flex(rx).search(line):
                hit.add(f"[LIST:{category}]")
        for kind, _value, rx in sweep:
            if flex(rx).search(line):
                hit.add(f"[SWEEP:{kind}]")
        for rx, kind, reason, req_ctx, exc_ctx in PATTERN_RULES:
            if rx in OCR_ONLY_RULES and not ocr:
                continue
            if req_ctx and not flex(req_ctx).search(line):
                continue
            if exc_ctx and flex(exc_ctx).search(line):
                continue
            if flex(rx).search(line) or (
                    ocr and kind in SHADOW_KINDS and rx.search(_shadow(line))):
                hit.add(reason)
        fails += [(ln, reason) for reason in sorted(hit)]

        stripped = TOKEN_RX.sub(" ", line)
        if flex(NAME_LABEL).search(stripped):
            runs = [m.group(0) for m in CAPS_RUN.finditer(stripped)]
            if ocr:
                runs += [m.group(0) for m in CAPS_BLOB.finditer(stripped)]
            for run in runs:
                if any(_significant_caps(w) for w in run.split()):
                    warns.append((ln, "possible unredacted name — check this "
                                      "line locally; add it to the list"))
                    break
    return fails, warns


def _is_ocr_extract(text):
    first = text.splitlines()[0] if text else ""
    return "OCR-DERIVED" in first


# --------------------------------------------------------------- list helpers
LIST_TEMPLATE = """\
# redaction_list.txt — values to strip from document extracts.
# THIS FILE IS SENSITIVE once filled in: keep it next to the raw documents,
# outside any repository, and never commit or share it.
#
# One entry per line; '#' starts a comment. Optional category prefix:
#   name:      person names (JOHN A SAMPLE also matches JOHN SAMPLE and
#              SAMPLE, JOHN — variants map to the same [NAME-n] token)
#   employer:  employer / payer / bank / brokerage names
#   addr:      street addresses
#   acct:      account numbers (8+ digit runs are also caught by pattern)
# Unprefixed lines default to name. Matching is case-insensitive with
# collapsed whitespace.
#
# Every run of redact.py appends candidate entries found on
# name-labeled lines of your PDFs under a dated '# auto-added' header. Review
# them; to REJECT one, comment it out (keep the line) — a commented-out entry
# is never redacted and never re-added.
#
# name: JOHN Q TAXPAYER
# employer: SOME BANK NA
# addr: 123 MAIN STREET, ANYTOWN, CA 90000
# acct: 001234567890
"""

SUGGEST_SKIP = re.compile(r"ADDRESS", re.I)
SUGGEST_EMPLOYER = re.compile(r"\bPAYER|\bEMPLOYER\b|BANK|BROKER|FUND", re.I)


def suggest_entries(raw_texts, entries, seen=()):
    """Candidate list entries from name-labeled lines that neither an active
    entry covers nor `seen` (active or commented-out list values) contains."""
    seen, out = {_norm_value(v) for v in seen}, []
    for name in sorted(raw_texts):
        for line in raw_texts[name].splitlines():
            if not NAME_LABEL.search(line) or SUGGEST_SKIP.search(line):
                continue
            seg = line.rsplit(":", 1)[-1] if ":" in line else line
            for m in CAPS_RUN.finditer(seg):
                words = [w.rstrip(".,'-") for w in m.group(0).split()]
                while words and not _significant_caps(words[0]):
                    words.pop(0)
                while words and not _significant_caps(words[-1]):
                    words.pop()
                if len(words) < 2:
                    continue
                cand = " ".join(words)
                if re.search(r"\d", cand):
                    continue
                if any(rx.search(cand) for _c, _v, _var, rx in entries):
                    continue  # already covered
                if _norm_value(cand) in seen:
                    continue  # already listed, or rejected (commented out)
                cat = "employer" if SUGGEST_EMPLOYER.search(line) else "name"
                seen.add(_norm_value(cand))
                out.append(f"{cat}: {cand}")
    return out


def format_report(findings_by_file, warnings, list_desc, unused=(), added=()):
    lines = ["REDACTION PREVIEW", f"redaction list: {list_desc}"]
    if added:
        lines.append(f"  added {len(added)} new entr{'y' if len(added) == 1 else 'ies'} "
                     "to the list (review; comment out any that are wrong):")
        lines += [f"    {a}" for a in added]
    lines.append("")
    n_pattern = n_list = 0
    for fname in sorted(findings_by_file):
        lines.append(f"== {fname} ==")
        findings = findings_by_file[fname]
        if not findings:
            lines.append("  (nothing to redact)")
        for (reason, original, tok), count in sorted(findings.items()):
            if reason.startswith("[LIST"):
                n_list += count
            else:
                n_pattern += count
            lines.append(f"  {reason:<18} {original:<42} -> {tok}  ({count}x)")
        lines.append("")
    lines.append("== SUMMARY ==")
    lines.append(f"  {len(findings_by_file)} file(s), "
                 f"{n_pattern + n_list} planned redaction(s) "
                 f"({n_pattern} pattern, {n_list} list)")
    for category, value in unused:
        lines.append(f"  NOTE: list entry never matched — stale or misspelled? "
                     f"{category}: {value}")
    for w in warnings:
        lines.append(f"  WARNING: {w}")
    lines.append("  Reminder: payer/employer/person names are only redacted if "
                 "they are in the redaction list — patterns cannot detect them. "
                 "Candidates on name-labeled lines are added automatically; "
                 "add any others by hand.")
    return "\n".join(lines)


def default_list_path(folder):
    """redaction_list.txt in the folder, else one or two levels up; if none
    exists, the folder's own path (to be created)."""
    folder = Path(folder).resolve()
    candidates = [folder / "redaction_list.txt",
                  folder.parent / "redaction_list.txt",
                  folder.parent.parent / "redaction_list.txt"]
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    return candidates[0]


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("folder", metavar="PATH",
                    help="folder of raw PDFs to redact, or a single .pdf "
                         "(for --audit: the redacted/ folder or a single .txt)")
    ap.add_argument("--out", metavar="DIR",
                    help="directory for the redacted extracts (default: "
                         "<folder>/redacted). Use this to land the sanitized "
                         "copies away from the raw folder, e.g. --out ~/work/redacted")
    ap.add_argument("--preview", action="store_true",
                    help="print the redaction plan and exit; no prompt, no writes")
    ap.add_argument("--yes", action="store_true",
                    help="skip the confirmation prompt")
    ap.add_argument("--no-ocr", dest="ocr", action="store_false",
                    help="do not OCR scanned PDFs that have no text layer; by "
                         "default they are OCR'd locally (RapidOCR) and the "
                         "extract is stamped OCR-DERIVED — verify amounts")
    ap.add_argument("--no-pdf", dest="pdf", action="store_false",
                    help="do not write <stem>.redacted.pdf next to each .txt "
                         "extract (true redaction: text removed under black "
                         "boxes labeled with the token; verified by re-extraction)")
    ap.add_argument("--report", metavar="PATH",
                    help="also write the preview report to PATH")
    ap.add_argument("--list", dest="list_path", metavar="PATH",
                    help="redaction list (default: <folder>/redaction_list.txt, "
                         "then one or two levels up; created in <folder> if "
                         "none exists). Candidate entries are appended each run")
    ap.add_argument("--audit", action="store_true",
                    help="leak-audit already-redacted .txt extracts in <folder>; "
                         "prints categories + line numbers only, never values")
    args = ap.parse_args(argv)

    target = Path(args.folder)
    single = None  # set when PATH is one file rather than a folder
    if target.is_dir():
        folder = target
    elif target.is_file():
        name = target.name.lower()
        ok = (name.endswith((".txt", ".redacted.pdf")) if args.audit
              else name.endswith(".pdf"))
        if not ok:
            sys.exit(f"error: {target} is not a "
                     f"{'.txt or .redacted.pdf' if args.audit else '.pdf'} file")
        single, folder = target, target.parent
    else:
        sys.exit(f"error: {target} is not a directory or file")

    list_path = Path(args.list_path) if args.list_path else default_list_path(folder)
    out_dir = Path(args.out) if args.out else folder / "redacted"
    if out_dir.resolve() == folder.resolve():
        sys.exit("error: --out must not be the raw folder itself")

    entries = load_list(list_path)
    warnings = []
    list_desc = (f"found {list_path} ({len(entries)} entries)"
                 if list_path.is_file() else "NONE")

    if args.audit:
        txts = [single] if single else sorted(
            [*folder.glob("*.txt"), *folder.glob("*.redacted.pdf")])
        txts = [t for t in txts if t.name != "redaction_list.txt"]
        if not txts:
            sys.exit(f"error: no .txt extracts or .redacted.pdf files found in {folder}")
        print(f"LEAK AUDIT of {len(txts)} extract(s)  (list: {list_desc})")
        n_fail = n_warn = 0
        for t in txts:
            if t.suffix.lower() == ".pdf":
                text, is_ocr = extract_pdf_text(t), True  # strictest setting
            else:
                text = t.read_text()
                is_ocr = _is_ocr_extract(text)
            fails, warns = audit_text(text, entries, ocr=is_ocr)
            for ln, reason in fails:
                print(f"  FAIL {t.name} line {ln}: {reason}")
                n_fail += 1
            for ln, msg in warns:
                print(f"  WARN {t.name} line {ln}: {msg}")
                n_warn += 1
        print(f"audit result: {n_fail} FAIL, {n_warn} WARN"
              + (" — extracts are NOT safe" if n_fail else ""))
        return 1 if n_fail else 0

    pdfs = [single] if single else sorted(folder.glob("*.pdf"))
    if not pdfs:
        sys.exit(f"error: no PDFs found in {folder}")
    if single and not args.preview:
        warnings.append("SINGLE-FILE RUN: tokens are numbered per run, so "
                        f"this extract's tokens will not line up with a "
                        "folder run's — re-run the whole folder before the "
                        "review hand-off")

    raw_texts = {}
    pages_by_name = {}
    src_by_name = {}
    ocr_files = set()
    for pdf in pdfs:
        pages = extract_pdf_pages(pdf)
        text = pages_to_text(pages)
        if len(text.strip()) < 20:
            if args.ocr:
                pages = ocr_pdf_pages(pdf)
                text = pages_to_text(pages)
                if len(text.strip()) >= 20:
                    ocr_files.add(pdf.name)
                    warnings.append(f"OCR APPLIED: {pdf.name} had no text layer; "
                                    "its extract is OCR-derived — verify amounts "
                                    "against the original")
            if len(text.strip()) < 20:
                warnings.append(f"NEEDS OCR / MANUAL HANDLING: {pdf.name} has no "
                                "extractable text (scanned image?) — no extract "
                                "will be written for it"
                                + ("" if args.ocr else "; re-run without --no-ocr"))
                continue
        raw_texts[pdf.name] = text
        pages_by_name[pdf.name] = pages
        src_by_name[pdf.name] = pdf

    # Redaction list: create if missing, append new candidates, reload so the
    # additions take effect in this same run (preview included).
    added = suggest_entries(raw_texts, entries, list_seen_values(list_path))
    created = append_list_entries(list_path, added, folder.name or str(folder)) \
        if (added or not list_path.is_file()) else False
    if added or created:
        entries = load_list(list_path)
    list_desc = f"{'created' if created else 'found'} {list_path} ({len(entries)} entries)"
    if not entries:
        warnings.append("no redaction list entries loaded — names, employers and "
                        "addresses will NOT be redacted (patterns only)")

    def redact_all(sweep):
        tokens = TokenMap()
        redacted, findings_by_file, spans_by_name = {}, {}, {}
        for name, text in raw_texts.items():
            findings, spans = defaultdict(int), []
            redacted[name] = redact_text(text, entries, tokens, findings,
                                         ocr=name in ocr_files, spans=spans,
                                         sweep=sweep)
            findings_by_file[name] = findings
            spans_by_name[name] = spans
        return redacted, findings_by_file, spans_by_name

    # Pass 1 finds values by pattern; pass 2 also redacts each of those
    # values literally wherever else it appears in the run (any line, any
    # file — e.g. a city/state/zip merged into an OCR row), like list entries.
    redacted, findings_by_file, spans_by_name = redact_all(())
    sweep_values = sorted({(reason[len("[PATTERN:"):-1].split(":")[0], orig)
                           for f in findings_by_file.values()
                           for reason, orig, _tok in f
                           if reason.startswith("[PATTERN:")})
    sweep = [(kind, val, _literal_rx(val)) for kind, val in sweep_values]
    if sweep:
        redacted, findings_by_file, spans_by_name = redact_all(sweep)

    used = {orig for f in findings_by_file.values()
            for (reason, orig, _tok) in f if reason.startswith("[LIST")}
    unused = sorted({(c, v) for c, v, _var, _rx in entries if v not in used})

    report = format_report(findings_by_file, warnings, list_desc, unused, added)
    print(report)
    if args.report:
        Path(args.report).write_text(report + "\n")
        print(f"\nreport written to {args.report}")

    if args.preview:
        return 0
    if not args.yes:
        try:
            answer = input("\nProceed with redaction? [y/N] ")
        except EOFError:
            answer = ""
        if answer.strip().lower() not in ("y", "yes"):
            print("Aborted — nothing written.")
            return 0

    out_dir.mkdir(parents=True, exist_ok=True)
    written = []
    for name, text in redacted.items():
        out = out_dir / (Path(name).stem + ".txt")
        ocr_note = (" OCR-DERIVED — verify amounts against the original."
                    if name in ocr_files else "")
        header = (f"# Redacted extract of {name} — generated by pdf-redactor; "
                  f"tokens like [SSN-1] are stable across this run's extracts."
                  f"{ocr_note}\n\n")
        out.write_text(header + text)
        written.append(out)

    # Self-check: audit every output with the same rules; any FAIL means
    # redaction failed — delete the output and fail loudly. WARNs are surfaced
    # for the user to eyeball locally.
    failed = []
    warn_lines = []
    for out in written:
        text = out.read_text()
        fails, warns = audit_text(text, entries, ocr=_is_ocr_extract(text),
                                  sweep=sweep)
        if fails:
            failed.append(out.name)
            out.unlink()
        warn_lines += [f"  WARN {out.name} line {ln}: {msg}" for ln, msg in warns]
    if failed:
        print(f"SELF-CHECK FAILED: residual sensitive values in {failed}; "
              "those outputs were DELETED. Fix the patterns/list and re-run.",
              file=sys.stderr)
        return 1
    if warn_lines:
        print("AUDIT WARNINGS (categories only — check these lines in the "
              "extracts locally):")
        print("\n".join(warn_lines))

    # Redacted PDFs: only once every .txt passed. Each PDF is re-extracted and
    # audited after writing; a residual match deletes it and fails the run.
    pdfs_written, pdf_failed = [], []
    if args.pdf:
        for name in redacted:
            pages = pages_by_name[name]
            dst = out_dir / (Path(name).stem + ".redacted.pdf")
            rects = redaction_rects(pages, spans_by_name[name])
            ocr_layer = []
            if name in ocr_files:
                lmap = _line_map(pages)
                for li, rline in enumerate(redacted[name].splitlines()):
                    loc = lmap[li] if li < len(lmap) else None
                    if loc is None:
                        continue
                    bx = [x for x in pages[loc[0]][loc[1]][1] if x]
                    if bx:
                        ocr_layer.append((loc[0], _union(bx), rline))
            reason = write_redacted_pdf(src_by_name[name], dst, rects, ocr_layer)
            if reason:
                print(f"WARNING: PDF SKIPPED: {name} {reason} — {PDF_SKIP_HINT}")
                continue
            fails = verify_redacted_pdf(dst, entries, ocr=name in ocr_files,
                                        sweep=sweep)
            if fails:
                dst.unlink()
                pdf_failed.append(dst.name)
                for ln, reason in fails:
                    print(f"  FAIL {dst.name} line {ln}: {reason}", file=sys.stderr)
            else:
                pdfs_written.append(dst)
        if pdf_failed:
            print(f"SELF-CHECK FAILED: residual sensitive values in {pdf_failed}; "
                  "those PDFs were DELETED (the .txt extracts passed and were "
                  "kept). Re-run with --no-pdf or report the file.",
                  file=sys.stderr)
            return 1

    print(f"wrote {len(written)} redacted extract(s) and {len(pdfs_written)} "
          f"redacted PDF(s) to {out_dir}/ (self-check passed)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
