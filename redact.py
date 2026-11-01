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
                     [--no-ocr] [--no-pdf] [--no-flatten] [--no-signatures]
                     [--keep-certificate]
                     [--report PATH] [--list PATH]
                     [--master PATH | --no-master]
    python redact.py <folder>/redacted --audit   # leak-audit extracts + PDFs
    pdf-redact ...                                # same, after `pip install .`

The redaction list (--list, default redaction_list.txt in the folder, then one
or two levels up) is created on first run if none is found, and every run
appends candidate entries found on name-labeled lines. To reject a candidate,
comment it out — it is then never re-added.

A master list (--master, default ~/.config/pdf-redactor/
master_redaction_list.txt) holds entries common to every folder — your own
name, address, ... It has the same format, is merged into every run, and is
never written by the script. --no-master skips it.

Fillable form fields and annotations are flattened into the page in memory
before extraction, so their contents are redacted too (--no-flatten skips
this). The source file is never modified.

Signature blocks (DocuSign-style stamps, signature form fields) are boxed as
a whole — text, image and drawing — under one [SIGNATURE-n] token. In an
e-signed document every small image counts as a signature, and the
certificate pages the service appended are left out (--keep-certificate).
--no-signatures skips all of this.

--audit prints category + file + line number ONLY — never the matched text —
so it is safe to run (and read the output of) on real redacted extracts.
"""

import argparse
from datetime import date
import functools
import io
import logging
import os
import re
import sys
from collections import defaultdict
from pathlib import Path

import pdfplumber

# pdfminer (under pdfplumber) logs a WARNING for every font that omits an
# optional descriptor entry (FontBBox, Widths, ...), once per page. The
# fallbacks it uses do not affect the extracted text, so only show errors.
logging.getLogger("pdfminer").setLevel(logging.ERROR)

# --------------------------------------------------------------- pattern list
# Reviewed under CLAUDE.md rule 8 — changes here require plan-mode review.
SSN_SEP = re.compile(r"(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)")
SSN_SPACED = re.compile(r"(?<!\d)\d{3} \d{2} \d{4}(?!\d)")
# Masked SSN: five mask characters then the last four digits
# ("XXX-XX-6789", "***-**-6789", "xxxxx6789"). Exactly five, so a masked
# account number (six or more) is not taken for an SSN.
SSN_MASKED = re.compile(r"(?<![\w*#•])[Xx*#•]{3}[- ]?[Xx*#•]{2}[- ]?\d{4}(?!\w)")
SSN_BARE = re.compile(r"(?<!\d)\d{9}(?!\d)")
SSN_CONTEXT = re.compile(r"SSN|SOCIAL\s+SECURITY|\bTIN\b|\bEIN\b", re.I)
EIN = re.compile(r"(?<!\d)\d{2}-\d{7}(?!\d)")
EMAIL = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+")
PHONE = re.compile(r"\(?\d{3}\)?[-. ]\s?\d{3}[-. ]\d{4}(?!\d)")
# 8+ digits, but not the decimals of a number ("0.00000123456") and not a
# percentage ("10000000 %").
ACCT = re.compile(r"(?<!\d)(?<!\d\.)(?<![^\w]\.)(?<!^\.)\d{8,}(?!\d)(?!\s?%)")
# An account number named by its label ("Account No. Z12-345678"): letters,
# digits and dashes, 5-20 characters, at least one digit. Only the number
# (group v) is replaced; the label stays.
ACCT_LABELED = re.compile(
    r"(?:ACCOUNT|ACCT)\.?\s*(?:NO\.?|NUMBER|NUM\.?|#)\s*:?\s*"
    r"(?P<v>(?=[A-Z0-9-]*\d)[A-Z0-9][A-Z0-9-]{4,19})(?![\w-])", re.I)

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
# Spellings an addr: list entry may use interchangeably with what the page
# shows ("500 INDUSTRY DRIVE" in the list, "500 INDUSTRY DR" on the form).
_ADDR_WORD_FORMS = [
    ("STREET", "ST"), ("AVENUE", "AVE", "AV"), ("ROAD", "RD"), ("DRIVE", "DR"),
    ("LANE", "LN"), ("BOULEVARD", "BLVD"), ("COURT", "CT"), ("CIRCLE", "CIR"),
    ("PLACE", "PL"), ("TERRACE", "TER"), ("PARKWAY", "PKWY"), ("HIGHWAY", "HWY"),
    ("SQUARE", "SQ"), ("TRAIL", "TRL"), ("CENTER", "CTR"), ("PLAZA", "PLZ"),
    ("NORTH", "N"), ("SOUTH", "S"), ("EAST", "E"), ("WEST", "W"),
    ("APARTMENT", "APT"), ("SUITE", "STE"),
]
# longest spelling first, so "ST" never wins a prefix of "STREET" only to
# fail the trailing word boundary
_ADDR_WORD_ALT = {w: "(?:" + "|".join(sorted(forms, key=len, reverse=True)) + ")"
                  for forms in _ADDR_WORD_FORMS for w in forms}
# Suffixes that are also everyday words: only when capitalised, so "our
# service center" or "the square footage" in running text does not count.
_STREET_SUFFIX_CAPS = "|".join(
    f"{w}|{w.capitalize()}" for w in
    "CENTER CTR PLAZA PLZ PARKWAY PKWY HIGHWAY HWY SQUARE SQ TRAIL TRL".split())
_UNIT = r"(?:,?\s*(?:(?:APT|UNIT|STE|SUITE)\b\.?|#)\s*[\w-]+)?"
# A dollar amount is never part of an address: form rows put a box amount
# right before the street ("12bAA  9477.36  1234 EXAMPLE STREET"). So a
# street-name word may not be an amount, and the house number may be neither
# the tail ("...36") nor the head ("9477...") of one. Nor is a street-name
# word a bare number: "90000 500 INDUSTRY WAY" is a ZIP followed by a street.
_AMOUNT_AHEAD = r"(?!\d[\d,]*\.\d{2}(?!\d))"
_STREET = (r"(?<!\d[.,])\d+(?![.,]?\d)\s+(?:%s(?!\d+\s)[A-Za-z0-9'.\-]+\s+){1,4}"
           r"(?:(?<=[ \t])(?:%s|(?-i:%s))|(?:%s))%s"
           % (_AMOUNT_AHEAD, _STREET_SUFFIX, _STREET_SUFFIX_CAPS,
              _STREET_SUFFIX_LONG, _UNIT))
# City and state are separated by a comma, a space, or both; some forms
# print the comma with no space after it ("SAMPLETOWN,CA 90000").
_CITY_SEP = r"(?:,\s*|\s+)"
_CITY_ZIP = r",\s*[A-Za-z .]+%s[A-Za-z]{2}\s+\d{5}(?:-\d{4})?" % _CITY_SEP
ADDR = re.compile(
    r"(?<!\w)(?:%s(?:%s)?|%s)(?!\w)" % (_STREET, _CITY_ZIP, _CITY_ZIP), re.I
)
# A unit designator on its own or apart from its street ("SUITE 2200",
# "Apt 4B", "22ND FLOOR"). Capitalised designator and a number required, so
# "1 unit 5 times", "UNITS 100" or "Suite of services" do not match.
_UNIT_WORDS = "|".join(f"{w}|{w.capitalize()}" for w in
                       "SUITE STE APT APARTMENT UNIT ROOM RM FLOOR".split())
UNIT_ALONE = re.compile(
    r"(?<![\w-])(?:(?:%s)\b\.?\s*#?\s*(?=[A-Za-z-]{0,3}\d)[\w-]+"
    r"|\d{1,3}(?:ST|ND|RD|TH|st|nd|rd|th)\s+(?:FLOOR|Floor))(?!\w)" % _UNIT_WORDS)
POBOX = re.compile(r"\bP\.?\s?O\.?\s?BOX\s+\d+(?:%s)?" % _CITY_ZIP, re.I)
# Line 2 of a two-line address ("SAMPLETOWN, CA 90000") — whole-line match only,
# and never on lines carrying form vocabulary, so return-page text is safe.
# Redaction tokens around it do not count as line content, so the city is
# still caught next to an already-redacted street or name ("[ADDR-1]
# SAMPLETOWN, CA 90000"); only the named group v is replaced.
_TOKEN = r"\[[A-Z]+[A-Z0-9.\-]*\]"
US_STATE = ("AL|AK|AZ|AR|CA|CO|CT|DE|DC|FL|GA|HI|ID|IL|IN|IA|KS|KY|LA|ME|MD|MA|"
            "MI|MN|MS|MO|MT|NE|NV|NH|NJ|NM|NY|NC|ND|OH|OK|OR|PA|RI|SC|SD|TN|TX|"
            "UT|VT|VA|WA|WV|WI|WY")
CITY_LINE = re.compile(
    r"^(?:\s*%s)*\s*(?P<v>[A-Za-z][A-Za-z .]{1,40}%s(?:%s)\s+\d{5}(?:-\d{4})?)"
    r"(?:\s*%s)*\s*$" % (_TOKEN, _CITY_SEP, US_STATE, _TOKEN))
# A city/state/zip in the middle of a line ("SAMPLETOWN, CA 90000-1234
# Recipient ID No. ..."). City = 1-3 capitalised words, real upper-case state
# codes only; the left edge is a guess, so a capitalised word or two before
# the city may go with it. ZIP+4 is unmistakable: comma optional, any line.
# A 5-digit ZIP needs the comma, is skipped on form-vocabulary lines, and
# may not be the start of an amount ("Proceeds,OR 12345.00").
_CITY_WORD = r"[A-Z][A-Za-z.'\-]*"
_CITY_INLINE = r"(?<![\w,])%s(?:\s%s){0,2}" % (_CITY_WORD, _CITY_WORD)
# "SAMPLETOWN CA US 90000": a form field for the country sits between state
# and ZIP. Comma optional, ZIP or ZIP+4, anywhere on a line.
CITY_US_INLINE = re.compile(
    r"%s%s(?:%s)\s+USA?\s+\d{5}(?:-\d{4})?(?![\w-]|[.,]\d)"
    % (_CITY_INLINE, _CITY_SEP, US_STATE))
CITY_ZIP4_INLINE = re.compile(
    r"%s%s(?:%s)\s+\d{5}-\d{4}(?![\w-])" % (_CITY_INLINE, _CITY_SEP, US_STATE))
CITY_INLINE = re.compile(
    r"%s,\s*(?:%s)\s+\d{5}(?![\w-]|[.,]\d)" % (_CITY_INLINE, US_STATE))
# OCR rows merge side-by-side fragments (two-space joiner) and stray wording
# ("IMPORTANT TAX RETURN DOCUMENT ENCLOSED  CITY, ST 12345"), so on OCR text
# the city/state/zip may be a line PREFIX or SUFFIX rather than the whole
# line. City capped at 3 words, real state codes only, re.I so an OCR read
# like "Ca" still matches. Applied to OCR-derived text only (OCR_ONLY_RULES).
_CITY_CORE = (r"[A-Za-z][A-Za-z.]*(?:\s[A-Za-z.]+){0,2}%s(?:%s)\s+\d{5}(?:-\d{4})?"
              % (_CITY_SEP, US_STATE))
CITY_EDGE_OCR = re.compile(
    r"(?:^\s*%s(?=\s\s|\s*$))|(?:(?<=\s)%s\s*$)" % (_CITY_CORE, _CITY_CORE), re.I)
# E-signature stamps: the signer ID printed under a DocuSign signature
# ("A1B2C3D4E5F64A7...") and the envelope uuid in the page header.
DOCUSIGN_ID = re.compile(r"(?<![0-9A-Za-z])[0-9A-F]{12,}\.{3}")
ENVELOPE_CONTEXT = re.compile(r"ENVELOPE\s+ID", re.I)
ENVELOPE_ID = re.compile(
    r"(?<![0-9A-Za-z])[0-9A-F]{8}(?:-[0-9A-F]{4}){3}-[0-9A-F]{12}(?![0-9A-Za-z])",
    re.I)
# Label of a signature stamp; the block under it is boxed as a region (see
# find_signature_regions). A bare "Signed by:" counts only with an ID below.
SIG_LABEL = re.compile(r"(Docu)?Signed\s+by:", re.I)
SIG_LABEL_STRICT = re.compile(r"DocuSigned\s+by:", re.I)
# Signs that a document went through an e-signature service; only then are
# small images taken for signatures and certificate pages dropped.
ESIGN_HEADER = re.compile(r"DOCU\s*SIGN\s+ENVELOPE\s+ID", re.I)
CERT_TITLE = re.compile(r"CERTIFICATE\s+OF\s+COMPLETION", re.I)
FORM_VOCAB = re.compile(r"SCHEDULE|\bFORM\b|\bBOX\b|\bLINE\b|\bPAGE\b", re.I)

# (pattern, token kind, reason tag, required line context, excluding line context)
PATTERN_RULES = [
    (DOCUSIGN_ID, "SIGNATURE", "[PATTERN:SIGNATURE]", None, None),
    (ENVELOPE_ID, "ENVELOPE", "[PATTERN:ENVELOPE]", ENVELOPE_CONTEXT, None),
    (SSN_SEP, "SSN", "[PATTERN:SSN]", None, None),
    (SSN_SPACED, "SSN", "[PATTERN:SSN]", None, None),
    (SSN_MASKED, "SSN", "[PATTERN:SSN]", None, None),
    (SSN_BARE, "SSN", "[PATTERN:SSN]", SSN_CONTEXT, None),
    (EIN, "EIN", "[PATTERN:EIN]", None, None),
    (EMAIL, "EMAIL", "[PATTERN:EMAIL]", None, None),
    (PHONE, "PHONE", "[PATTERN:PHONE]", None, None),
    (DOB_NUM, "DOB", "[PATTERN:DOB]", DOB_CONTEXT, None),
    (DOB_WORD, "DOB", "[PATTERN:DOB]", DOB_CONTEXT, None),
    (ROUTING, "ROUTING", "[PATTERN:ROUTING]", ROUTING_CONTEXT, None),
    # Address rules come before the ID rule, which would otherwise take the
    # ZIP on a line carrying ID wording and strand the city. The whole-line
    # city rules run again last, for a city left alone on its line by the
    # ID/account redactions.
    (POBOX, "ADDR", "[PATTERN:ADDR]", None, None),
    (ADDR, "ADDR", "[PATTERN:ADDR]", None, None),
    (UNIT_ALONE, "ADDR", "[PATTERN:ADDR]", None, None),
    (CITY_US_INLINE, "ADDR", "[PATTERN:ADDR]", None, None),
    (CITY_ZIP4_INLINE, "ADDR", "[PATTERN:ADDR]", None, None),
    (CITY_INLINE, "ADDR", "[PATTERN:ADDR]", None, FORM_VOCAB),
    (CITY_LINE, "ADDR", "[PATTERN:ADDR]", None, FORM_VOCAB),
    (CITY_EDGE_OCR, "ADDR", "[PATTERN:ADDR]", None, FORM_VOCAB),
    (ACCT_LABELED, "ACCT", "[PATTERN:ACCT]", None, None),
    (ID_TOKEN, "ID", "[PATTERN:ID]", ID_CONTEXT, None),
    (ACCT, "ACCT", "[PATTERN:ACCT]", None, None),
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

LIST_CATEGORIES = {"name": "NAME", "addr": "ADDR", "acct": "ACCT",
                   "employer": "EMPLOYER", "ssn": "SSN", "email": "EMAIL",
                   "dob": "DOB", "id": "ID", "phone": "PHONE"}
LIST_ALIASES = {"social": "ssn", "address": "addr", "account": "acct"}
_LIST_PREFIX = re.compile(r"\s*([A-Za-z]+)\s*:\s*(.*)$")


def _split_entry(line):
    """A list line -> (category, value, known). A one-word prefix that is not
    a category ("estate: X") still yields the value after the colon, as a
    name, so a mistyped prefix never leaves the value unredacted; known is
    False so the run can warn about it."""
    m = _LIST_PREFIX.match(line)
    if not m:
        return "name", line.strip(), True
    prefix = m.group(1).lower()
    prefix = LIST_ALIASES.get(prefix, prefix)
    if prefix in LIST_CATEGORIES:
        return prefix, m.group(2).strip(), True
    return "name", m.group(2).strip(), False


def list_unknown_prefixes(path):
    """1-based line numbers of active entries whose prefix is not a category.
    Numbers only: the prefix and value may both be sensitive."""
    if path is None or not Path(path).is_file():
        return []
    return [n for n, raw in enumerate(Path(path).read_text().splitlines(), 1)
            if raw.strip() and not raw.strip().startswith("#")
            and not _split_entry(raw.strip())[2]]


class TokenMap:
    """Stable value -> token assignment across every file in one run."""

    def __init__(self, ssns=()):
        """ssns: full SSNs known to be in the run; a masked SSN or bare
        last-4 tail then shares the token of the SSN it belongs to."""
        self._map = {}
        self._counters = defaultdict(int)
        self._acct_by_last4 = defaultdict(dict)
        by_last4 = defaultdict(set)
        for ssn in ssns:
            digits = re.sub(r"\D", "", ssn)
            by_last4[digits[-4:]].add(digits)
        self._ssn_by_last4 = {last4: next(iter(full))
                              for last4, full in by_last4.items() if len(full) == 1}

    @staticmethod
    def _normalize(kind, value):
        if kind in ("SSN", "EIN", "ACCT", "ROUTING"):
            return re.sub(r"\D", "", value)
        return re.sub(r"\s+", " ", value).strip().upper()

    def token(self, kind, value):
        norm = self._normalize(kind, value)
        if kind == "SSN" and len(norm) == 4:
            norm = self._ssn_by_last4.get(norm, norm)
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


_UNIT_WORDS = ("APT", "UNIT", "STE", "SUITE", "#")  # same set as _UNIT
_SPLIT_SUFFIXES = set(_ADDR_WORD_ALT) | {
    w for w in "CENTER CTR PLAZA PLZ PARKWAY PKWY HIGHWAY HWY SQUARE SQ TRAIL TRL".split()}


def _is_unit_word(word):
    return word.upper().rstrip(".") in _UNIT_WORDS or word.startswith("#")


def _addr_variants(value):
    """An addr: entry also matches its street half and its locality half
    (city, state, ZIP) on their own, as forms print them on two lines; every
    variant maps to the entry's token. An entry that is only a street, or
    that has no comma and no recognisable suffix, yields just itself."""
    yield value
    if "," in value:
        parts = [p.strip() for p in value.split(",") if p.strip()]
        if len(parts) >= 2 and _is_unit_word(parts[1].split()[0]):
            parts = [parts[0] + ", " + parts[1]] + parts[2:]
        street, locality = parts[0], ", ".join(parts[1:])
        if len(street.split()) >= 2 and len(locality.split()) >= 2:
            yield street
            yield locality
        return
    words = value.split()
    for i in range(1, len(words)):
        if words[i].upper().rstrip(".") in _SPLIT_SUFFIXES:
            end = i + 1
            if end < len(words) and _is_unit_word(words[end]):
                end += 2
            street, locality = words[:end], words[end:]
            if len(street) >= 3 and len(locality) >= 2:
                yield " ".join(street)
                yield " ".join(locality)
            return


def _entry_variants(category, value):
    if category == "addr":
        return _addr_variants(value)
    return _name_variants(category, value)


@functools.lru_cache(maxsize=None)
def _name_part_rxs(name):
    """(first-name regex, last-name regex) of a name: entry, or None for a
    one-word name or one whose first or last word is a bare initial. The
    first-name regex takes the middle name/initial along when it follows."""
    words = [re.escape(w) for w in name.split()]
    if len(words) < 2 or min(len(name.split()[0]), len(name.split()[-1])) < 2:
        return None
    if re.search(r"\d", name.split()[0] + name.split()[-1]):
        return None  # not a person's name (an address or number filed as one)
    middle = r"(?:\s+%s\.?)?" % r"\s+".join(words[1:-1]) if words[1:-1] else ""
    return (re.compile(r"(?<!\w)%s%s(?!\w)" % (words[0], middle), re.I),
            re.compile(r"(?<!\w)%s(?!\w)" % words[-1], re.I))


def split_name_hits(entries, line, flex):
    """name: entries whose first AND last name both appear on the line, in any
    order and with anything between them (separate form fields, "LAST FIRST",
    "JOHN & JANE SAMPLE") -> [(canonical, (first_rx, last_rx))]. A first or
    last name on its own is never a hit: many are ordinary words."""
    hits = []
    for name in dict.fromkeys(c for cat, c, _v, _rx in entries if cat == "name"):
        rxs = _name_part_rxs(name)
        if rxs and all(flex(rx).search(line) for rx in rxs):
            hits.append((name, rxs))
    return hits


def _literal_rx(value):
    """Whole-value literal match, case-insensitive, whitespace-collapsed;
    ocr_rx() makes it space-optional on OCR text."""
    words = [re.escape(w) for w in value.split()]
    return re.compile(r"(?<!\w)" + r"\s+".join(words) + r"(?!\w)", re.I)


def _addr_word_rx(word):
    """One word of an addr: entry: a street suffix, directional or unit word
    matches any of its spellings (_ADDR_WORD_FORMS); a period after the word
    is optional on both sides."""
    bare = word[:-1] if word.endswith(".") else word
    return _ADDR_WORD_ALT.get(bare.upper(), re.escape(bare)) + r"\.?"


def _addr_rx(value):
    """A listed address, however it is punctuated, spaced or abbreviated on
    the page: "1234 EXAMPLE STREET, SAMPLETOWN, CA 90000" also matches the
    same words with no commas, with wide gaps between form fields, and as
    "1234 EXAMPLE ST" / "1234 EXAMPLE ST." (see _ADDR_WORD_FORMS)."""
    words = [_addr_word_rx(w) for w in re.findall(r"[^\s,]+", value)]
    if not words:
        return None
    return re.compile(r"(?<!\w)" + r"(?:,\s*|\s+)".join(words) + r"(?!\w)", re.I)


def _ssn_rx(value):
    """A listed SSN in any grouping ("987-65-4321", "987 65 4321",
    "987654321"); None unless the value has exactly nine digits."""
    d = re.sub(r"\D", "", value)
    if len(d) != 9:
        return None
    return re.compile(r"(?<!\d)%s[- ]?%s[- ]?%s(?!\d)" % (d[:3], d[3:5], d[5:]))


_MONTHS = ("JANUARY FEBRUARY MARCH APRIL MAY JUNE JULY AUGUST SEPTEMBER "
           "OCTOBER NOVEMBER DECEMBER").split()
_DATE_NUM = re.compile(r"(\d{1,2})[/.-](\d{1,2})[/.-](\d{4}|\d{2})$")
_DATE_ISO = re.compile(r"(\d{4})-(\d{1,2})-(\d{1,2})$")
_DATE_WORD = re.compile(r"([A-Za-z]{3,9})\.?\s+(\d{1,2})(?:st|nd|rd|th)?,?\s+(\d{4})$",
                        re.I)


def _parse_date(value):
    """A listed date -> (year, month, day), or None. Numeric dates are read
    month first; a two-digit year is taken as written (no century)."""
    value = value.strip()
    if m := _DATE_ISO.match(value):
        y, mo, d = m.groups()
    elif m := _DATE_NUM.match(value):
        mo, d, y = m.groups()
    elif m := _DATE_WORD.match(value):
        name, d, y = m.groups()
        hits = [i for i, full in enumerate(_MONTHS, 1)
                if full.startswith(name.upper())]
        if len(hits) != 1:
            return None
        mo = hits[0]
    else:
        return None
    mo, d = int(mo), int(d)
    if not (1 <= mo <= 12 and 1 <= d <= 31):
        return None
    return y, mo, d


def _dob_rx(value):
    """A listed date in its common written forms: 01/02/1980, 1-2-80,
    1980-01-02, January 2, 1980, Jan 2 1980, 2 January 1980."""
    parsed = _parse_date(value)
    if not parsed:
        return None
    y, mo, d = parsed
    year = rf"(?:{y}|{y[-2:]})" if len(y) == 4 else y
    full = _MONTHS[mo - 1]
    month = full if len(full) <= 3 else rf"(?:{full}|{full[:3]}\.?)"
    if mo == 9:
        month = r"(?:SEPTEMBER|SEPT?\.?)"
    alts = [rf"(?<![\d/.-])0?{mo}[/.-]0?{d}[/.-]{year}(?![\d/.-])",
            rf"(?<!\w){month}\s+0?{d}(?:ST|ND|RD|TH)?,?\s+{y}(?!\d)",
            rf"(?<![\d/.-])0?{d}\s+{month},?\s+{y}(?!\d)"]
    if len(y) == 4:
        alts.append(rf"(?<![\d/.-]){y}-0?{mo}-0?{d}(?![\d/.-])")
    return re.compile("|".join(alts), re.I)


def _phone_rx(value):
    """A listed phone number with any of the usual separators, with or
    without a leading 1 or parentheses; None unless it has 7 or 10 digits
    (11 with a leading 1)."""
    d = re.sub(r"\D", "", value)
    if len(d) == 11 and d[0] == "1":
        d = d[1:]
    if len(d) == 10:
        area = rf"(?:\+?1[-. ]?)?\(?{d[:3]}\)?[-. ]?"
    elif len(d) == 7:
        area = ""
    else:
        return None
    return re.compile(rf"(?<![\d(+]){area}{d[-7:-4]}[-. ]?{d[-4:]}(?!\d)")


def _ssn_tail_rx(last4):
    """The bare tail of a known SSN ("-6789"). Not after a digit (ZIP+4,
    phone) and not the start of an amount ("-6789.00")."""
    return re.compile(r"(?<!\d)-%s(?!\d|[.,]\d)" % re.escape(last4))


_FLEXIBLE_RX = {"ssn": _ssn_rx, "dob": _dob_rx, "phone": _phone_rx, "addr": _addr_rx}


def load_list(path):
    """Parse redaction_list.txt -> [(category, canonical, variant, regex)].

    Lines: optional prefix (one of LIST_CATEGORIES, default name), '#'
    comments. ssn:, dob:, phone: and addr: entries match the value in its
    common written forms (see _ssn_rx, _dob_rx, _phone_rx, _addr_rx), not
    just as typed. Matching is case-insensitive with collapsed whitespace;
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
        category, value, _known = _split_entry(line)
        if not value:
            continue
        for variant in dict.fromkeys(_entry_variants(category, value)):
            flexible = _FLEXIBLE_RX.get(category)
            rx = (flexible(variant) if flexible else None) or _literal_rx(variant)
            entries.append((category, value, variant, rx))
    entries.sort(key=lambda e: len(e[3].pattern), reverse=True)  # longest wins
    return entries


def load_lists(*paths):
    """Merge several lists (master first, then the folder's) into one entry
    list; an entry present in more than one list is kept once."""
    merged = {}
    for path in paths:
        for entry in load_list(path):
            merged.setdefault((entry[0], _norm_value(entry[2])), entry)
    return sorted(merged.values(), key=lambda e: len(e[3].pattern), reverse=True)


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
        value = _split_entry(line)[1]
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


def redact_text(text, entries, tokens, findings, ocr=False, spans=None, sweep=(),
                presets=None):
    """Redact one document's text. findings[(reason, original, token)] += n.

    sweep = [(kind, value, rx)]: literal values a pattern found elsewhere in
    this run (see main); redacted everywhere with reason [SWEEP:kind].

    ocr=True (OCR-derived text) matches list entries, contexts and address
    patterns space-optionally and adds the digit-lookalike shadow pass.
    spans, if a list, receives (line_index, start, end, token) for every
    substitution; start/end index the ORIGINAL line, so the same match that
    produced the token can be located on the page (see redaction_rects).
    presets = {line_index: [(start, end, key)]}: stretches inside a signature
    region (see signature_presets), replaced first with the region's
    [SIGNATURE-n] token. They add no spans: the region is boxed as a whole.
    """
    flex = ocr_rx if ocr else (lambda rx: rx)
    out_lines = []
    for li, line in enumerate(text.splitlines()):
        s = line
        # orig_of[i] = index in `line` of s[i], or None inside an inserted token
        orig_of = list(range(len(line)))
        if presets and li in presets:
            parts, omap, last = [], [], 0
            for a, b, key in sorted(presets[li]):
                tok = tokens.token("SIGNATURE", key)
                findings[("[SIGNATURE]", line[a:b].strip(), tok)] += 1
                parts += [line[last:a], tok]
                omap += list(range(last, a)) + [None] * len(tok)
                last = b
            s, orig_of = "".join(parts) + line[last:], omap + list(range(last, len(line)))

        def substitute(rx, kind, reason, s, orig_of, canonical=None, shadow=False):
            src = _shadow(s) if shadow else s  # _shadow keeps length
            parts, omap, last = [], [], 0
            for m in rx.finditer(src):
                # a rule with a named group v redacts only that group
                a, b = m.span("v") if "v" in rx.groupindex else m.span()
                tok_val = canonical if canonical is not None else src[a:b]
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
        # judged on the untouched line, so "JOHN & JANE SAMPLE" loses JOHN too
        split = split_name_hits(entries, line, flex)
        for part in (0, 1):  # every first name before any shared last name
            for canonical, rxs in split:
                s, orig_of = substitute(flex(rxs[part]), "NAME", "[LIST:name]",
                                        s, orig_of, canonical=canonical)
        for rx, kind, reason, req_ctx, exc_ctx in PATTERN_RULES:
            if rx in OCR_ONLY_RULES and not ocr:
                continue
            if req_ctx and not flex(req_ctx).search(line):
                continue
            # judged on what is left of the line, as the audit will see it:
            # the "BOX" of an already-redacted PO box is not form vocabulary
            if exc_ctx and flex(exc_ctx).search(s):
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


def _as_file(src):
    """A PDF source is a path, or the bytes of an in-memory flattened copy."""
    return io.BytesIO(src) if isinstance(src, bytes) else src


# A gap wider than this fraction of the font size is a word space. Many PDFs
# position words instead of drawing space characters; pdfplumber's default
# (a fixed 3 pt) then glues the words of small print together
# ("JOHNASAMPLE"), and nothing matches.
WORD_GAP_RATIO = 0.15


def _is_upright(char):
    """pdfminer calls a character sideways on the sign of two matrix terms
    that are zero for upright text; after a rotation (a page stored
    sideways) they come out as +/-1e-5 noise and whole pages of ordinary
    text were handled as vertical text. Judge by size instead."""
    if char.get("upright", True):
        return True
    a, b, c, d = (char.get("matrix") or (0, 1, 1, 0))[:4]
    return a > 0 and d > 0 and max(abs(b), abs(c)) <= 0.01 * min(a, d)


def _textmap_tuples(page):
    """(character, char object or None) for a page's text, line by line.

    pdfplumber groups characters into lines by chaining: any two characters
    whose tops are within 3 pt join the same line, and so does whatever is
    within 3 pt of those. On small print, or next to a table column set
    slightly lower, that chains separate lines into one and interleaves their
    letters. Lines are therefore formed here, from the characters' bottom
    edge with a limit tied to the font size and anchored to the line's first
    character (no chaining); pdfplumber then orders and spaces each line."""
    from pdfplumber.utils.text import chars_to_textmap
    upright = sorted((dict(c, upright=True) for c in page.chars if _is_upright(c)),
                     key=lambda c: (c["bottom"], c["x0"]))
    other = [c for c in page.chars if not _is_upright(c)]
    groups = []
    for c in upright:
        if groups and c["bottom"] - groups[-1][0]["bottom"] <= min(
                3.0, max(0.5, 0.4 * groups[-1][0]["size"])):
            groups[-1].append(c)
        else:
            groups.append([c])
    if other:  # rotated text: left to pdfplumber as a whole
        groups.append(other)
    tuples = []
    for group in groups:
        part = chars_to_textmap(group, x_tolerance_ratio=WORD_GAP_RATIO).tuples
        if not "".join(ch for ch, _obj in part).strip():
            continue
        if tuples:
            tuples.append(("\n", None))
        tuples += part
    return tuples


def extract_pdf_pages(pdf_path):
    """Text-layer pages: characters with their boxes, grouped into lines by
    _textmap_tuples."""
    pages = []
    with pdfplumber.open(_as_file(pdf_path)) as pdf:
        for page in pdf.pages:
            tuples = _textmap_tuples(page)
            text = "".join(ch for ch, _obj in tuples)
            # pdfplumber measures from the PDF origin, PyMuPDF from the page's
            # top-left corner; they differ when the page box starts elsewhere
            ox, oy = page.bbox[0], page.bbox[1]
            boxes = [None if obj is None
                     else (obj["x0"] - ox, obj["top"] - oy,
                           obj["x1"] - ox, obj["bottom"] - oy)
                     for _ch, obj in tuples]
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


# A PDF "has a text layer" when its pages carry at least this many
# non-blank characters. Counted on the pages, never on pages_to_text(),
# whose PAGE_SEP lines would make a multi-page scan look like text.
MIN_TEXT_CHARS = 20


def page_text_chars(pages):
    """Non-blank characters across extracted pages (page separators excluded)."""
    return sum(len(t.strip()) for lines in pages for t, _b in lines)


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
_OCR_MAX_SIDE = 3300   # px; 300 DPI on a letter page. Phone scans store the
                       # photo's pixel size as the page size (2000+ pt), which
                       # at 300 DPI would be a 1000 DPI render that RapidOCR
                       # only shrinks again, so the long side is capped.


def _ocr_scale(width_pt, height_pt):
    return min(_OCR_SCALE, _OCR_MAX_SIDE / max(width_pt, height_pt, 1))


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


def _import_rapidocr():
    """onnxruntime prints a "GPU device discovery failed" warning straight to
    the C-level stderr while it is imported on a CPU-only machine; no logging
    setting reaches it, so fd 2 is parked on /dev/null for that one import.
    Import errors still surface: they are raised, not printed."""
    sys.stderr.flush()
    saved, devnull = os.dup(2), os.open(os.devnull, os.O_WRONLY)
    try:
        os.dup2(devnull, 2)
        from rapidocr_onnxruntime import RapidOCR
    finally:
        os.dup2(saved, 2)
        os.close(saved)
        os.close(devnull)
    return RapidOCR


def ocr_pdf_pages(pdf_path):
    """OCR every page (no text layer expected); boxes converted to PDF points."""
    global _OCR_ENGINE
    import numpy as np
    import pypdfium2 as pdfium
    if _OCR_ENGINE is None:
        _OCR_ENGINE = _import_rapidocr()()
    doc = pdfium.PdfDocument(pdf_path if isinstance(pdf_path, bytes)
                             else str(pdf_path))
    try:
        pages = []
        for i in range(len(doc)):
            scale = _ocr_scale(*doc[i].get_size())
            pil = doc[i].render(scale=scale).to_pil()
            result, _elapse = _OCR_ENGINE(np.array(pil))
            lines = []
            for text, boxes in _ocr_page_lines(result or []):
                lines.append((text, [None if b is None
                                     else tuple(v / scale for v in b)
                                     for b in boxes]))
            pages.append(lines)
        return pages
    finally:
        doc.close()


def ocr_pdf_text(pdf_path):
    return pages_to_text(ocr_pdf_pages(pdf_path))


# --------------------------------------------------------------- redacted PDF
PDF_SKIP_HINT = ("print it to PDF and re-run on the copy; with --no-flatten "
                 "its .txt extract may also be missing values typed into "
                 "form fields")


def _open_pymupdf(src):
    import pymupdf
    if isinstance(src, bytes):
        return pymupdf.open(stream=src, filetype="pdf")
    return pymupdf.open(str(src))


def flatten_pdf(pdf_path):
    """Merge form-field and annotation contents into the page content so they
    are extracted, redacted and audited like page text. In memory only: the
    source is never modified and no flattened copy touches the disk.
    -> None if there is nothing to flatten, else (pdf_bytes, field_values,
    sig_rects): field_values are the non-empty text-field values, for
    unflattened_count(); sig_rects = [(page_idx, (x0, top, x1, bottom))] of
    the signature fields, for find_signature_regions()."""
    import pymupdf
    doc = _open_pymupdf(pdf_path)
    try:
        widgets, sig_rects = [], []
        for page in doc:
            for w in page.widgets():
                widgets.append(w)
                if w.field_type == pymupdf.PDF_WIDGET_TYPE_SIGNATURE:
                    sig_rects.append((page.number, tuple(w.rect)))
        if not widgets and not any(next(page.annots(), None) is not None
                                   for page in doc):
            return None
        values = [w.field_value for w in widgets
                  if w.field_type == pymupdf.PDF_WIDGET_TYPE_TEXT
                  and isinstance(w.field_value, str) and w.field_value.strip()]
        doc.bake(annots=True, widgets=True)
        return doc.tobytes(garbage=4, deflate=True), values, sig_rects
    finally:
        doc.close()


def unrotate_pdf(src, sig_rects=()):
    """Rewrite rotated pages as unrotated ones that look the same, so the
    extracted character boxes and the redaction boxes share one coordinate
    system. In memory only, like flatten_pdf. sig_rects (as returned by
    flatten_pdf) are carried over to the unrotated pages.
    -> None if no page is rotated, else (pdf_bytes, rotated_page_count,
    sig_rects)."""
    import pymupdf
    doc = _open_pymupdf(src)
    try:
        rotated = {page.number: page.rotation_matrix
                   for page in doc if page.rotation != 0}
        if not rotated:
            return None
        for pno in rotated:
            doc[pno].remove_rotation()
        sig_rects = [(pi, tuple(pymupdf.Rect(r) * rotated[pi])
                      if pi in rotated else r) for pi, r in sig_rects]
        return doc.tobytes(garbage=4, deflate=True), len(rotated), sig_rects
    finally:
        doc.close()


def is_esigned(src, sig_fields=()):
    """Did this document go through an e-signature service? True on a
    signature form field (visible or not), an envelope-ID page header, or a
    stamp label / signer ID in the text."""
    if sig_fields:
        return True
    doc = _open_pymupdf(src)
    try:
        return any(rx.search(page.get_text())
                   for page in doc
                   for rx in (ESIGN_HEADER, SIG_LABEL_STRICT, DOCUSIGN_ID))
    finally:
        doc.close()


def certificate_start(doc):
    """0-based index of the first e-signature certificate page, or None. A
    certificate on the very first page is not one appended to a document."""
    for page in doc:
        if page.number and CERT_TITLE.search(page.get_text()):
            return page.number
    return None


def drop_certificate_pages(src):
    """Leave out the certificate an e-signature service appends (signer
    names, emails, IP addresses, timestamps): its first page and every page
    after it. In memory only, like flatten_pdf.
    -> None if there is none, else (pdf_bytes, first_dropped, last_dropped),
    1-based."""
    doc = _open_pymupdf(src)
    try:
        start, total = certificate_start(doc), len(doc)
        if start is None:
            return None
        doc.select(list(range(start)))
        return doc.tobytes(garbage=4, deflate=True), start + 1, total
    finally:
        doc.close()


def unflattened_count(field_values, text):
    """How many field values are absent from the flattened text (a field with
    no rendered appearance bakes to nothing). A count, never the values."""
    squeezed = "".join(text.split())
    return sum(1 for v in field_values if "".join(v.split()) not in squeezed)


SIG_ID_REACH = 120          # max points from a stamp label down to its ID line
SIG_ID_SHIFT = 40           # max horizontal offset between label and ID line
SIG_DEFAULT_AREA = (180, 60)  # boxed under a label that has no ID line
SIG_MAX_GRAPHIC = (0.6, 200)  # page-width share / height of a stamp graphic
SIG_PAD = 2
SIG_MIN_FIELD = 5           # a smaller signature field is invisible: no box
SIG_MIN_IMAGE = (10, 5)     # smaller images are specks, not signatures
SIG_REACH = 14              # how far a stamp's frame/label lies from its image
SIG_FRAME = (1.6, 120, 100)   # frame width: share of image width / floor; height
SIG_SMALL_PRINT = (160, 9.8)  # label/ID line: max width, max height (~8 pt type)


def _intersects(a, b):
    return a[0] < b[2] and b[0] < a[2] and a[1] < b[3] and b[1] < a[3]


def _gap(a, b):
    """Distance between two boxes; 0 if they touch or overlap."""
    return max(a[0] - b[2], b[0] - a[2], a[1] - b[3], b[1] - a[3], 0)


def _image_stamps(page):
    """Small images on a page, each widened by the frame drawings and small
    print around it: the signature stamps of an e-signed document whose label
    and ID line are not readable text."""
    pw = page.rect.width
    log = [(kind, tuple(r)) for kind, r in page.get_bboxlog()]
    out = []
    for kind, seed in log:
        w, h = seed[2] - seed[0], seed[3] - seed[1]
        if ("image" not in kind or w < SIG_MIN_IMAGE[0] or h < SIG_MIN_IMAGE[1]
                or w > SIG_MAX_GRAPHIC[0] * pw or h > SIG_MAX_GRAPHIC[1]):
            continue
        frame_w = max(SIG_FRAME[0] * w, SIG_FRAME[1])
        near = [r for k, r in log
                if ("path" in k and r[2] - r[0] <= frame_w
                    and r[3] - r[1] <= SIG_FRAME[2])
                or ("text" in k and r[2] - r[0] <= SIG_SMALL_PRINT[0]
                    and r[3] - r[1] <= SIG_SMALL_PRINT[1])]
        rect = seed
        for _ in range(2):  # the label sits beyond the frame it belongs to
            rect = _union([rect] + [r for r in near if _gap(r, rect) <= SIG_REACH])
        out.append(rect)
    return out


def find_signature_regions(pages, src, widget_rects=(), esigned=False):
    """Signature blocks to box as a whole: DocuSign-style stamps (label, the
    signature itself, signer ID line), signature form fields and — in an
    e-signed document (see is_esigned) — small images with their frames.
    -> ({page_idx: [(rect, key)]}, pages_without_id). key is the signer ID
    (one token per signer across the run) or None when there is none;
    pages_without_id lists 1-based pages where a label had no ID line and a
    default area was boxed."""
    found, no_id = defaultdict(list), []
    for pi, lines in enumerate(pages):
        ids = []
        for text, boxes in lines:
            for m in DOCUSIGN_ID.finditer(text):
                bx = [x for x in boxes[m.start():m.end()] if x]
                if bx:
                    ids.append([_union(bx), m.group(0), False])
        for text, boxes in lines:
            for m in SIG_LABEL.finditer(text):
                bx = [x for x in boxes[m.start():m.end()] if x]
                if not bx:
                    continue
                lab = _union(bx)
                below = [i for i in ids if not i[2]
                         and -2 <= i[0][1] - lab[1] <= SIG_ID_REACH
                         and abs(i[0][0] - lab[0]) <= SIG_ID_SHIFT]
                if below:
                    hit = min(below, key=lambda i: i[0][1])
                    hit[2] = True
                    found[pi].append((_union([lab, hit[0]]), hit[1]))
                elif m.group(1):
                    no_id.append(pi + 1)
                    found[pi].append(((lab[0], lab[1],
                                       lab[0] + SIG_DEFAULT_AREA[0],
                                       lab[3] + SIG_DEFAULT_AREA[1]), None))
    for pi, rect in widget_rects:
        if (pi < len(pages) and rect[2] - rect[0] >= SIG_MIN_FIELD
                and rect[3] - rect[1] >= SIG_MIN_FIELD):
            found[pi].append((tuple(rect), None))
    if not found and not esigned:
        return {}, no_id

    regions = {}
    doc = _open_pymupdf(src)
    try:
        if esigned:
            for page in doc:
                found[page.number] += [(r, None) for r in _image_stamps(page)]
        for pi, items in sorted(found.items()):
            if not items:
                continue
            page = doc[pi]
            pw, ph = page.rect.width, page.rect.height
            marks = [tuple(r) for kind, r in page.get_bboxlog()
                     if not kind.startswith("ignore")
                     and r[2] - r[0] <= SIG_MAX_GRAPHIC[0] * pw
                     and r[3] - r[1] <= SIG_MAX_GRAPHIC[1]]
            merged = []
            for rect, key in items:
                rect = _union([rect] + [m for m in marks if _intersects(m, rect)])
                rect = (max(0, rect[0] - SIG_PAD), max(0, rect[1] - SIG_PAD),
                        min(pw, rect[2] + SIG_PAD), min(ph, rect[3] + SIG_PAD))
                for i, (other, okey) in enumerate(merged):
                    if _intersects(other, rect):
                        merged[i] = (_union([other, rect]), okey or key)
                        break
                else:
                    merged.append((rect, key))
            regions[pi] = merged
    finally:
        doc.close()
    return regions, no_id


def signature_presets(pages, regions):
    """The characters of pages_to_text(pages) that lie inside a signature
    region -> ({line_index: [(start, end, region)]}, regions_with_text) with
    region = (page_idx, n), the n-th region of that page."""
    presets, with_text = defaultdict(list), set()
    for li, loc in enumerate(_line_map(pages)):
        if loc is None or loc[0] not in regions:
            continue
        boxes = pages[loc[0]][loc[1]][1]
        for n, (rect, _key) in enumerate(regions[loc[0]]):
            inside = [i for i, b in enumerate(boxes) if b
                      and rect[0] <= (b[0] + b[2]) / 2 <= rect[2]
                      and rect[1] <= (b[1] + b[3]) / 2 <= rect[3]]
            start = prev = None
            for i in inside + [None]:
                if start is not None and (
                        i is None or any(boxes[prev + 1:i])):
                    presets[li].append((start, prev + 1, (loc[0], n)))
                    with_text.add((loc[0], n))
                    start = None
                if start is None:
                    start = i
                prev = i
    return presets, with_text


def _text_band(top, bottom):
    """The thin horizontal band, through the middle of a line's character
    boxes, that is used to remove the line's glyphs (see write_redacted_pdf)."""
    mid, half = (top + bottom) / 2, 0.1 * (bottom - top)
    return mid - half, mid + half


THIN_BOX = 2.5  # pt; no real line of text is this short


def _repair_thin_boxes(page, rects):
    """Some fonts give the text extractor character boxes of almost no
    height, sitting on the descender line: nothing is removed there and the
    box and its label are invisible. Rebuild such a box from the glyphs
    PyMuPDF places at that spot — the line whose bottom edge is nearest.
    -> [(box, token)], other boxes unchanged."""
    if not any(bottom - top < THIN_BOX for (_x0, top, _x1, bottom), _t in rects):
        return list(rects)
    glyphs = [c["bbox"] for b in page.get_text("rawdict")["blocks"] if b["type"] == 0
              for ln in b["lines"] for sp in ln["spans"] for c in sp["chars"]
              if c["c"].strip()]
    out = []
    for (x0, top, x1, bottom), tok in rects:
        if bottom - top < THIN_BOX:
            mid = (top + bottom) / 2
            near = [g for g in glyphs
                    if x0 - 0.5 <= (g[0] + g[2]) / 2 <= x1 + 0.5
                    and g[1] - 0.5 <= mid <= g[3] + 0.5]
            if near:
                edge = min((g[3] for g in near), key=lambda y1: abs(y1 - bottom))
                line = [g for g in near if abs(g[3] - edge) <= 1.0]
                gy0, gy1 = min(g[1] for g in line), max(g[3] for g in line)
                h = gy1 - gy0
                out.append(((min(x0, min(g[0] for g in line)), gy0 + 0.12 * h,
                             max(x1, max(g[2] for g in line)), gy1 - 0.1 * h), tok))
                continue
        out.append(((x0, top, x1, bottom), tok))
    return out


def _unremoved_boxes(pdf_bytes, boxes_by_page):
    """{page_idx: [box]} of the redaction boxes that still hold characters,
    as seen by the extractor that produced the boxes. The band misses glyphs
    whose position in PyMuPDF differs from their pdfplumber box (unusual
    font metrics); those boxes are then cleared whole."""
    left = {}
    with pdfplumber.open(io.BytesIO(pdf_bytes)) as pdf:
        for pi, boxes in boxes_by_page.items():
            hit = set()
            ox, oy = pdf.pages[pi].bbox[0], pdf.pages[pi].bbox[1]
            for ch in pdf.pages[pi].chars:
                if not ch["text"].strip():
                    continue
                cx = (ch["x0"] + ch["x1"]) / 2 - ox
                cy = (ch["top"] + ch["bottom"]) / 2 - oy
                # a little below the box too: see _repair_thin_boxes
                hit.update(i for i, (x0, top, x1, bottom) in enumerate(boxes)
                           if x0 <= cx <= x1
                           and top <= cy <= bottom + 0.2 * (bottom - top))
            if hit:
                left[pi] = [boxes[i] for i in sorted(hit)]
    return left


def write_redacted_pdf(src, dst, rects_by_page, ocr_layer=(), sig_rects=None):
    """True-redact src into dst: a black box with the white token label over
    each rect (drawn here, not by PyMuPDF, which drops the label of a box
    under about 8 pt tall — i.e. on small print), the underlying text and
    image pixels removed, then metadata, attachments, links and hidden text
    scrubbed. Text is removed with a thin band through the middle of each
    rect: PyMuPDF deletes every glyph whose box touches a redaction, and on
    tightly spaced lines the glyph boxes of the lines above and below reach
    into the full rect. A box whose characters survive the band is cleared
    whole instead. sig_rects = {page_idx:
    [(rect, token)]} are signature regions: boxed first, and any line art
    they touch is removed with them. ocr_layer =
    [(page_idx, (x0, top, x1, bottom), text)] of REDACTED OCR lines written
    back as invisible text so a scanned PDF stays searchable. Returns None on
    success, else a reason the PDF was skipped: fillable/annotated, rotated
    or cropped pages are not safely redactable by this path."""
    import pymupdf
    doc = _open_pymupdf(src)
    try:
        if doc.is_form_pdf:
            return "has fillable form fields"
        for page in doc:
            if page.rotation != 0:
                return "has rotated pages"
            # sizes, not coordinates: PyMuPDF reports the two boxes from
            # different origins when the page box does not start at (0, 0)
            if (abs(page.cropbox.width - page.mediabox.width) > 0.01
                    or abs(page.cropbox.height - page.mediabox.height) > 0.01):
                return "has a crop box"
            if (next(page.widgets(), None) is not None
                    or next(page.annots(), None) is not None):
                return "has form fields or annotations"
        labels = defaultdict(list)
        rects_by_page = {pi: _repair_thin_boxes(doc[pi], rects)
                         for pi, rects in rects_by_page.items() if rects}
        for pi, page in enumerate(doc):
            sigs = (sig_rects or {}).get(pi, ())
            for rect, tok in sigs:
                page.add_redact_annot(pymupdf.Rect(rect), fill=(0, 0, 0),
                                      cross_out=False)
                labels[pi].append((pymupdf.Rect(rect), tok))
            if sigs:
                page.apply_redactions(
                    images=pymupdf.PDF_REDACT_IMAGE_PIXELS,
                    graphics=pymupdf.PDF_REDACT_LINE_ART_REMOVE_IF_TOUCHED)
            rects = rects_by_page.get(pi, ())
            for (x0, top, x1, bottom), _tok in rects:
                y0, y1 = _text_band(top, bottom)
                page.add_redact_annot(pymupdf.Rect(x0, y0, x1, y1),
                                      fill=False, cross_out=False)
            if rects:
                page.apply_redactions(images=pymupdf.PDF_REDACT_IMAGE_PIXELS)
        boxes_by_page = {pi: [box for box, _tok in rects]
                         for pi, rects in rects_by_page.items() if rects}
        if boxes_by_page:
            for pi, boxes in _unremoved_boxes(doc.tobytes(), boxes_by_page).items():
                for box in boxes:
                    doc[pi].add_redact_annot(pymupdf.Rect(box), fill=False,
                                             cross_out=False)
                doc[pi].apply_redactions(images=pymupdf.PDF_REDACT_IMAGE_PIXELS)
        for pi, page in enumerate(doc):
            rects = rects_by_page.get(pi, ())
            for (x0, top, x1, bottom), tok in rects:
                inset = min(0.5, (bottom - top) / 4)
                rect = pymupdf.Rect(x0, top + inset, x1, bottom - inset)
                # the visible box: image pixels under all of it, no more text
                page.add_redact_annot(rect, fill=(0, 0, 0), cross_out=False)
                labels[pi].append((rect, tok))
            if rects:
                page.apply_redactions(images=pymupdf.PDF_REDACT_IMAGE_PIXELS,
                                      text=pymupdf.PDF_REDACT_TEXT_NONE)
            for rect, tok in labels[pi]:
                size = min(8.0, 0.75 * rect.height)
                width = pymupdf.get_text_length(tok, fontsize=size)
                size *= min(1.0, (rect.width - 1) / width)
                if size > 0:
                    page.insert_text((rect.x0 + 0.5, rect.y1 - 0.25 * rect.height),
                                     tok, fontsize=size, color=(1, 1, 1))
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


def _same_rect(a, b, tol=1.5):
    return all(abs(x - y) <= tol for x, y in zip(a, b))


def verify_redacted_pdf(dst, entries, ocr=False, sweep=(), sig_rects=None,
                        signatures=True):
    """Re-extract the saved PDF with the same extractor and audit it with the
    same rules; also require that no metadata, widgets, annotations or
    embedded files remain, and that nothing but the box is left in a
    signature region. -> list of (line, reason) FAILs; empty = clean."""
    import pymupdf
    fails, _warns = audit_text(extract_pdf_text(dst), entries, ocr=ocr, sweep=sweep,
                               signatures=signatures)
    doc = pymupdf.open(str(dst))
    try:
        for pi, sigs in (sig_rects or {}).items():
            log = [(kind, tuple(r)) for kind, r in doc[pi].get_bboxlog()]
            for rect, _tok in sigs:
                inner = (rect[0] + 1, rect[1] + 1, rect[2] - 1, rect[3] - 1)
                for kind, r in log:
                    if not _intersects(r, inner):
                        continue
                    if "image" in kind:  # partly covered: pixels were blanked
                        left = (r[0] >= rect[0] - 1 and r[1] >= rect[1] - 1
                                and r[2] <= rect[2] + 1 and r[3] <= rect[3] + 1)
                    elif "path" in kind or "shade" in kind:
                        left = not _same_rect(r, rect)  # our own box is fine
                    else:
                        left = False
                    if left:
                        fails.append((pi + 1, "signature graphics remain"))
                        break

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
TOKEN_RX = re.compile(_TOKEN)
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


def audit_text(text, entries, ocr=False, sweep=(), signatures=True):
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
        if split_name_hits(entries, line, flex):
            hit.add("[LIST:name]")
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
        if signatures and flex(SIG_LABEL_STRICT).search(line):
            hit.add("[SIGNATURE] stamp label remains")
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
#   ssn:       social security numbers, any grouping (also caught by
#              pattern; listing one also covers its bare 9-digit form and
#              ties XXX-XX-1234 / -1234 to the same [SSN-n] token)
#   email:     email addresses (also caught by pattern)
#   dob:       dates of birth; 01/02/1980 also matches 1-2-80, 1980-01-02,
#              January 2, 1980 ... (numeric dates are read month first;
#              the pattern only catches dates on DOB-labeled lines)
#   id:        driver's license / state ID numbers (the pattern only
#              catches them on license-labeled lines)
#   phone:     phone numbers, any separators
#   addr:      street addresses; commas and spacing need not match the page
#   acct:      account numbers (8+ digit runs are also caught by pattern)
# Unprefixed lines default to name. Matching is case-insensitive with
# collapsed whitespace.
#
# Every run of redact.py appends candidate entries found on
# name-labeled lines of your PDFs under a dated '# auto-added' header. Review
# them; to REJECT one, comment it out (keep the line) — a commented-out entry
# is never redacted and never re-added.
#
# Entries common to every folder (your own name, address, ...) belong in the
# master list instead — see --master in `redact.py --help`.
#
# name: JOHN Q TAXPAYER
# employer: SOME BANK NA
# addr: 123 MAIN STREET, ANYTOWN, CA 90000
# acct: 001234567890
# ssn: 000-12-3456
"""

SUGGEST_SKIP = re.compile(r"ADDRESS", re.I)
SUGGEST_EMPLOYER = re.compile(r"\bPAYER|\bEMPLOYER\b|BANK|BROKER|FUND", re.I)


# A caps run containing any of these is form wording, not a name ("COPY B
# FOR", "KEEP FOR YOUR RECORDS", "INSTRUCTIONS FOR RECIPIENTS OF FORM").
SUGGEST_NEVER = set(
    "FOR TO BY IN ON AT IF IS ARE BE AS IT THIS THAT YOUR YOU WITH FROM NOT "
    "SEE KEEP COPY FORM FORMS INSTRUCTIONS IRS FATCA OMB VOID CORRECTED BOX "
    "LINE PAGE SCHEDULE RECORDS UNDER SECTION SEC CODE PART PURSUANT TREAS "
    "REG REGS REGULATION REGULATIONS ELECTION SALE PTE FEIN PER ACT".split())
# What may stand between a name label and the name it introduces
# ("RECIPIENT'S NAME:", "EMPLOYEE -").
_AFTER_LABEL = re.compile(r"(?:'?S)?(?:\s+NAMES?)?\s*[:\-]?\s*", re.I)
# ... and these too, unless the line names a payer/employer/bank, whose names
# do contain such words ("FAKE FEDERAL CREDIT UNION", "BANK OF EXAMPLE").
SUGGEST_NOT_A_PERSON = set(
    "OF TAX TAXES RETURN STATEMENT INFORMATION DEPARTMENT TREASURY INTERNAL "
    "REVENUE SERVICE FEDERAL INCOME WITHHELD WITHHOLDING REQUIREMENT REQUIRED "
    "IMPORTANT NOTICE TOTAL AMOUNT PAYMENT PAYMENTS DIVIDENDS INTEREST "
    "PROCEEDS WAGES SUMMARY DETAIL CONSOLIDATED YEAR".split())


def suggest_entries(raw_texts, entries, seen=()):
    """Candidate list entries from name-labeled lines that neither an active
    entry covers nor `seen` (active or commented-out list values) contains."""
    seen, out = {_norm_value(v) for v in seen}, []
    for name in sorted(raw_texts):
        for line in raw_texts[name].splitlines():
            if not NAME_LABEL.search(line) or SUGGEST_SKIP.search(line):
                continue
            # only the caps run a label introduces: other caps on such a line
            # are form wording ("... UNDER SECTION 754 ... PARTNER NAME")
            runs = []
            for label in NAME_LABEL.finditer(line):
                start = _AFTER_LABEL.match(line, label.end()).end()
                run = CAPS_RUN.match(line, start)
                if run:
                    runs.append(run)
            for m in runs:
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
                vocab = SUGGEST_NEVER if cat == "employer" else (
                    SUGGEST_NEVER | SUGGEST_NOT_A_PERSON)
                if vocab & set(cand.upper().split()):
                    continue  # form wording
                seen.add(_norm_value(cand))
                out.append(f"{cat}: {cand}")
    return out


def format_report(findings_by_file, warnings, list_desc, unused=(), added=(),
                  master_desc=None):
    lines = ["REDACTION PREVIEW", f"redaction list: {list_desc}"]
    if master_desc:
        lines.append(f"master list: {master_desc}")
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


CANNOT_WRITE = ("error: cannot write {out} — if it is open in a PDF viewer or "
                "another program, close it and re-run. The file on disk is "
                "from an EARLIER run; do not hand it off.")


def _is_write_error(exc):
    """A failure to replace the output file (e.g. locked by a viewer), as
    opposed to a failure inside the redaction itself."""
    return isinstance(exc, OSError) or any(
        hint in str(exc).lower()
        for hint in ("permission denied", "cannot remove file", "cannot open file",
                     "cannot rename"))


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


MASTER_LIST_NAME = "master_redaction_list.txt"


def default_master_path():
    """The master list: entries shared by every run (your own name, address,
    ...). Lives in the user's config directory, never next to the script."""
    config = os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config"
    return Path(config) / "pdf-redactor" / MASTER_LIST_NAME


SIG_MENTION = re.compile(r"docu\s*sign|signed\s*by|signature", re.I)


def _positions_confirmed(page, page_lines, sample=300):
    """'n of m': how many sampled character boxes (from the text extractor)
    sit on a glyph as PyMuPDF places it. Redaction boxes are drawn from the
    former and applied by the latter, so a low count means misplaced boxes."""
    lines = [ln for b in page.get_text("rawdict")["blocks"] if b["type"] == 0
             for ln in b["lines"]]
    sideways = sum(1 for ln in lines if abs(ln["dir"][0]) < 0.99
                   for sp in ln["spans"] for c in sp["chars"] if c["c"].strip())
    raw = [c for ln in lines if abs(ln["dir"][0]) >= 0.99
           for sp in ln["spans"] for c in sp["chars"] if c["c"].strip()]
    glyphs = [c["bbox"] for c in raw]
    # lines as drawn: distinct baselines, 1 pt apart or more
    baselines, drawn = sorted(c["origin"][1] for c in raw), 0
    for i, y in enumerate(baselines):
        drawn += i == 0 or y - baselines[i - 1] > 1.0
    # how far the character boxes of one extracted line are spread vertically
    spreads = sorted(max(tops) - min(tops) for tops in (
        [b[1] for ch, b in zip(text, bx) if b and ch.strip()]
        for text, bx in page_lines) if tops)
    boxes = [b for text, bx in page_lines
             for ch, b in zip(text, bx) if b and ch.strip()][:sample]
    hit = 0
    for x0, top, x1, bottom in boxes:
        cx, cy = (x0 + x1) / 2, (top + bottom) / 2
        hit += any(g[0] <= cx <= g[2] and g[1] <= cy <= g[3] for g in glyphs)
    def median(vals):
        vals = sorted(vals)
        return vals[len(vals) // 2] if vals else 0.0
    return (f"{hit} of {len(boxes)}; median character box "
            f"{median(b[2] - b[0] for b in boxes):.2f}x"
            f"{median(b[3] - b[1] for b in boxes):.2f} pt, glyph "
            f"{median(g[2] - g[0] for g in glyphs):.2f}x"
            f"{median(g[3] - g[1] for g in glyphs):.2f} pt; lines: "
            f"{len(spreads)} extracted / {drawn} drawn; vertical spread within "
            f"an extracted line: median {median(spreads):.2f}, "
            f"max {max(spreads, default=0.0):.2f} pt; sideways characters: "
            f"{sideways}")


def inspect_pdf(pdf_path, flatten=True):
    """Structure of a PDF as the signature detection sees it -> report lines.
    Counts, kinds and sizes ONLY — never document text — so the output is
    safe to share when a signature was not boxed."""
    from collections import Counter
    lines = []
    doc = _open_pymupdf(pdf_path)
    try:
        fields = Counter(w.field_type_string for page in doc for w in page.widgets())
        annots = Counter(a.type[1] for page in doc for a in page.annots())
    finally:
        doc.close()
    src, sig_fields = pdf_path, ()
    flat = flatten_pdf(pdf_path) if flatten else None
    if flat:
        src, _values, sig_fields = flat
    unrotated = unrotate_pdf(src, sig_fields)
    if unrotated:
        src, _count, sig_fields = unrotated
    esigned = is_esigned(src, sig_fields)
    count = lambda c: ", ".join(f"{k}={v}" for k, v in sorted(c.items())) or "none"
    lines.append(f"  form fields: {count(fields)}; annotations: {count(annots)}; "
                 f"flattened: {'yes' if flat else 'no'}; "
                 f"rotated pages: {unrotated[1] if unrotated else 0}; "
                 f"e-signed: {'yes' if esigned else 'no'}")
    pages = extract_pdf_pages(src)
    regions, no_id = find_signature_regions(pages, src, sig_fields, esigned)
    doc = _open_pymupdf(src)
    try:
        cert = certificate_start(doc) if esigned else None
        lines.append("  certificate pages: "
                     + ("none found" if cert is None else
                        f"{cert + 1}-{len(doc)} (dropped from the output unless "
                        "--keep-certificate; regions there do not apply)"))
        for pi, page_lines in enumerate(pages):
            texts = [t for t, _b in page_lines]
            log = [(kind, r) for kind, r in doc[pi].get_bboxlog()]
            images = [r for kind, r in log if "image" in kind]
            small = sorted({f"{r[2] - r[0]:.0f}x{r[3] - r[1]:.0f}" for r in images
                            if r[2] - r[0] <= SIG_MAX_GRAPHIC[0] * doc[pi].rect.width
                            and r[3] - r[1] <= SIG_MAX_GRAPHIC[1]})
            lines.append(
                f"  page {pi + 1}: {sum(len(t.strip()) for t in texts)} text chars, "
                f"{len(images)} image(s), "
                f"{sum('path' in kind for kind, _r in log)} drawing(s); "
                f"stamp labels: {sum(len(SIG_LABEL_STRICT.findall(t)) for t in texts)} "
                f"DocuSigned / {sum(len(SIG_LABEL.findall(t)) for t in texts)} any; "
                f"signer IDs: {sum(len(DOCUSIGN_ID.findall(t)) for t in texts)}; "
                f"lines mentioning signing: "
                f"{sum(bool(SIG_MENTION.search(t)) for t in texts)}; "
                f"regions: {len(regions.get(pi, ()))}"
                + ("".join(f" [{r[2] - r[0]:.0f}x{r[3] - r[1]:.0f} pt]"
                           for r, _k in regions.get(pi, ())))
                + (f"; small images (pt): {', '.join(small)}" if small else "")
                + f"; page box origin: ({doc[pi].mediabox.x0:.0f}, "
                  f"{doc[pi].mediabox.y0:.0f}); "
                  f"character positions confirmed: {_positions_confirmed(doc[pi], page_lines)}"
                + ("; label without ID line" if pi + 1 in no_id else ""))
    finally:
        doc.close()
    return lines


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
    ap.add_argument("--no-flatten", dest="flatten", action="store_false",
                    help="do not flatten form fields and annotations into "
                         "the page (in memory) before extraction; such PDFs "
                         "then get a .txt extract only, without the values "
                         "typed into fields")
    ap.add_argument("--no-signatures", dest="signatures", action="store_false",
                    help="do not box signature blocks (DocuSign-style stamps "
                         "and signature form fields) as a whole; signer and "
                         "envelope IDs are still redacted by pattern")
    ap.add_argument("--keep-certificate", dest="certificate", action="store_false",
                    help="keep the certificate pages an e-signature service "
                         "appends (signer names, emails, IP addresses); by "
                         "default they are left out of the output")
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
    ap.add_argument("--master", dest="master_path", metavar="PATH",
                    help="master redaction list merged into every run "
                         f"(default: {default_master_path()}); same format as "
                         "the redaction list, never written by the script")
    ap.add_argument("--no-master", dest="master", action="store_false",
                    help="do not load the master redaction list")
    ap.add_argument("--inspect", action="store_true",
                    help="print the structure of the raw PDFs as the signature "
                         "detection sees it (counts and sizes only, never "
                         "text) and exit; nothing is written")
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

    if not args.master:
        master_path, master_desc = None, "skipped (--no-master)"
    else:
        if args.master_path and not Path(args.master_path).is_file():
            sys.exit(f"error: master list {args.master_path} is not a file")
        master_path = Path(args.master_path) if args.master_path else default_master_path()
        master_desc = (f"found {master_path} ({len(load_list(master_path))} entries)"
                       if master_path.is_file() else
                       f"none (create {master_path} to share entries across folders)")

    entries = load_lists(master_path, list_path)
    warnings = []
    for desc, path in (("master list", master_path), ("redaction list", list_path)):
        lines = list_unknown_prefixes(path)
        if lines:
            warnings.append(
                f"UNKNOWN LIST PREFIX: {desc} line(s) {', '.join(map(str, lines))} "
                f"— not one of {', '.join(f'{c}:' for c in LIST_CATEGORIES)}; the "
                "value after the colon is redacted as a name")
    list_desc = (f"found {list_path} ({len(load_list(list_path))} entries)"
                 if list_path.is_file() else "NONE")

    if args.audit:
        txts = [single] if single else sorted(
            [*folder.glob("*.txt"), *folder.glob("*.redacted.pdf")])
        txts = [t for t in txts if t.name != "redaction_list.txt"]
        if not txts:
            sys.exit(f"error: no .txt extracts or .redacted.pdf files found in {folder}")
        print(f"LEAK AUDIT of {len(txts)} extract(s)  (list: {list_desc}; "
              f"master list: {master_desc})")
        n_fail = n_warn = 0
        for t in txts:
            if t.suffix.lower() == ".pdf":
                text, is_ocr = extract_pdf_text(t), True  # strictest setting
            else:
                text = t.read_text()
                is_ocr = _is_ocr_extract(text)
            fails, warns = audit_text(text, entries, ocr=is_ocr,
                                      signatures=args.signatures)
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
    if args.inspect:
        print("INSPECT (structure only — no document text)")
        for n, pdf in enumerate(pdfs, 1):
            print(f"file {n} of {len(pdfs)}:")  # not the name: it may identify
            print("\n".join(inspect_pdf(pdf, args.flatten)))
        return 0
    if single and not args.preview:
        warnings.append("SINGLE-FILE RUN: tokens are numbered per run, so "
                        f"this extract's tokens will not line up with a "
                        "folder run's — re-run the whole folder before the "
                        "review hand-off")

    raw_texts = {}
    pages_by_name = {}
    src_by_name = {}
    regions_by_name = {}
    ocr_files = set()
    for pdf in pdfs:
        src, field_values, sig_fields = pdf, (), ()
        if args.flatten:
            try:
                flat = flatten_pdf(pdf)
            except Exception as exc:  # any PyMuPDF failure: keep the old path
                flat = None
                warnings.append(f"FLATTEN FAILED: {pdf.name} "
                                f"({type(exc).__name__}) — processed as is")
            if flat:
                src, field_values, sig_fields = flat
                warnings.append(f"FLATTENED: {pdf.name} had form fields/"
                                "annotations; their contents were merged into "
                                "the page and redacted like page text")
        try:
            unrotated = unrotate_pdf(src, sig_fields)
        except Exception as exc:  # any PyMuPDF failure: keep the old path
            unrotated = None
            warnings.append(f"UNROTATE FAILED: {pdf.name} "
                            f"({type(exc).__name__}) — processed as is")
        if unrotated:
            src, count, sig_fields = unrotated
            warnings.append(f"ROTATION REMOVED: {pdf.name} had {count} rotated "
                            "page(s); the redacted PDF stores them unrotated "
                            "and looks the same")
        esigned = args.signatures and is_esigned(src, sig_fields)
        if esigned and args.certificate:
            cut = drop_certificate_pages(src)
            if cut:
                src, first, last = cut
                warnings.append(f"CERTIFICATE DROPPED: {pdf.name} — page"
                                + (f" {first}" if first == last
                                   else f"s {first}-{last}")
                                + " (e-signature certificate) left out of the "
                                "output")
        pages = extract_pdf_pages(src)
        text = pages_to_text(pages)
        if page_text_chars(pages) < MIN_TEXT_CHARS:
            if args.ocr:
                pages = ocr_pdf_pages(src)
                text = pages_to_text(pages)
                if page_text_chars(pages) >= MIN_TEXT_CHARS:
                    ocr_files.add(pdf.name)
                    warnings.append(f"OCR APPLIED: {pdf.name} had no text layer; "
                                    "its extract is OCR-derived — verify amounts "
                                    "against the original")
            if page_text_chars(pages) < MIN_TEXT_CHARS:
                warnings.append(f"NEEDS OCR / MANUAL HANDLING: {pdf.name} has no "
                                "extractable text (scanned image?) — no extract "
                                "will be written for it"
                                + ("" if args.ocr else "; re-run without --no-ocr"))
                continue
        missing = unflattened_count(field_values, text)
        if missing:
            warnings.append(f"FLATTEN INCOMPLETE: {pdf.name} — {missing} field "
                            "value(s) not in the extract; check the original")
        raw_texts[pdf.name] = text
        pages_by_name[pdf.name] = pages
        src_by_name[pdf.name] = src
        if args.signatures:
            regions, no_id = find_signature_regions(pages, src, sig_fields,
                                                    esigned)
            regions_by_name[pdf.name] = regions
            for page_no in no_id:
                warnings.append(f"SIGNATURE: {pdf.name} page {page_no} — stamp "
                                "without an ID line, default area boxed; check "
                                "the redacted PDF")

    # Redaction list: create if missing, append new candidates, reload so the
    # additions take effect in this same run (preview included).
    added = suggest_entries(raw_texts, entries,
                            list_seen_values(list_path) | list_seen_values(master_path))
    created = append_list_entries(list_path, added, folder.name or str(folder)) \
        if (added or not list_path.is_file()) else False
    if added or created:
        entries = load_lists(master_path, list_path)
    folder_entries = load_list(list_path)
    list_desc = (f"{'created' if created else 'found'} {list_path} "
                 f"({len(folder_entries)} entries)")
    if not entries:
        warnings.append("no redaction list entries loaded — names, employers and "
                        "addresses will NOT be redacted (patterns only)")

    def redact_all(sweep, ssns=()):
        tokens = TokenMap(ssns)
        redacted, findings_by_file, spans_by_name, sigs_by_name = {}, {}, {}, {}
        for name, text in raw_texts.items():
            findings, spans = defaultdict(int), []
            regions = regions_by_name.get(name, {})
            presets, with_text = signature_presets(pages_by_name[name], regions)
            # a stamp without a signer ID gets a token of its own
            keys = {(pi, n): key or f"{name} page {pi + 1} #{n + 1}"
                    for pi, items in regions.items()
                    for n, (_rect, key) in enumerate(items)}
            sigs = defaultdict(list)
            for (pi, n), key in sorted(keys.items()):
                tok = tokens.token("SIGNATURE", key)
                sigs[pi].append((regions[pi][n][0], tok))
                if (pi, n) not in with_text:  # image-only: nothing in the text
                    findings[("[SIGNATURE]",
                              f"(signature block, page {pi + 1})", tok)] += 1
            presets = {li: [(a, b, keys[r]) for a, b, r in items]
                       for li, items in presets.items()}
            redacted[name] = redact_text(text, entries, tokens, findings,
                                         ocr=name in ocr_files, spans=spans,
                                         sweep=sweep, presets=presets)
            findings_by_file[name] = findings
            spans_by_name[name] = spans
            sigs_by_name[name] = sigs
        return redacted, findings_by_file, spans_by_name, sigs_by_name

    # Pass 1 finds values by pattern; pass 2 also redacts each of those
    # values literally wherever else it appears in the run (any line, any
    # file — e.g. a city/state/zip merged into an OCR row), like list entries.
    listed_ssns = {d for c, v, _var, _rx in entries if c == "ssn"
                   for d in [re.sub(r"\D", "", v)] if len(d) == 9}
    redacted, findings_by_file, spans_by_name, sigs_by_name = redact_all(
        (), sorted(listed_ssns))
    sweep_values = sorted({(reason[len("[PATTERN:"):-1].split(":")[0], orig)
                           for f in findings_by_file.values()
                           for reason, orig, _tok in f
                           if reason.startswith("[PATTERN:")})
    sweep = [(kind, val, _literal_rx(val)) for kind, val in sweep_values]
    # An SSN's last four digits also appear as a bare tail ("-6789"); too
    # loose for a pattern rule, so only the tails of SSNs seen in this run
    # or listed with ssn:.
    ssn_digits = listed_ssns | {re.sub(r"\D", "", _shadow(val))
                                for kind, val in sweep_values if kind == "SSN"}
    sweep += [("SSN", f"-{last4}", _ssn_tail_rx(last4))
              for last4 in sorted({d[-4:] for d in ssn_digits if len(d) in (4, 9)})]
    if sweep:
        redacted, findings_by_file, spans_by_name, sigs_by_name = redact_all(
            sweep, sorted(d for d in ssn_digits if len(d) == 9))

    used = {orig for f in findings_by_file.values()
            for (reason, orig, _tok) in f if reason.startswith("[LIST")}
    # Folder entries only: a master entry missing from one folder is normal.
    unused = sorted({(c, v) for c, v, _var, _rx in folder_entries if v not in used})

    report = format_report(findings_by_file, warnings, list_desc, unused, added,
                           master_desc)
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
        try:
            out.write_text(header + text)
        except OSError:
            sys.exit(CANNOT_WRITE.format(out=out))
        written.append(out)

    # Self-check: audit every output with the same rules; any FAIL means
    # redaction failed — delete the output and fail loudly. WARNs are surfaced
    # for the user to eyeball locally.
    failed = []
    warn_lines = []
    for out in written:
        text = out.read_text()
        fails, warns = audit_text(text, entries, ocr=_is_ocr_extract(text),
                                  sweep=sweep, signatures=args.signatures)
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
            try:
                reason = write_redacted_pdf(src_by_name[name], dst, rects,
                                            ocr_layer, sigs_by_name[name])
            except Exception as exc:  # PyMuPDF raises its own error types
                if not _is_write_error(exc):
                    raise
                sys.exit(CANNOT_WRITE.format(out=dst))
            if reason:
                print(f"WARNING: PDF SKIPPED: {name} {reason} — {PDF_SKIP_HINT}")
                continue
            fails = verify_redacted_pdf(dst, entries, ocr=name in ocr_files,
                                        sweep=sweep, sig_rects=sigs_by_name[name],
                                        signatures=args.signatures)
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
