# pdf-redactor

Redact personal data out of PDFs — tax forms, bank and brokerage statements,
letters — before handing them to an AI assistant, an accountant's portal, or
anyone else who does not need to know who you are.

Each source PDF becomes two things:

- a sanitized **`.txt` extract** in which every identity is replaced by a
  stable token (`[SSN-1]`, `[NAME-1]`, `[EMPLOYER-2]`, `[ACCT-...5678]`), so
  amounts, dates, box and line numbers survive and cross-document checks
  still work; and
- a **true-redacted `.redacted.pdf`** in which the same matches are removed
  from the page (text and pixels), painted over with a labeled black box, and
  the metadata is scrubbed.

Nothing is written until you have seen and approved a preview of every planned
redaction, with a reason for each. Every output is re-scanned with the same
rules before it is kept, and a separate `--audit` mode gives a second opinion
on finished output without ever printing the matched text.

It was built for a personal tax-review workflow where an AI assistant is only
ever allowed to read the redacted output. The patterns lean towards US
financial documents (SSN, EIN, routing numbers, form vocabulary), but nothing
about the flow is tax-specific.

## Install

Python 3.10+.

```bash
python3 -m venv --prompt pdf-redactor venv
venv/bin/pip install -r requirements.txt   # runtime + test dependencies
venv/bin/pytest                            # run before every commit
```

To get a `pdf-redact` command instead of `python redact.py` (for example
inside another project's virtualenv), install the package:

```bash
pip install /path/to/pdf-redactor          # or: pip install -e /path/to/pdf-redactor
pdf-redact --help
```

The redacted-PDF step uses PyMuPDF, which is AGPL-licensed. That is fine for
personal and internal use; check the terms if you redistribute a derived tool.
Pass `--no-pdf` if you only need the text extracts.

## Usage

```bash
python redact.py <folder|file.pdf> [--out DIR] [--preview] [--yes] [--no-ocr] [--no-pdf] [--report PATH] [--list PATH]
python redact.py <out-dir> --audit          # leak-audit finished extracts + PDFs
```

`<folder>` holds the raw PDFs. `--out DIR` is where the output goes (default
`<folder>/redacted`); it may not be the raw folder itself. The positional
argument can also be a single `.pdf` (or, with `--audit`, a single `.txt`):
the redaction list is looked up from that file's folder and the default
output is `<parent>/redacted`. Tokens are numbered per run, so re-run the
whole folder before handing a set off.

### Recommended workflow

Run these in your own terminal, not inside an AI-assistant session: the
preview and the list additions print the raw values on purpose — that is your
local audit of the plan — and those values must never enter a conversation
log.

1. **Collect.** Put the PDFs in a private folder outside any repository,
   e.g. `~/private/2025/`. Keep it off synced or shared drives.
2. **Redaction list.** Nothing to do up front: the first run creates
   `redaction_list.txt` next to the PDFs if none exists, and every run
   appends candidate entries it finds on name-labeled lines (banks, brokers,
   employers, people) and prints them. Review the additions; comment out any
   that are wrong and they stay out for good. To share one list across
   folders, move it up a level or two — the script looks in the folder, then
   one and two levels up (`--list PATH` overrides). The list is sensitive:
   keep it with the raw documents.
3. **Preview.** Check that every planned redaction and its reason look right
   and that no amounts are being taken:

   ```bash
   python redact.py ~/private/2025 --preview
   ```

   Watch the summary for `never matched` notes (typo in a list entry?) and
   `OCR APPLIED` notes (scanned documents were OCR'd; verify their amounts).
4. **Redact.** Same command without `--preview`, plus `--out`; confirm at the
   prompt:

   ```bash
   python redact.py ~/private/2025 --out ~/work/2025/redacted
   ```

   The self-check and leak audit run automatically; a failing output is
   deleted, never kept. Heed any `AUDIT WARNINGS` by checking those lines
   locally and extending the list.
5. **Spot-check.** Open two or three `.redacted.pdf` files next to the
   originals: black boxes labeled with tokens over identities, amounts
   intact; the `.txt` extracts carry the same tokens.
6. **Hand off.** Whoever (or whatever) receives the output can run the
   independent audit, whose output is categories and line numbers only:

   ```bash
   python redact.py ~/work/2025/redacted --audit
   ```

   If a residual leak is suspected, the report names file + line + category;
   you check the line locally, extend the list, and re-run from step 3.

Known limitation: an unlisted name on an *unlabeled* line (e.g. a bare payer
row in a table) is invisible to both the patterns and the audit heuristic —
the list is the only defense, so add such names by hand and lean on the
spot-check.

## What it does

- **Two-stage flow.** Prints a preview of every value it plans to strip, with
  a reason tag per value — `[LIST:<category>]`, `[PATTERN:<TYPE>]` or
  `[SWEEP:…]` — then prompts `Proceed with redaction? [y/N]` (default No).
  `--preview` prints the report and exits without prompting or writing;
  `--yes` skips the prompt for scripted runs; `--report PATH` also writes the
  report to a file.
- **Pattern rules.** SSNs (separated, spaced, and bare 9-digit on
  SSN/TIN/EIN-labeled lines), EINs, email addresses, phone numbers, account
  numbers (digit runs of 8+, last 4 preserved), dates of birth (on
  DOB-labeled lines only, so transaction dates survive), driver's license /
  state ID numbers (on license-labeled lines), bank routing numbers (on
  routing/ABA-labeled lines), and addresses: street lines with optional
  APT/UNIT/STE suffixes, PO Boxes, and standalone city/state/ZIP lines
  (whole-line match, real state codes only, never on lines carrying form
  vocabulary such as SCHEDULE or LINE). Dollar amounts, other dates, and
  box/line numbers are untouched.
- **Sweep.** Every value a pattern found is then also redacted literally
  wherever else it appears in the run — any line, any file — like a list
  entry.
- **Redaction list.** Names, employers, addresses, and account numbers are
  not reliably pattern-detectable, so they come from a user-maintained
  `redaction_list.txt`: one entry per line, optional `name:` / `addr:` /
  `acct:` / `employer:` prefix (default `name`), `#` comments, matched
  case-insensitively with collapsed whitespace, longest entry first. A
  `name:` entry like `JOHN A SAMPLE` also matches `JOHN SAMPLE`,
  `SAMPLE, JOHN A` and `SAMPLE, JOHN`, all mapping to the same `[NAME-n]`
  token. Every run scans name-labeled lines for candidate entries and appends
  new ones under a dated `# auto-added` header; a commented-out entry is
  never redacted and never re-added. Entries that never matched are flagged
  in the preview summary.
- **Stable tokens.** Replacements, not deletions. One value→token map per
  run, so the same SSN on two documents gets the same token. SSN/EIN/account
  values are digit-normalized so formatting variants map to one token; two
  accounts sharing a last-4 get distinct tokens (`[ACCT-2-...5678]`).
- **Scanned documents (OCR by default).** PDFs with no text layer are OCR'd
  locally with RapidOCR (pip-only, no system packages). OCR output is
  second-class: the extract is stamped `OCR-DERIVED — verify amounts against
  the original`, matching becomes whitespace-flexible (OCR often drops spaces
  between words), and a digit-lookalike shadow pass (l/I→1, O→0 next to
  digits) catches garbled values like `l23-45-6789`. Short street suffixes
  (ST, CT, DR, …) must follow a real space on OCR text so word tails like
  `direCT` are not taken as suffixes, and city/state/ZIP is recognized as the
  prefix or suffix of a merged row. `--no-ocr` skips scanned PDFs instead;
  they then get a loud NEEDS-OCR warning and no extract.
- **Redacted PDF** (`<stem>.redacted.pdf`, `--no-pdf` to skip). The boxes
  come from the very characters pdfplumber extracted, not from a second text
  search; the underlying text and image pixels are removed; a black box
  labeled with the token is painted; metadata, attachments, links and hidden
  text are scrubbed. The PDF keeps its text layer, so it stays readable by
  people and programs; a scanned PDF gets its redacted OCR text written back
  as an invisible layer so it stays searchable. Every PDF is then re-extracted
  and audited with the same rules; a residual match deletes the PDF and fails
  the run. PDFs with fillable form fields, annotations, rotated or cropped
  pages are skipped with a `PDF SKIPPED` warning — flatten them (print to
  PDF) first; field values are invisible to text extraction too, so the
  `.txt` may be missing them.
- **Leak audit (`--audit`).** A second-opinion scan of finished output that
  reports category + file + line number only — never the matched text — so
  its output is safe to read and share. FAIL (exit 1) if any redaction rule
  still matches; WARN for name-labeled lines that still carry an all-caps
  phrase (a likely unlisted name — patterns cannot detect names, only the
  list can). The same checks run automatically after every full redaction; a
  FAIL deletes the output.
- **Safety nets.** Source PDFs are opened read-only and never modified;
  output goes only to `--out`. A PDF that yields no text even after OCR gets
  a loud `NEEDS OCR / MANUAL HANDLING` warning instead of a silent empty
  extract. An output that survives to disk is clean against the ruleset.

## Repository layout

```
redact.py            The tool (also installed as the `pdf-redact` command)
make_testdata.py     Generates the FAKE document set in testdata/
testdata/            Fabricated PDFs + a fake redaction_list.txt (committed; no real data)
tests/               pytest suite: pattern units, list handling, OCR, redacted PDFs,
                     audit, end-to-end runs, gitignore guardrails
CLAUDE.md            Standing privacy rules for AI-assisted development in this repo
```

The fake set is a W-2, 1099-INT, 1099-DIV, 1099-B, bank statement, an
image-only scanned letter, and a multi-page tax return that repeats the same
fake identities (SSN `123-45-6789`, `JOHN A SAMPLE`, `ACME WIDGETS INC`,
…). Regenerate it with:

```bash
venv/bin/python make_testdata.py [--filing-status {mfj,single}] [--out testdata]
```

`.gitignore` ignores every `.pdf`, every `redacted/` folder and every
`redaction_list.txt` outside `testdata/`, and a test asserts that stays true,
so a real document cannot be committed by accident.

## Privacy rules for development

Real documents never enter this repository and are never read to debug a
miss; use `testdata/` or a made-up reproduction. Nothing an SSN, account
number or address could appear in — logs, error messages, test output —
may carry one. See `CLAUDE.md`.
