"""Tests for redact.py — patterns, list matching, and end-to-end runs
against the fake testdata set. The fake SSN must never survive redaction."""

import shutil
import subprocess
import sys
from collections import defaultdict
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
TESTDATA = REPO / "testdata"
sys.path.insert(0, str(REPO))

import redact  # noqa: E402


def run_text(text, list_entries=()):
    tokens = redact.TokenMap()
    findings = defaultdict(int)
    out = redact.redact_text(text, list(list_entries), tokens, findings)
    return out, findings


# ------------------------------------------------------------- pattern units
def test_ssn_separated():
    out, f = run_text("EMPLOYEE SSN: 123-45-6789")
    assert "123-45-6789" not in out
    assert "[SSN-1]" in out


def test_ssn_spaced_and_stable_across_formats():
    out, _ = run_text("SSN: 123-45-6789\nALSO SSN 123 45 6789")
    assert out.count("[SSN-1]") == 2  # same SSN, different formatting


def test_ssn_bare_digits_only_in_labeled_context():
    out, _ = run_text("RECIPIENT TIN: 123456789")
    assert "[SSN-1]" in out
    # without context the 9-digit run is still caught, as an account number
    out2, _ = run_text("REFERENCE: 123456789")
    assert "123456789" not in out2
    assert "[ACCT-...6789]" in out2


def test_ein():
    out, _ = run_text("EMPLOYER EIN: 12-3456789")
    assert "12-3456789" not in out
    assert "[EIN-1]" in out


def test_email_and_phone():
    out, _ = run_text("contact john.sample@example.com or (555) 123-4567")
    assert "john.sample@example.com" not in out
    assert "123-4567" not in out
    assert "[EMAIL-1]" in out and "[PHONE-1]" in out


def test_account_run_preserves_last4():
    out, _ = run_text("ACCOUNT NUMBER: 00012345678")
    assert "00012345678" not in out
    assert "[ACCT-...5678]" in out


def test_distinct_accounts_same_last4_get_distinct_tokens():
    out, _ = run_text("A: 11115678999\nB: 22225678999")
    assert "[ACCT-...8999]" in out and "[ACCT-2-...8999]" in out


def test_amounts_dates_and_lines_untouched():
    text = ("BOX 1 WAGES, TIPS, OTHER COMPENSATION: 120,450.00\n"
            "BOX 1b DATE ACQUIRED: 03/15/2025\n"
            "LINE 16 TAX: 11,885.00")
    out, findings = run_text(text)
    assert out == text
    assert not findings


def test_address_heuristic():
    out, _ = run_text("HOME ADDRESS: 1234 EXAMPLE STREET, SAMPLETOWN, CA 90000")
    assert "EXAMPLE STREET" not in out
    assert "90000" not in out
    assert "[ADDR-1]" in out


def test_dob_only_in_birth_context():
    out, _ = run_text("DATE OF BIRTH: 03/15/1980")
    assert "03/15/1980" not in out and "[DOB-1]" in out
    # same date shape outside a birth context must survive (1099-B dates)
    out2, _ = run_text("BOX 1b DATE ACQUIRED: 03/15/1980")
    assert "03/15/1980" in out2


def test_drivers_license_id():
    out, _ = run_text("DRIVER LICENSE NO: A1234567")
    assert "A1234567" not in out and "[ID-1]" in out
    out2, _ = run_text("REFERENCE CODE: A1234567")  # no license context
    assert "A1234567" in out2


def test_routing_context_beats_generic_account():
    out, _ = run_text("ROUTING NUMBER (ABA): 121099999")
    assert "121099999" not in out and "[ROUTING-1]" in out
    out2, _ = run_text("REFERENCE: 121099999")
    assert "[ACCT-...9999]" in out2


def test_po_box():
    out, _ = run_text("MAILING ADDRESS: P.O. BOX 4321")
    assert "BOX 4321" not in out and "[ADDR-1]" in out


def test_ocr_short_suffix_needs_space():
    # ocr_rx relaxes \s+ to \s*; a 2-letter street suffix must not match the
    # tail of an ordinary word ("direCT", "intereST") on OCR-derived text
    ocr = redact.ocr_rx(redact.ADDR)
    for s in ("7Payer made direct", "0o0ormore of  dividendsorinterest",
              "7 Payer made direct sales"):
        assert not ocr.search(s), s
    # real addresses still match, spaced or OCR-glued long form
    for s in ("123 MAIN ST", "123 MAIN ST APT 4", "789 NORTH ELM DR",
              "123MAINSTREET", "456 OAK AVE, SAMPLETOWN CA 90000"):
        assert ocr.search(s), s


def test_city_line_requires_real_state():
    out, _ = run_text("SAMPLETOWN, CA 90000")
    assert out == "[ADDR-1]"
    out, _ = run_text("SAMPLETOWN, XX 90000")  # not a state code
    assert "90000" in out


def test_city_edge_ocr_rule():
    def ocr(text):
        return redact.redact_text(text, [], redact.TokenMap(), defaultdict(int),
                                  ocr=True)
    merged = "IMPORTANT TAX RETURN DOCUMENT ENCLOSED  SAMPLETOWN, CA 90000"
    for s in (merged,
              "IMPORTANT TAX RETURN DOCUMENT ENCLOSED SAMPLETOWN, CA 90000",
              "SAMPLETOWN, CA 90000  ACCOUNT SUMMARY",
              "SAMPLETOWN,CA90000  ACCOUNT SUMMARY",
              "SAMPLETOWN, Ca 90000",
              "SAN LUIS OBISPO, CA 93401"):
        out = ocr(s)
        assert "90000" not in out and "93401" not in out, (s, out)
        assert "[ADDR-1]" in out
    assert ocr(merged).startswith("IMPORTANT TAX RETURN DOCUMENT ENCLOSED")
    for s in ("TOTAL DIVIDENDS 12345", "PAY BY 10000", "BOX 1 WAGES 120450",
              "SEE SCHEDULE CA 12345", "PAGE 1 OF 3  SAMPLETOWN, CA 90000"):
        assert ocr(s) == s, s  # the last: form vocabulary on the line wins
    # text-layer extracts do not get the edge rule; whole-line rule still does
    plain, _ = run_text(merged)
    assert plain == merged
    assert run_text("SAMPLETOWN, CA 90000")[0] == "[ADDR-1]"


def test_street_with_unit_suffix():
    out, _ = run_text("STREET ADDRESS: 1234 EXAMPLE STREET APT 12")
    assert "EXAMPLE STREET" not in out and "APT 12" not in out
    assert "[ADDR-1]" in out


def test_standalone_city_state_zip_line():
    out, _ = run_text("SAMPLETOWN, CA 90000")
    assert out == "[ADDR-1]"
    # form vocabulary exempts return-page lines from the whole-line heuristic
    keep = "SCHEDULE CA 90000"
    out2, _ = run_text(keep)
    assert out2 == keep


def test_ocr_shadow_catches_garbled_ssn():
    tokens = redact.TokenMap()
    out = redact.redact_text("SSN: l23-45-6789", [], tokens, defaultdict(int),
                             ocr=True)
    assert "l23" not in out and "[SSN-1]" in out
    # without the shadow pass the garbled value would leak — pins why it exists
    out2 = redact.redact_text("SSN: l23-45-6789", [], redact.TokenMap(),
                              defaultdict(int))
    assert "l23-45-6789" in out2


def test_ocr_spaceless_text_still_matches_list_and_context():
    entries = redact.load_list(TESTDATA / "redaction_list.txt")
    tokens = redact.TokenMap()
    text = "CUSTOMER:JOHNASAMPLE\nDATEOFBIRTH:03/15/1980\nEXAMPLECREDITUNION"
    out = redact.redact_text(text, entries, tokens, defaultdict(int), ocr=True)
    assert "JOHNASAMPLE" not in out and "[NAME-1]" in out
    assert "03/15/1980" not in out and "[DOB-1]" in out
    assert "EXAMPLECREDITUNION" not in out
    # non-OCR text keeps strict matching
    out2 = redact.redact_text("CUSTOMER:JOHNASAMPLE", entries,
                              redact.TokenMap(), defaultdict(int))
    assert "JOHNASAMPLE" in out2


def test_name_variants_share_one_token():
    entries = redact.load_list(TESTDATA / "redaction_list.txt")
    out, _ = run_text("prepared for JOHN SAMPLE and SAMPLE, JOHN A", entries)
    assert "SAMPLE" not in out
    assert out.count("[NAME-1]") == 2  # both variants -> the canonical's token


def test_list_matching_case_and_whitespace_insensitive():
    entries = redact.load_list(TESTDATA / "redaction_list.txt")
    out, f = run_text("employee: John  A  Sample of ACME WIDGETS INC", entries)
    assert "Sample" not in out and "ACME" not in out
    assert "[NAME-1]" in out and "[EMPLOYER-1]" in out
    assert any(reason == "[LIST:name]" for reason, _, _ in f)


def test_load_list_categories_and_comments(tmp_path):
    lst = tmp_path / "redaction_list.txt"
    lst.write_text("# comment\n\nPLAIN PERSON\nacct: 99887766\naddr: 9 OAK ST\n")
    entries = redact.load_list(lst)
    assert {(c, v) for c, v, _var, _rx in entries} == {
        ("name", "PLAIN PERSON"), ("acct", "99887766"), ("addr", "9 OAK ST")}


# ------------------------------------------------------------------- e2e runs
SCRIPT = REPO / "redact.py"

SENSITIVE = [
    "123-45-6789", "987-65-4321", "123456789", "12-3456789",
    "00012345678", "98765432",
    "JOHN A SAMPLE", "JANE B SAMPLE", "ACME WIDGETS INC",
    "FIRST EXAMPLE BANK", "SECOND NATIONAL BANK", "EXAMPLE BROKERAGE LLC",
    "EXAMPLE CREDIT UNION",
    "1234 EXAMPLE STREET", "SAMPLETOWN",
    "03/15/1980", "A1234567", "121099999", "BOX 4321",
]


@pytest.fixture()
def workdir(tmp_path):
    for pdf in TESTDATA.glob("*.pdf"):
        shutil.copy(pdf, tmp_path)
    shutil.copy(TESTDATA / "redaction_list.txt", tmp_path)
    return tmp_path


def run_script(folder, *flags, stdin=subprocess.DEVNULL):
    return subprocess.run(
        [sys.executable, str(SCRIPT), str(folder), *flags],
        capture_output=True, text=True, stdin=stdin,
    )


def test_e2e_full_redaction(workdir):
    proc = run_script(workdir, "--yes", "--no-ocr")
    assert proc.returncode == 0, proc.stderr
    assert "self-check passed" in proc.stdout
    # scanned-fake.pdf has no text layer; with --no-ocr it is skipped loudly
    assert "NEEDS OCR" in proc.stdout
    assert "re-run without --no-ocr" in proc.stdout
    outputs = sorted((workdir / "redacted").glob("*.txt"))
    assert len(outputs) == 6
    all_text = "\n".join(p.read_text() for p in outputs)
    for value in SENSITIVE:
        assert value not in all_text, f"sensitive value leaked: {value}"
    # amounts and non-DOB dates survive
    assert "120,450.00" in (workdir / "redacted" / "w2-fake.txt").read_text()
    assert "03/15/2025" in (workdir / "redacted" / "1099b-fake.txt").read_text()
    # stable cross-document tokens: same SSN token on W-2 and 1040
    w2 = (workdir / "redacted" / "w2-fake.txt").read_text()
    ret = (workdir / "redacted" / "return-fake.txt").read_text()
    ssn_tokens = {t for t in ("[SSN-1]", "[SSN-2]") if t in w2}
    assert ssn_tokens and all(t in ret for t in ssn_tokens)
    assert "[ACCT-...5678]" in (workdir / "redacted" / "1099int-fake.txt").read_text()
    # new-pattern tokens present in the bank statement extract
    stmt = (workdir / "redacted" / "bankstmt-fake.txt").read_text()
    for tok in ("[DOB-", "[ID-", "[ROUTING-", "[ADDR-"):
        assert tok in stmt, f"missing {tok} token in bankstmt extract"
    # source PDFs untouched
    assert sorted(p.name for p in workdir.glob("*.pdf")) == [
        "1099b-fake.pdf", "1099div-fake.pdf", "1099int-fake.pdf",
        "bankstmt-fake.pdf", "return-fake.pdf", "scanned-fake.pdf", "w2-fake.pdf"]


def test_e2e_out_flag_writes_outside_raw_folder(workdir, tmp_path):
    # Raw docs live outside the repo; --out lands the extracts elsewhere
    # (nested dirs created) and nothing is written next to the PDFs.
    out = tmp_path / "repo" / "workspace" / "2024" / "redacted"
    proc = run_script(workdir, "--yes", "--out", str(out), "--no-ocr")
    assert proc.returncode == 0, proc.stderr
    assert "self-check passed" in proc.stdout
    assert len(list(out.glob("*.txt"))) == 6  # scanned-fake skipped via --no-ocr
    assert not (workdir / "redacted").exists()
    all_text = "\n".join(p.read_text() for p in out.glob("*.txt"))
    for value in SENSITIVE:
        assert value not in all_text, f"sensitive value leaked: {value}"


def test_e2e_out_flag_rejects_raw_folder(workdir):
    proc = run_script(workdir, "--yes", "--out", str(workdir))
    assert proc.returncode != 0
    assert "must not be the raw folder" in proc.stderr
    assert [t.name for t in workdir.glob("*.txt")] == ["redaction_list.txt"]


def test_e2e_single_pdf(workdir, tmp_path):
    out = tmp_path / "out"
    proc = run_script(workdir / "w2-fake.pdf", "--yes", "--out", str(out))
    assert proc.returncode == 0, proc.stderr
    assert "SINGLE-FILE RUN" in proc.stdout
    assert [t.name for t in out.glob("*.txt")] == ["w2-fake.txt"]
    text = (out / "w2-fake.txt").read_text()
    for value in SENSITIVE:
        assert value not in text, f"sensitive value leaked: {value}"
    assert "[EMPLOYER-1]" in text  # list found via the file's parent folder
    assert not (workdir / "redacted").exists()


def test_e2e_single_pdf_default_out_is_parent_redacted(workdir):
    proc = run_script(workdir / "w2-fake.pdf", "--yes")
    assert proc.returncode == 0, proc.stderr
    assert [t.name for t in (workdir / "redacted").glob("*.txt")] == ["w2-fake.txt"]


def test_e2e_single_txt_audit(workdir):
    assert run_script(workdir, "--yes").returncode == 0
    proc = run_script(workdir / "redacted" / "w2-fake.txt", "--audit")
    assert proc.returncode == 0, proc.stderr
    assert "LEAK AUDIT of 1 extract(s)" in proc.stdout


def test_e2e_single_file_wrong_type(workdir):
    proc = run_script(workdir / "redaction_list.txt", "--preview")
    assert proc.returncode != 0
    assert "is not a .pdf file" in proc.stderr
    proc = run_script(workdir / "w2-fake.pdf", "--audit")
    assert proc.returncode != 0
    assert "is not a .txt or .redacted.pdf file" in proc.stderr
    proc = run_script(workdir / "missing.pdf", "--preview")
    assert proc.returncode != 0
    assert "is not a directory or file" in proc.stderr


def test_e2e_preview_writes_nothing(workdir):
    proc = run_script(workdir, "--preview")
    assert proc.returncode == 0, proc.stderr
    assert not (workdir / "redacted").exists()
    # preview report names the values it plans to strip, with reasons
    assert "123-45-6789" in proc.stdout
    assert "[PATTERN:SSN]" in proc.stdout
    assert "[LIST:employer]" in proc.stdout


def test_e2e_prompt_defaults_to_no(workdir):
    proc = run_script(workdir)  # stdin closed -> EOF -> default No
    assert proc.returncode == 0, proc.stderr
    assert "Aborted" in proc.stdout
    assert not (workdir / "redacted").exists()


def test_e2e_report_flag(workdir, tmp_path):
    report = tmp_path / "out" / "plan.txt"
    report.parent.mkdir()
    proc = run_script(workdir, "--preview", "--report", str(report))
    assert proc.returncode == 0, proc.stderr
    assert "SUMMARY" in report.read_text()


def test_e2e_missing_list_is_created_and_used(workdir):
    lst = workdir / "redaction_list.txt"
    lst.unlink()
    proc = run_script(workdir, "--preview")
    assert proc.returncode == 0, proc.stderr
    assert f"created {lst.resolve()}" in proc.stdout
    assert "no redaction list" not in proc.stdout
    text = lst.read_text()
    assert "SENSITIVE" in text  # template header
    assert "# auto-added" in text
    assert "employer: FIRST EXAMPLE BANK" in text
    assert "name: JOHN A SAMPLE" in text
    assert "employer: JOHN A SAMPLE" not in text  # TAXPAYER != PAYER
    # additions are announced and take effect in the same run
    assert "employer: FIRST EXAMPLE BANK" in proc.stdout
    assert "[LIST:employer]" in proc.stdout
    assert not (workdir / "redacted").exists()  # preview still writes no extracts


def test_e2e_unused_list_entry_noted(workdir):
    with (workdir / "redaction_list.txt").open("a") as f:
        f.write("name: NEVER PRESENT PERSON\n")
    proc = run_script(workdir, "--preview")
    assert proc.returncode == 0, proc.stderr
    assert "never matched" in proc.stdout
    assert "NEVER PRESENT PERSON" in proc.stdout


def test_e2e_ocr(workdir):
    pytest.importorskip("rapidocr_onnxruntime")
    proc = run_script(workdir, "--yes")  # OCR is on by default
    assert proc.returncode == 0, proc.stderr
    assert "OCR APPLIED" in proc.stdout
    assert "NEEDS OCR" not in proc.stdout
    scanned = workdir / "redacted" / "scanned-fake.txt"
    assert scanned.exists()
    text = scanned.read_text()
    assert "OCR-DERIVED" in text.splitlines()[0]
    joined = text.replace(" ", "")  # OCR may drop or keep spaces
    for value in ("123-45-6789", "123456789", "00012345678",
                  "JOHNASAMPLE", "03/15/1980"):
        assert value not in joined, f"sensitive value leaked via OCR: {value}"
    # standalone audit agrees the whole output set is clean
    audit = run_script(workdir / "redacted", "--audit")
    assert audit.returncode == 0, audit.stdout + audit.stderr
    assert "0 FAIL" in audit.stdout


# ------------------------------------------------------------- redacted PDF
def test_redact_text_spans_match_output():
    line = "EMPLOYEE NAME: JOHN A SAMPLE SSN: 123-45-6789 ACCT 001234567890"
    entries = redact.load_list(TESTDATA / "redaction_list.txt")
    spans = []
    out = redact.redact_text(line, entries, redact.TokenMap(), defaultdict(int),
                             spans=spans)
    plain = redact.redact_text(line, entries, redact.TokenMap(), defaultdict(int))
    assert out == plain  # span tracking never changes the text output
    got = {(line[a:b], tok) for _li, a, b, tok in spans}
    assert got == {("JOHN A SAMPLE", "[NAME-1]"), ("123-45-6789", "[SSN-1]"),
                   ("001234567890", "[ACCT-...7890]")}
    # OCR shadow pass records spans too
    spans = []
    redact.redact_text("SSN: l23-45-6789", [], redact.TokenMap(),
                       defaultdict(int), ocr=True, spans=spans)
    assert [(a, b) for _l, a, b, _t in spans] == [(5, 16)]


def test_extract_pages_matches_extract_text():
    import pdfplumber
    for pdf_path in sorted(TESTDATA.glob("*.pdf")):
        pages = redact.extract_pdf_pages(pdf_path)
        with pdfplumber.open(pdf_path) as pdf:
            parts, multi = [], len(pdf.pages) > 1
            for i, page in enumerate(pdf.pages, 1):
                if multi:
                    parts.append(f"===== PAGE {i} =====")
                parts.append(page.extract_text() or "")
        assert redact.pages_to_text(pages) == "\n".join(parts), pdf_path.name
        for lines in pages:
            for text, boxes in lines:
                assert len(text) == len(boxes)
                for ch, box in zip(text, boxes):
                    assert box is not None or ch.isspace(), (pdf_path.name, ch)


def test_pdf_verification_catches_missing_rects(workdir, tmp_path):
    entries = redact.load_list(TESTDATA / "redaction_list.txt")
    src = workdir / "w2-fake.pdf"
    bad = tmp_path / "bad.redacted.pdf"
    assert redact.write_redacted_pdf(src, bad, {}) is None  # nothing boxed
    assert redact.verify_redacted_pdf(bad, entries)  # -> FAILs, not silence
    # the real thing: spans -> rects -> clean
    pages = redact.extract_pdf_pages(src)
    spans = []
    redact.redact_text(redact.pages_to_text(pages), entries, redact.TokenMap(),
                       defaultdict(int), spans=spans)
    good = tmp_path / "good.redacted.pdf"
    assert redact.write_redacted_pdf(src, good, redact.redaction_rects(pages, spans)) is None
    assert redact.verify_redacted_pdf(good, entries) == []


def test_e2e_pdf_written_and_clean(workdir):
    pytest.importorskip("rapidocr_onnxruntime")
    proc = run_script(workdir, "--yes")
    assert proc.returncode == 0, proc.stderr
    out = workdir / "redacted"
    pdfs = sorted(out.glob("*.redacted.pdf"))
    assert [p.name for p in pdfs] == [
        t.name.replace(".txt", ".redacted.pdf") for t in sorted(out.glob("*.txt"))]
    assert len(pdfs) == 7  # incl. the OCR'd scan
    import pymupdf
    for pdf in pdfs:
        text = redact.extract_pdf_text(pdf)
        for value in SENSITIVE:
            assert value not in text, f"{pdf.name}: leaked {value}"
        assert "[SSN-1]" in text or "[NAME-1]" in text or "[EMPLOYER-" in text, pdf.name
        doc = pymupdf.open(str(pdf))
        assert not any(doc.metadata.get(k) for k in ("author", "title", "subject"))
        doc.close()
    assert "120,450.00" in redact.extract_pdf_text(out / "w2-fake.redacted.pdf")
    assert "[SSN-1]" in redact.extract_pdf_text(out / "scanned-fake.redacted.pdf")
    assert "7 redacted PDF(s)" in proc.stdout
    audit = run_script(out, "--audit")
    assert audit.returncode == 0, audit.stdout + audit.stderr
    assert "LEAK AUDIT of 14 extract(s)" in audit.stdout
    assert "0 FAIL" in audit.stdout


def test_sweep_catches_pattern_value_in_other_context(workdir):
    # A text-layer PDF: the city/state/zip once on its own line (found by the
    # whole-line rule) and once merged into other wording (found by nothing
    # but the sweep, since --no-ocr keeps the OCR edge rule out of play).
    from reportlab.pdfgen import canvas
    c = canvas.Canvas(str(workdir / "envelope-fake.pdf"))
    c.drawString(72, 720, "*** FAKE TEST DOCUMENT - ALL VALUES FABRICATED ***")
    c.drawString(72, 700, "SAMPLETOWN, CA 90000")
    c.drawString(72, 680, "IMPORTANT TAX RETURN DOCUMENT ENCLOSED SAMPLETOWN, CA 90000")
    c.save()
    proc = run_script(workdir, "--yes", "--no-ocr")
    assert proc.returncode == 0, proc.stderr
    assert "[SWEEP:ADDR]" in proc.stdout
    out = workdir / "redacted"
    txt = (out / "envelope-fake.txt").read_text()
    assert "SAMPLETOWN" not in txt and "90000" not in txt
    assert "IMPORTANT TAX RETURN DOCUMENT ENCLOSED [ADDR-" in txt
    pdf_text = redact.extract_pdf_text(out / "envelope-fake.redacted.pdf")
    assert "SAMPLETOWN" not in pdf_text and "90000" not in pdf_text


def test_e2e_no_pdf_flag(workdir):
    proc = run_script(workdir, "--yes", "--no-ocr", "--no-pdf")
    assert proc.returncode == 0, proc.stderr
    assert not list((workdir / "redacted").glob("*.pdf"))
    assert "0 redacted PDF(s)" in proc.stdout


def _form_pdf(path, field_value="JOHN A SAMPLE 987-65-4321", annot=None):
    import pymupdf
    doc = pymupdf.open()
    page = doc.new_page()
    page.insert_text((72, 72), "EMPLOYEE WAGES 1,000.00 FAKE FORM DOCUMENT")
    w = pymupdf.Widget()
    w.field_name, w.field_type = "f", pymupdf.PDF_WIDGET_TYPE_TEXT
    w.rect, w.field_value = pymupdf.Rect(72, 100, 400, 120), field_value
    page.add_widget(w)
    if annot:
        page.add_freetext_annot(pymupdf.Rect(72, 200, 400, 230), annot)
    doc.save(str(path))
    doc.close()


def test_form_fields_are_flattened_and_redacted(tmp_path):
    import pymupdf
    src = tmp_path / "form-fake.pdf"
    _form_pdf(src, annot="note 123-45-6789")
    (tmp_path / "redaction_list.txt").write_text("name: JOHN A SAMPLE\n")
    before = src.read_bytes()
    proc = run_script(tmp_path, "--yes", "--no-ocr")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "FLATTENED: form-fake.pdf" in proc.stdout
    assert "PDF SKIPPED" not in proc.stdout
    assert "FLATTEN INCOMPLETE" not in proc.stdout
    out = tmp_path / "redacted"
    txt = (out / "form-fake.txt").read_text()
    pdf_text = redact.extract_pdf_text(out / "form-fake.redacted.pdf")
    for text in (txt, pdf_text):
        assert "[NAME-1]" in text and "[SSN-" in text
        assert "WAGES 1,000.00" in text
        for leak in ("SAMPLE", "987-65-4321", "123-45-6789"):
            assert leak not in text
    doc = pymupdf.open(str(out / "form-fake.redacted.pdf"))
    assert not doc.is_form_pdf
    assert not any(list(p.widgets()) or list(p.annots()) for p in doc)
    doc.close()
    # source untouched, and no flattened copy left anywhere
    assert src.read_bytes() == before
    assert sorted(p.name for p in tmp_path.iterdir()) == [
        "form-fake.pdf", "redacted", "redaction_list.txt"]
    assert run_script(out, "--audit").returncode == 0


def test_no_flatten_flag_skips_form_pdf(tmp_path):
    _form_pdf(tmp_path / "form-fake.pdf")
    proc = run_script(tmp_path, "--yes", "--no-ocr", "--no-flatten")
    assert proc.returncode == 0, proc.stderr
    assert "PDF SKIPPED: form-fake.pdf" in proc.stdout
    assert "FLATTENED" not in proc.stdout
    assert (tmp_path / "redacted" / "form-fake.txt").exists()
    assert not list((tmp_path / "redacted").glob("*.pdf"))


def test_preview_shows_field_values_and_writes_nothing(tmp_path):
    _form_pdf(tmp_path / "form-fake.pdf")
    proc = run_script(tmp_path, "--preview")
    assert proc.returncode == 0, proc.stderr
    assert "987-65-4321" in proc.stdout
    assert "FLATTENED: form-fake.pdf" in proc.stdout
    assert not (tmp_path / "redacted").exists()


def test_plain_pdf_is_not_flattened(workdir):
    assert redact.flatten_pdf(workdir / "w2-fake.pdf") is None
    proc = run_script(workdir, "--preview", "--no-ocr")
    assert "FLATTENED" not in proc.stdout


def test_unflattened_count():
    text = "NAME JOHN A\nSAMPLE  WAGES 1,000.00"
    assert redact.unflattened_count(["JOHN A SAMPLE"], text) == 0  # wrapped
    assert redact.unflattened_count(["JOHN A SAMPLE", "JANE B SAMPLE"], text) == 1
    assert redact.unflattened_count([], text) == 0


# ---------------------------------------------------------- signature blocks
SIGNER_A, SIGNER_B = "A1B2C3D4E5F64A7...", "0F9E8D7C6B5A4C3..."


def _stamp(page, x, y, signer=SIGNER_A, label="DocuSigned by:"):
    """A fake e-signature stamp at (x, y): label, an image and a scribble
    inside a Form XObject, then the signer ID line."""
    import pymupdf
    pm = pymupdf.Pixmap(pymupdf.csRGB, pymupdf.IRect(0, 0, 120, 40))
    pm.clear_with(200)
    art = pymupdf.open()
    ap = art.new_page(width=160, height=60)
    ap.insert_image(pymupdf.Rect(5, 5, 125, 45), stream=pm.tobytes("png"))
    ap.draw_bezier((5, 40), (40, 0), (80, 60), (150, 20), color=(0, 0, 1), width=1.5)
    page.insert_text((x, y), label, fontsize=6)
    page.show_pdf_page(pymupdf.Rect(x, y + 2, x + 160, y + 62), art, 0)
    if signer:
        page.insert_text((x, y + 70), signer, fontsize=6)
    art.close()


def _signed_pdf(path, stamps=((80, 318, SIGNER_A, "DocuSigned by:"),), pages=1):
    import pymupdf
    doc = pymupdf.open()
    for _ in range(pages):
        page = doc.new_page()
        page.insert_text(
            (72, 40), "DocuSign Envelope ID: 1A2B3C4D-1111-2222-3333-ABCDEF123456",
            fontsize=7)
        page.insert_text((72, 72), "IN WITNESS WHEREOF  PURCHASE AMOUNT 25,000.00")
        page.insert_text((72, 300), "INVESTOR:", fontsize=10)
        for x, y, signer, label in stamps:
            _stamp(page, x, y, signer, label)
        page.insert_text((72, 430), "Title: FAKE SIGNATORY ROLE", fontsize=10)
        page.draw_line((72, 500), (500, 500))
    doc.save(str(path))
    doc.close()


def _marks_in(pdf, rect, page=0):
    """Kinds of page marks touching rect, the redaction box itself (a mark
    that covers all of rect) excluded."""
    import pymupdf
    doc = pymupdf.open(str(pdf))
    try:
        return [kind for kind, r in doc[page].get_bboxlog()
                if redact._intersects(tuple(r), rect)
                and not (r[0] < rect[0] and r[1] < rect[1]
                         and r[2] > rect[2] and r[3] > rect[3])]
    finally:
        doc.close()


STAMP_AREA = (71, 306, 244, 394)  # just inside the fake stamp's art at (80, 318)


def test_signature_stamp_is_boxed(tmp_path):
    _signed_pdf(tmp_path / "signed-fake.pdf")
    assert "fill-image" in _marks_in(tmp_path / "signed-fake.pdf", STAMP_AREA)
    proc = run_script(tmp_path, "--yes", "--no-ocr")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "[SIGNATURE]" in proc.stdout
    out = tmp_path / "redacted"
    txt = (out / "signed-fake.txt").read_text()
    pdf_text = redact.extract_pdf_text(out / "signed-fake.redacted.pdf")
    assert "[ENVELOPE-1]" in txt  # (too small a box to carry its label in the PDF)
    for text in (txt, pdf_text):
        assert "[SIGNATURE-1]" in text
        assert "PURCHASE AMOUNT 25,000.00" in text
        assert "Title: FAKE SIGNATORY ROLE" in text
        for leak in ("DocuSigned", SIGNER_A[:12], "1A2B3C4D"):
            assert leak not in text
    marks = _marks_in(out / "signed-fake.redacted.pdf", STAMP_AREA)
    assert not [k for k in marks if "image" in k or "stroke" in k]
    # the unrelated rule further down the page survives
    assert "stroke-path" in _marks_in(out / "signed-fake.redacted.pdf",
                                      (70, 495, 505, 505))
    assert run_script(out, "--audit").returncode == 0


def test_signature_stamps_side_by_side(tmp_path):
    _signed_pdf(tmp_path / "signed-fake.pdf", stamps=(
        (80, 318, SIGNER_A, "DocuSigned by:"), (330, 318, SIGNER_B, "Signed by:")))
    proc = run_script(tmp_path, "--yes", "--no-ocr")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    txt = (tmp_path / "redacted" / "signed-fake.txt").read_text()
    assert "[SIGNATURE-1]" in txt and "[SIGNATURE-2]" in txt
    assert "Signed by" not in txt and SIGNER_B[:12] not in txt


def test_same_signer_gets_same_token_on_every_page(tmp_path):
    _signed_pdf(tmp_path / "signed-fake.pdf", pages=2)
    proc = run_script(tmp_path, "--yes", "--no-ocr")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    txt = (tmp_path / "redacted" / "signed-fake.txt").read_text()
    assert "[SIGNATURE-1]" in txt and "[SIGNATURE-2]" not in txt


def test_signed_by_in_prose_is_left_alone(tmp_path):
    import pymupdf
    doc = pymupdf.open()
    page = doc.new_page()
    page.insert_text((72, 72), "This agreement was signed by: the parties below.")
    page.insert_text((72, 100), "PURCHASE AMOUNT 25,000.00 FAKE DOCUMENT")
    doc.save(str(tmp_path / "prose-fake.pdf"))
    doc.close()
    pages = redact.extract_pdf_pages(tmp_path / "prose-fake.pdf")
    assert redact.find_signature_regions(pages, tmp_path / "prose-fake.pdf") == ({}, [])


def test_stamp_without_id_line_gets_default_area(tmp_path):
    _signed_pdf(tmp_path / "signed-fake.pdf",
                stamps=((80, 318, None, "DocuSigned by:"),))
    proc = run_script(tmp_path, "--yes", "--no-ocr")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "SIGNATURE: signed-fake.pdf page 1" in proc.stdout
    marks = _marks_in(tmp_path / "redacted" / "signed-fake.redacted.pdf", STAMP_AREA)
    assert not [k for k in marks if "image" in k or "stroke" in k]


def test_signature_form_field_is_boxed(tmp_path):
    import pymupdf
    doc = pymupdf.open()
    page = doc.new_page()
    page.insert_text((72, 72), "PURCHASE AMOUNT 25,000.00 FAKE FORM DOCUMENT")
    w = pymupdf.Widget()
    w.field_name, w.field_type = "sig", pymupdf.PDF_WIDGET_TYPE_SIGNATURE
    w.rect = pymupdf.Rect(72, 200, 300, 260)
    page.add_widget(w)
    doc.save(str(tmp_path / "sigfield-fake.pdf"))
    doc.close()
    flat = redact.flatten_pdf(tmp_path / "sigfield-fake.pdf")
    assert flat and [pi for pi, _r in flat[2]] == [0]
    proc = run_script(tmp_path, "--yes", "--no-ocr")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "[SIGNATURE]" in proc.stdout
    pdf_text = redact.extract_pdf_text(tmp_path / "redacted" / "sigfield-fake.redacted.pdf")
    assert "[SIGNATURE-1]" in pdf_text


def test_envelope_id_needs_its_label():
    uuid = "1A2B3C4D-1111-2222-3333-ABCDEF123456"
    out, _f = run_text(f"DocuSign Envelope ID: {uuid}")
    assert uuid not in out and "[ENVELOPE-1]" in out
    out, _f = run_text(f"REFERENCE {uuid}")
    assert "[ENVELOPE" not in out


def test_no_signatures_flag(tmp_path):
    _signed_pdf(tmp_path / "signed-fake.pdf")
    proc = run_script(tmp_path, "--yes", "--no-ocr", "--no-signatures")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    out = tmp_path / "redacted"
    txt = (out / "signed-fake.txt").read_text()
    assert "DocuSigned by:" in txt          # block not boxed...
    assert SIGNER_A[:12] not in txt         # ...the signer ID still is
    assert "fill-image" in _marks_in(out / "signed-fake.redacted.pdf", STAMP_AREA)


def test_audit_flags_leftover_stamp_label(tmp_path):
    d = tmp_path / "redacted"
    d.mkdir()
    (d / "leaky.txt").write_text("# Redacted extract\n\nDocuSigned by:\nsome name\n")
    proc = run_script(d, "--audit")
    assert proc.returncode == 1
    assert "[SIGNATURE] stamp label remains" in proc.stdout
    assert "some name" not in proc.stdout + proc.stderr
    assert run_script(d, "--audit", "--no-signatures").returncode == 0


def test_verify_fails_when_signature_graphics_remain(tmp_path):
    src = tmp_path / "signed-fake.pdf"
    _signed_pdf(src)
    pages = redact.extract_pdf_pages(src)
    regions, _no_id = redact.find_signature_regions(pages, src)
    sigs = {pi: [(rect, "[SIGNATURE-1]") for rect, _k in items]
            for pi, items in regions.items()}
    good, bad = tmp_path / "good.pdf", tmp_path / "bad.pdf"
    assert redact.write_redacted_pdf(src, bad, {}) is None  # region not boxed
    assert (1, "signature graphics remain") in redact.verify_redacted_pdf(
        bad, [], sig_rects=sigs)
    assert redact.write_redacted_pdf(src, good, {}, sig_rects=sigs) is None
    assert not [f for f in redact.verify_redacted_pdf(good, [], sig_rects=sigs)
                if f[1] == "signature graphics remain"]


# --------------------------------------------------------------------- audit
def test_ocr_glued_form_vocabulary_is_not_a_name():
    # OCR merges "PAYER'S TIN" into one token; it must not read as a name
    line = "PAYER'STIN RECIPIENT'STIN"
    assert not any(redact._significant_caps(w) for w in line.split())
    assert redact.suggest_entries({"x.pdf": line}, []) == []
    _fails, warns = redact.audit_text("# OCR-DERIVED\n\n" + line, [], ocr=True)
    assert warns == []
    # glued vocabulary without the apostrophe, and with possessive S
    for w in ("PAYERSTIN", "RECIPIENTSNAME", "EMPLOYEESSSN"):
        assert not redact._significant_caps(w), w
    # real names stay significant, including short ones made of stopwords
    for w in ("NOOR", "ANDREW", "O'BRIEN", "MACY'S", "NORTHEAST", "ACME"):
        assert redact._significant_caps(w), w
    assert redact.suggest_entries({"x.pdf": "PAYER'S NAME: FIRST EXAMPLE BANK"}, []) \
        == ["employer: FIRST EXAMPLE BANK"]


def test_audit_flags_leaks_without_printing_values(tmp_path):
    d = tmp_path / "redacted"
    d.mkdir()
    (d / "clean.txt").write_text(
        "# Redacted extract of clean.pdf\n\n"
        "EMPLOYER: [EMPLOYER-1]\nBOX 1 WAGES: 120,450.00\n")
    proc = run_script(d, "--audit")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "0 FAIL" in proc.stdout

    (d / "leaky.txt").write_text(
        "EMPLOYEE SSN: 123-45-6789\n"
        "PAYER'S NAME: JPMORGAN CHASE BANK NA\n")
    proc = run_script(d, "--audit")
    assert proc.returncode == 1
    out = proc.stdout + proc.stderr
    assert "[PATTERN:SSN]" in out
    assert "possible unredacted name" in out
    # the audit must NEVER print the values themselves
    assert "123-45-6789" not in out
    assert "JPMORGAN" not in out


def test_self_check_surfaces_name_warnings(workdir):
    # simulate a redaction gap: empty the list so names would leak, then
    # confirm the tightened audit-based self-check still exits 0 (patterns
    # alone leave no rule-matchable residue) but WARNs about name lines
    # (every entry is commented out, which also blocks auto-re-adding)
    lst = workdir / "redaction_list.txt"
    lst.write_text("".join(f"# {ln}\n" for ln in lst.read_text().splitlines()))
    proc = run_script(workdir, "--yes")
    assert proc.returncode == 0, proc.stderr
    assert "new entr" not in proc.stdout
    assert "AUDIT WARNINGS" in proc.stdout
    assert "possible unredacted name" in proc.stdout
    # and the names really are still there (patterns can't catch them) —
    # which is exactly what the WARN is for
    leaked = (workdir / "redacted" / "w2-fake.txt").read_text()
    assert "JOHN A SAMPLE" in leaked


# ------------------------------------------------- list auto-create / append
def test_full_list_gets_no_additions(workdir):
    before = (workdir / "redaction_list.txt").read_text()
    proc = run_script(workdir, "--preview")
    assert proc.returncode == 0, proc.stderr
    assert "found" in proc.stdout and "new entr" not in proc.stdout
    assert (workdir / "redaction_list.txt").read_text() == before


def test_existing_list_is_appended_and_idempotent(workdir):
    lst = workdir / "redaction_list.txt"
    lst.write_text("name: NEVER PRESENT PERSON")  # no trailing newline
    proc = run_script(workdir, "--preview")
    assert proc.returncode == 0, proc.stderr
    assert f"found {lst.resolve()}" in proc.stdout
    assert "new entr" in proc.stdout
    text = lst.read_text()
    assert text.startswith("name: NEVER PRESENT PERSON\n")
    assert "# auto-added" in text
    assert text.count("employer: FIRST EXAMPLE BANK") == 1
    # second run: nothing new, file untouched
    proc2 = run_script(workdir, "--preview")
    assert proc2.returncode == 0, proc2.stderr
    assert "new entr" not in proc2.stdout
    assert lst.read_text() == text


def test_commented_out_entry_is_not_readded(workdir):
    lst = workdir / "redaction_list.txt"
    lst.write_text("# employer: FIRST EXAMPLE BANK\n")
    proc = run_script(workdir, "--preview")
    assert proc.returncode == 0, proc.stderr
    text = lst.read_text()
    assert text.count("FIRST EXAMPLE BANK") == 1  # still only the comment
    assert not any("[LIST" in ln and "FIRST EXAMPLE BANK" in ln
                   for ln in proc.stdout.splitlines())  # rejected: not redacted
    assert "name: JOHN A SAMPLE" in text  # others still added


def test_list_search_climbs_two_levels(tmp_path):
    lst = tmp_path / "redaction_list.txt"
    shutil.copy(TESTDATA / "redaction_list.txt", lst)
    deep = tmp_path / "year" / "docs"
    deep.mkdir(parents=True)
    for pdf in TESTDATA.glob("*.pdf"):
        shutil.copy(pdf, deep)
    proc = run_script(deep, "--preview")
    assert proc.returncode == 0, proc.stderr
    assert f"found {lst.resolve()}" in proc.stdout
    assert not (deep / "redaction_list.txt").exists()
    assert not (tmp_path / "year" / "redaction_list.txt").exists()


def test_list_flag_creates_at_given_path(workdir, tmp_path):
    (workdir / "redaction_list.txt").unlink()
    custom = tmp_path / "elsewhere" / "my_list.txt"
    proc = run_script(workdir, "--preview", "--list", str(custom))
    assert proc.returncode == 0, proc.stderr
    assert f"created {custom}" in proc.stdout
    assert custom.is_file()
    assert not (workdir / "redaction_list.txt").exists()


def test_audit_never_creates_list(workdir):
    assert run_script(workdir, "--yes").returncode == 0
    out = workdir / "redacted"
    (workdir / "redaction_list.txt").unlink()
    proc = run_script(out, "--audit")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert not (out / "redaction_list.txt").exists()
    assert not (workdir / "redaction_list.txt").exists()


# --------------------------------------------------------------- master list
def _move_to_master(workdir, tmp_path, line="employer: ACME WIDGETS INC"):
    """Take one entry out of the folder list and put it in a master list."""
    lst = workdir / "redaction_list.txt"
    lst.write_text(lst.read_text().replace(line + "\n", ""))
    master = tmp_path / "cfg" / "master.txt"
    master.parent.mkdir()
    master.write_text(line + "\n")
    return lst, master


def test_master_entry_is_redacted(workdir, tmp_path):
    lst, master = _move_to_master(workdir, tmp_path)
    before = master.read_text()
    proc = run_script(workdir, "--preview", "--master", str(master))
    assert proc.returncode == 0, proc.stderr
    assert f"master list: found {master} (1 entries)" in proc.stdout
    assert any("[LIST:employer]" in ln and "ACME WIDGETS INC" in ln
               for ln in proc.stdout.splitlines())
    assert "ACME WIDGETS INC" not in lst.read_text()  # covered: not suggested
    assert master.read_text() == before  # the script never writes to it


def test_master_default_location(workdir, isolated_config):
    proc = run_script(workdir, "--preview")
    assert proc.returncode == 0, proc.stderr
    master = isolated_config / "pdf-redactor" / "master_redaction_list.txt"
    assert f"master list: none (create {master}" in proc.stdout
    assert not master.exists()  # never auto-created
    master.parent.mkdir()
    master.write_text("employer: NEVER PRESENT COMPANY\n")
    proc = run_script(workdir, "--preview")
    assert proc.returncode == 0, proc.stderr
    assert f"master list: found {master} (1 entries)" in proc.stdout
    # a master entry absent from this folder is normal, not a stale entry
    assert "never matched" not in proc.stdout


def test_no_master_flag(workdir, tmp_path, isolated_config):
    lst, master = _move_to_master(workdir, tmp_path, "acct: 98765432")
    default = isolated_config / "pdf-redactor" / "master_redaction_list.txt"
    default.parent.mkdir()
    shutil.copy(master, default)
    proc = run_script(workdir, "--preview", "--no-master")
    assert proc.returncode == 0, proc.stderr
    assert "master list: skipped" in proc.stdout
    assert "[LIST:acct]        98765432" not in proc.stdout
    proc = run_script(workdir, "--preview")
    assert "[LIST:acct]        98765432" in proc.stdout


def test_master_flag_missing_file_is_an_error(workdir, tmp_path):
    proc = run_script(workdir, "--preview", "--master", str(tmp_path / "nope.txt"))
    assert proc.returncode != 0
    assert "master list" in proc.stderr


def test_entry_in_both_lists_is_one_entry(workdir, tmp_path):
    master = tmp_path / "master.txt"
    master.write_text("employer: acme  widgets inc\n")
    merged = redact.load_lists(master, workdir / "redaction_list.txt")
    assert len(merged) == len(redact.load_list(workdir / "redaction_list.txt"))
    base = run_script(workdir, "--preview", "--no-master")
    proc = run_script(workdir, "--preview", "--master", str(master))
    assert proc.returncode == 0, proc.stderr
    summary = [ln for ln in base.stdout.splitlines() if "planned redaction" in ln]
    assert summary and summary[0] in proc.stdout


def test_master_rejection_is_not_suggested(workdir, tmp_path):
    lst, master = _move_to_master(workdir, tmp_path)
    master.write_text("# employer: ACME WIDGETS INC\n")
    proc = run_script(workdir, "--preview", "--master", str(master))
    assert proc.returncode == 0, proc.stderr
    assert "ACME WIDGETS INC" not in lst.read_text()
    assert not any("[LIST" in ln and "ACME WIDGETS INC" in ln
                   for ln in proc.stdout.splitlines())


def test_audit_uses_master_list(tmp_path):
    d = tmp_path / "redacted"
    d.mkdir()
    (d / "leaky.txt").write_text(
        "# Redacted extract of leaky.pdf\n\nsent to zebra quartz holdings today\n")
    master = tmp_path / "master.txt"
    master.write_text("employer: ZEBRA QUARTZ HOLDINGS\n")
    assert run_script(d, "--audit", "--no-master").returncode == 0
    proc = run_script(d, "--audit", "--master", str(master))
    assert proc.returncode == 1
    assert "zebra" not in (proc.stdout + proc.stderr).lower()


def test_locked_output_is_a_clear_error(workdir):
    import os
    if os.geteuid() == 0:
        pytest.skip("root ignores file permissions")
    assert run_script(workdir / "w2-fake.pdf", "--yes").returncode == 0
    out = workdir / "redacted"
    assert run_script(workdir / "w2-fake.pdf", "--yes").returncode == 0  # re-run
    (out / "w2-fake.txt").chmod(0o444)
    proc = run_script(workdir / "w2-fake.pdf", "--yes")
    (out / "w2-fake.txt").chmod(0o644)
    assert proc.returncode != 0
    assert "cannot write" in proc.stderr and "close it and re-run" in proc.stderr
    assert "Traceback" not in proc.stderr
    # same for the PDF, which PyMuPDF replaces by removing the old file
    out.chmod(0o555)
    proc = run_script(workdir / "w2-fake.pdf", "--yes")
    out.chmod(0o755)
    assert proc.returncode != 0
    assert "cannot write" in proc.stderr and "Traceback" not in proc.stderr


def test_write_error_detection():
    assert redact._is_write_error(PermissionError(13, "Permission denied"))
    assert redact._is_write_error(RuntimeError(
        "code=2: cannot remove file 'x.redacted.pdf': Permission denied"))
    assert not redact._is_write_error(RuntimeError("code=7: syntax error in content"))


def test_inspect_prints_structure_only(tmp_path):
    _signed_pdf(tmp_path / "signed-fake.pdf")
    before = sorted(p.name for p in tmp_path.iterdir())
    proc = run_script(tmp_path, "--inspect")
    assert proc.returncode == 0, proc.stderr
    assert "stamp labels: 1 DocuSigned / 1 any; signer IDs: 1" in proc.stdout
    assert "regions: 1" in proc.stdout
    for leak in ("signed-fake", SIGNER_A[:12], "1A2B3C4D", "WITNESS", "SIGNATORY"):
        assert leak not in proc.stdout
    assert sorted(p.name for p in tmp_path.iterdir()) == before  # nothing written


# ------------------------------------- e-signed documents without stamp text
IMG_AREA = (148, 318, 249, 358)  # just around the fake signature image


def _esigned_pdf(path, header=True, cert_pages=0, sig_field=False):
    """A signature page whose stamp carries NO readable label or ID: an
    image, a bracket drawn around it, small print next to it, and a long
    underline beneath. Optionally followed by certificate pages."""
    import pymupdf
    pm = pymupdf.Pixmap(pymupdf.csRGB, pymupdf.IRect(0, 0, 97, 36))
    pm.clear_with(180)
    doc = pymupdf.open()
    for n in range(1 + cert_pages):
        page = doc.new_page()
        if header:
            page.insert_text(
                (72, 40), "Docusign Envelope ID: 1A2B3C4D-1111-2222-3333-ABCDEF123456",
                fontsize=7)
        if n:
            page.insert_text((72, 80), "Certificate Of Completion" if n == 1
                             else "Electronic Record Disclosure FAKE", fontsize=12)
            page.insert_text((72, 110), "Signer Events  JOHN A SAMPLE  10.0.0.1",
                             fontsize=9)
            page.insert_image(pymupdf.Rect(300, 100, 376, 128), pixmap=pm)
            continue
        page.insert_text((72, 72), "IN WITNESS WHEREOF  PURCHASE AMOUNT 25,000.00")
        page.insert_text((72, 350), "By:", fontsize=10)
        page.insert_image(pymupdf.Rect(150, 320, 247, 356), pixmap=pm)
        page.draw_line((146, 316), (146, 360))                   # bracket
        page.draw_line((146, 316), (156, 316))
        page.draw_line((146, 360), (156, 360))
        page.insert_text((150, 314), "unreadable label", fontsize=6)
        page.insert_text((150, 369), "UNREADABLEID", fontsize=6)
        page.draw_line((100, 376), (420, 376))                   # signature line
        page.insert_text((300, 350), "KEEP THIS TEXT", fontsize=10)
        page.insert_text((72, 395), "Name: JOHN A SAMPLE", fontsize=10)
        if sig_field:
            w = pymupdf.Widget()
            w.field_name, w.field_type = "cert", pymupdf.PDF_WIDGET_TYPE_SIGNATURE
            w.rect = pymupdf.Rect(20, 20, 21, 21)  # as good as invisible
            page.add_widget(w)
    doc.save(str(path))
    doc.close()


def test_text_free_stamp_in_esigned_document_is_boxed(tmp_path):
    src = tmp_path / "esigned-fake.pdf"
    _esigned_pdf(src)
    (tmp_path / "redaction_list.txt").write_text("name: JOHN A SAMPLE\n")
    proc = run_script(tmp_path, "--yes", "--no-ocr")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "[SIGNATURE]" in proc.stdout
    out = tmp_path / "redacted"
    txt = (out / "esigned-fake.txt").read_text()
    pdf_text = redact.extract_pdf_text(out / "esigned-fake.redacted.pdf")
    for text in (txt, pdf_text):
        assert "unreadable" not in text and "UNREADABLEID" not in text
        assert "KEEP THIS TEXT" in text and "By:" in text   # beside the stamp
        assert "Name: [NAME-1]" in text                     # 10 pt line: by list only
        assert "PURCHASE AMOUNT 25,000.00" in text
    marks = _marks_in(out / "esigned-fake.redacted.pdf", IMG_AREA)
    assert not [k for k in marks if "image" in k or "stroke" in k]
    # the long signature line is not part of the stamp
    assert "stroke-path" in _marks_in(out / "esigned-fake.redacted.pdf",
                                      (300, 374, 420, 378))
    assert run_script(out, "--audit").returncode == 0


def test_image_in_ordinary_document_is_left_alone(tmp_path):
    src = tmp_path / "plain-fake.pdf"
    _esigned_pdf(src, header=False)
    assert not redact.is_esigned(src)
    proc = run_script(tmp_path, "--yes", "--no-ocr")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "[SIGNATURE]" not in proc.stdout
    assert "fill-image" in _marks_in(
        tmp_path / "redacted" / "plain-fake.redacted.pdf", IMG_AREA)


def test_invisible_signature_field_marks_esigned_but_gets_no_box(tmp_path):
    src = tmp_path / "esigned-fake.pdf"
    _esigned_pdf(src, header=False, sig_field=True)
    flat, _values, sig_fields = redact.flatten_pdf(src)
    assert sig_fields and redact.is_esigned(flat, sig_fields)
    pages = redact.extract_pdf_pages(flat)
    regions, _no_id = redact.find_signature_regions(pages, flat, sig_fields, True)
    assert len(regions[0]) == 1  # the image stamp; nothing for the tiny field
    rect = regions[0][0][0]
    assert rect[2] - rect[0] > 90 and rect[3] - rect[1] > 30


def test_certificate_pages_are_dropped(tmp_path):
    import pymupdf
    src = tmp_path / "esigned-fake.pdf"
    _esigned_pdf(src, cert_pages=2)
    before = src.read_bytes()
    proc = run_script(tmp_path, "--yes", "--no-ocr")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "CERTIFICATE DROPPED: esigned-fake.pdf — pages 2-3" in proc.stdout
    out = tmp_path / "redacted"
    txt = (out / "esigned-fake.txt").read_text()
    doc = pymupdf.open(str(out / "esigned-fake.redacted.pdf"))
    assert len(doc) == 1
    pdf_text = doc[0].get_text()
    doc.close()
    for text in (txt, pdf_text):
        assert "Certificate" not in text and "10.0.0.1" not in text
        assert "PURCHASE AMOUNT" in text
    assert src.read_bytes() == before
    assert sorted(p.name for p in tmp_path.iterdir()) == [
        "esigned-fake.pdf", "redacted", "redaction_list.txt"]


def test_keep_certificate_flag(tmp_path):
    import pymupdf
    _esigned_pdf(tmp_path / "esigned-fake.pdf", cert_pages=2)
    proc = run_script(tmp_path, "--yes", "--no-ocr", "--keep-certificate")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "CERTIFICATE DROPPED" not in proc.stdout
    doc = pymupdf.open(str(tmp_path / "redacted" / "esigned-fake.redacted.pdf"))
    assert len(doc) == 3
    doc.close()


def test_certificate_wording_in_ordinary_document_drops_nothing(tmp_path):
    _esigned_pdf(tmp_path / "plain-fake.pdf", header=False, cert_pages=1)
    proc = run_script(tmp_path, "--preview", "--no-ocr")
    assert proc.returncode == 0, proc.stderr
    assert "CERTIFICATE DROPPED" not in proc.stdout
    assert "===== PAGE 2 =====" in redact.extract_pdf_text(tmp_path / "plain-fake.pdf")


def test_inspect_reports_esigned_and_certificate(tmp_path):
    _esigned_pdf(tmp_path / "esigned-fake.pdf", cert_pages=2)
    proc = run_script(tmp_path, "--inspect")
    assert proc.returncode == 0, proc.stderr
    assert "e-signed: yes" in proc.stdout
    assert "certificate pages: 2-3" in proc.stdout
    for leak in ("esigned-fake", "SAMPLE", "1A2B3C4D", "10.0.0.1", "WITNESS",
                 "unreadable", "Completion"):
        assert leak not in proc.stdout
