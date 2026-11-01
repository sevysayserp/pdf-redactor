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


def test_ssn_masked():
    for masked in ("XXX-XX-4321", "***-**-4321", "xxxxx4321"):
        out, _ = run_text(f"SSN {masked} WAGES 1,000.00")
        assert out == "SSN [SSN-1] WAGES 1,000.00", masked
    # six mask characters: a masked account number, not an SSN
    out, _ = run_text("ACCOUNT XXXXXX4321")
    assert "[SSN-" not in out


def test_masked_ssn_shares_token_with_full():
    tokens = redact.TokenMap(ssns=["987-65-4321"])
    full = tokens.token("SSN", "987-65-4321")
    assert tokens.token("SSN", "XXX-XX-4321") == full
    assert tokens.token("SSN", "-4321") == full
    assert tokens.token("SSN", "XXX-XX-9999") != full
    plain = redact.TokenMap()
    assert plain.token("SSN", "987-65-4321") != plain.token("SSN", "XXX-XX-4321")
    assert plain.token("SSN", "XXX-XX-4321") == plain.token("SSN", "-4321")


def test_e2e_masked_ssn_and_bare_tail(tmp_path):
    from reportlab.pdfgen import canvas
    c = canvas.Canvas(str(tmp_path / "masked-fake.pdf"))
    for y, line in ((720, "*** FAKE TEST DOCUMENT - ALL VALUES FABRICATED ***"),
                    (700, "EMPLOYEE SSN 987-65-4321"),
                    (680, "RECIPIENT TIN XXX-XX-4321"),
                    (660, "COPY B FOR -4321 RECORDS"),
                    (640, "REFERENCE 90000-4321 ADJUSTMENT -4321.00")):
        c.drawString(72, y, line)
    c.save()
    proc = run_script(tmp_path, "--yes", "--no-ocr")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "[SWEEP:SSN]" in proc.stdout
    out = tmp_path / "redacted"
    pdf_text = redact.extract_pdf_text(out / "masked-fake.redacted.pdf")
    for text in ((out / "masked-fake.txt").read_text(), pdf_text):
        assert "EMPLOYEE SSN [SSN-1]" in text
        assert "RECIPIENT TIN [SSN-1]" in text
        assert "COPY B FOR [SSN-1] RECORDS" in text
        assert "[SSN-2]" not in text
        assert "REFERENCE 90000-4321 ADJUSTMENT -4321.00" in text
    assert run_script(out, "--audit").returncode == 0


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


def test_decimals_and_percentages_are_not_accounts():
    kept = ("0.00000123456 %", "0.00000123456%", ".00000123456 %",
            "12.00000123456", "rate 10000000 %")
    redacted = {
        "ACCT 00012345678": "ACCT [ACCT-...5678]",
        "REF 987650001 AMOUNT": "REF [ACCT-...0001] AMOUNT",
        "Account No.12345678": "Account No.[ACCT-...5678]",
        "No. 12345678.": "No. [ACCT-...5678].",
        "1234567890.50": "[ACCT-...7890].50",
    }
    for ocr in (False, True):
        for line in kept:
            out = redact.redact_text(line, [], redact.TokenMap(),
                                     defaultdict(int), ocr=ocr)
            assert out == line, (line, ocr)
        for line, want in redacted.items():
            out = redact.redact_text(line, [], redact.TokenMap(),
                                     defaultdict(int), ocr=ocr)
            assert out == want, (line, ocr)


def test_labeled_account_number():
    cases = {
        "Account No. Z12-345678": "Account No. [ACCT-...5678]",
        "Account No. Z12-345678 Recipient ID No. XXX-XX-4321":
            "Account No. [ACCT-...5678] Recipient ID No. [SSN-1]",
        "ACCOUNT NUMBER: 1234-5678-90": "ACCOUNT NUMBER: [ACCT-...7890]",
        "Acct # AB1234": "Acct # [ACCT-...1234]",
        "AccountNo.Z12-345678": "AccountNo.[ACCT-...5678]",
    }
    cases.update({s: s for s in (
        "Account Number 2025", "Account No. of shares 100", "Account No. 1,234.56",
        "Account No. 12/31/2025 statement", "Account Summary 2025-12-31")})
    for line, want in cases.items():
        for ocr in (False, True):
            out = redact.redact_text(line, [], redact.TokenMap(),
                                     defaultdict(int), ocr=ocr)
            assert out == want, (line, ocr)
            assert not redact.audit_text(out, [], ocr=ocr)[0], (line, ocr)


def test_e2e_labeled_account_is_swept_where_unlabeled(tmp_path):
    from reportlab.pdfgen import canvas
    c = canvas.Canvas(str(tmp_path / "acct-fake.pdf"))
    for y, line in ((720, "*** FAKE TEST DOCUMENT - ALL VALUES FABRICATED ***"),
                    (700, "Account No. Z12-345678"),
                    (680, "Statement for Z12-345678 continued")):
        c.drawString(72, y, line)
    c.save()
    proc = run_script(tmp_path, "--yes", "--no-ocr")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "[SWEEP:ACCT]" in proc.stdout
    out = tmp_path / "redacted"
    pdf_text = redact.extract_pdf_text(out / "acct-fake.redacted.pdf")
    for text in ((out / "acct-fake.txt").read_text(), pdf_text):
        assert "Account No. [ACCT-...5678]" in text
        assert "Statement for [ACCT-...5678] continued" in text
        assert "345678" not in text


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


def test_street_suffixes_that_are_everyday_words():
    for line in ("4 SAMPLETECH CENTER", "4 Sampletech Center",
                 "4 SAMPLETECH CENTER, SAMPLETOWN, CA 90000",
                 "100 EXAMPLE PLAZA STE 200", "500 OLD COUNTRY HWY", "12 TIMES SQ"):
        for ocr in (False, True):
            out = redact.redact_text(line, [], redact.TokenMap(),
                                     defaultdict(int), ocr=ocr)
            assert out == "[ADDR-1]", (line, ocr)
    # lower case: running text, not an address
    for line in ("Call 800 our service center today",
                 "Box 3 Total for the square footage",
                 "Line 5 see the trail of payments"):
        for ocr in (False, True):
            out = redact.redact_text(line, [], redact.TokenMap(),
                                     defaultdict(int), ocr=ocr)
            assert out == line, (line, ocr)


def test_unit_designator_apart_from_its_street():
    cases = {
        "SUITE 2200": "[ADDR-1]",
        "Suite 2200": "[ADDR-1]",
        "100 EXAMPLE STREET SUITE 2200": "[ADDR-1]",
        "100 EXAMPLE STREET NW SUITE 2200": "[ADDR-1] NW [ADDR-2]",
        "100 EXAMPLE ST. SUITE 2200": "[ADDR-1]. [ADDR-2]",
        "4 SAMPLETECH CENTER, 22ND FLOOR, SUITE 2200": "[ADDR-1], [ADDR-2], [ADDR-3]",
        "ACME WIDGETS SUITE 2200 SAMPLETOWN, CA 90000": "ACME WIDGETS [ADDR-1] [ADDR-2]",
        "APT 4B": "[ADDR-1]", "Unit #12": "[ADDR-1]", "STE. 300": "[ADDR-1]",
        "Rm 204": "[ADDR-1]", "APT 12-C": "[ADDR-1]", "FLOOR 5": "[ADDR-1]",
    }
    cases.update({s: s for s in ("sold 1 unit 5 times", "UNITS 100",
                                 "Suite of services 2025", "ROOM AND BOARD 1200")})
    for line, want in cases.items():
        for ocr in (False, True):
            out = redact.redact_text(line, [], redact.TokenMap(),
                                     defaultdict(int), ocr=ocr)
            assert out == want, (line, ocr)
            assert not redact.audit_text(out, [], ocr=ocr)[0], (line, ocr)


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


def test_amount_before_address_is_not_part_of_it():
    # a form row puts a box label and amount right before the street address
    # (W-2 box 12b); only the address itself may match
    rows = ("12bAA  9477.36  1234 EXAMPLE STREET",
            "1 Wages 50,000.00 1234 EXAMPLE STREET, SAMPLETOWN, CA 90000")
    for rx in (redact.ADDR, redact.ocr_rx(redact.ADDR)):
        for s in rows:
            matches = [m.group() for m in rx.finditer(s)]
            assert len(matches) == 1 and matches[0].startswith("1234 EXAMPLE"), s
    out, _ = run_text(rows[0])
    assert out == "12bAA  9477.36  [ADDR-1]"


def test_city_line_requires_real_state():
    out, _ = run_text("SAMPLETOWN, CA 90000")
    assert out == "[ADDR-1]"
    out, _ = run_text("SAMPLETOWN, XX 90000")  # not a state code
    assert "90000" in out


def test_city_line_next_to_redacted_values():
    # a city/state/zip sharing its line with nothing but redacted values
    out, _ = run_text("1234 EXAMPLE STREET SAMPLETOWN, CA 90000")
    assert out == "[ADDR-1] [ADDR-2]"
    out, _ = run_text("JOHN A SAMPLE  SAMPLETOWN, CA 90000",
                      redact.load_list(TESTDATA / "redaction_list.txt"))
    assert "SAMPLETOWN" not in out and "[NAME-" in out and "[ADDR-1]" in out
    # the "BOX" of a redacted PO box is not form vocabulary
    assert run_text("PO BOX 1 SAMPLETOWN, CA 90000")[0] == "[ADDR-1] [ADDR-2]"
    # form vocabulary still protects return-page text
    line = "1234 EXAMPLE STREET FORM SAMPLETOWN, CA 90000"
    assert "SAMPLETOWN, CA 90000" in run_text(line)[0]


@pytest.mark.parametrize("font,size,leading", [
    ("Helvetica", 8, 8), ("Helvetica", 8, 7), ("Courier", 8, 7),
    ("Times-Roman", 6, 6), ("Helvetica", 10, 12)])
def test_redaction_spares_lines_above_and_below(tmp_path, font, size, leading):
    # PyMuPDF removes every glyph whose box touches a redaction; on tight
    # line spacing that used to eat the neighbouring lines
    from reportlab.pdfgen import canvas
    c = canvas.Canvas(str(tmp_path / "tight-fake.pdf"))
    c.setFont(font, size)
    c.drawString(72, 740, "*** FAKE TEST DOCUMENT - ALL VALUES FABRICATED ***")
    for i, line in enumerate(("FAKE BROKERAGE SERVICES", "P.O. BOX 12345",
                              "Customer Service wording here",
                              "SAMPLE TOWNSHIP, CA 90000-1234",
                              "Questions and answers")):
        c.drawString(72, 700 - i * leading, line)
    c.save()
    proc = run_script(tmp_path, "--yes", "--no-ocr")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    want = ["FAKE BROKERAGE SERVICES", "[ADDR-1]", "Customer Service wording here",
            "[ADDR-2]", "Questions and answers"]
    out = tmp_path / "redacted"
    assert (out / "tight-fake.txt").read_text().splitlines()[-5:] == want
    pdf_text = redact.extract_pdf_text(out / "tight-fake.redacted.pdf")
    assert pdf_text.splitlines()[-5:] == want


@pytest.mark.parametrize("size", [5, 6, 8, 10, 12])
def test_words_positioned_without_space_characters(tmp_path, size):
    # no space glyphs: each word is placed on its own, a normal word gap apart
    from reportlab.pdfbase.pdfmetrics import stringWidth
    from reportlab.pdfgen import canvas
    c = canvas.Canvas(str(tmp_path / "nospace-fake.pdf"))
    c.setFont("Helvetica", size)
    y = 720
    for line in ("FAKE TEST DOCUMENT ALL VALUES FABRICATED",
                 "EMPLOYEE JOHN A SAMPLE", "1234 EXAMPLE STREET APT 12",
                 "SAMPLETOWN, CA 90000", "Total dividends 1,234.56"):
        x = 72
        for word in line.split():
            c.drawString(x, y, word)
            x += stringWidth(word, "Helvetica", size) + 0.22 * size
        y -= 1.3 * size
    c.save()
    (tmp_path / "redaction_list.txt").write_text("name: JOHN A SAMPLE\n")
    proc = run_script(tmp_path, "--yes", "--no-ocr")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    out = tmp_path / "redacted"
    want = ["EMPLOYEE [NAME-1]", "[ADDR-1]", "[ADDR-2]", "Total dividends 1,234.56"]
    assert (out / "nospace-fake.txt").read_text().splitlines()[-4:] == want
    pdf_text = redact.extract_pdf_text(out / "nospace-fake.redacted.pdf")
    assert pdf_text.splitlines()[-4:] == want


@pytest.mark.parametrize("mediabox", [
    "[100 0 712 792]", "[-100 0 512 792]", "[100 80 712 872]", "[0 -80 612 712]"])
def test_page_box_not_starting_at_origin(tmp_path, mediabox):
    # the two libraries then disagree on coordinates; boxes used to land
    # beside the text and the PDF self-check failed
    import pymupdf
    from reportlab.pdfgen import canvas
    raw = tmp_path / "raw.tmp"
    c = canvas.Canvas(str(raw))
    c.setFont("Helvetica", 9)
    for i, line in enumerate(("FAKE TEST DOCUMENT ALL VALUES FABRICATED",
                              "Account No. Z12-345678 SSN 987-65-4321",
                              "1234 EXAMPLE STREET", "SAMPLETOWN, CA 90000-1234",
                              "Questions and answers 12345678")):
        c.drawString(172, 600 - i * 14, line)
    c.save()
    doc = pymupdf.open(str(raw), filetype="pdf")
    doc.xref_set_key(doc[0].xref, "MediaBox", mediabox)
    doc.save(str(tmp_path / "mbox-fake.pdf"))
    doc.close()
    raw.unlink()
    proc = run_script(tmp_path, "--yes", "--no-ocr")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "PDF SKIPPED" not in proc.stdout
    want = ["FAKE TEST DOCUMENT ALL VALUES FABRICATED",
            "Account No. [ACCT-...5678] SSN [SSN-1]", "[ADDR-1]", "[ADDR-2]",
            "Questions and answers [ACCT-...5678]"]
    out = tmp_path / "redacted"
    assert (out / "mbox-fake.txt").read_text().splitlines()[-5:] == want
    pdf_text = redact.extract_pdf_text(out / "mbox-fake.redacted.pdf")
    assert pdf_text.splitlines()[-5:] == want


@pytest.mark.parametrize("leading", [9, 10.5, 14])
def test_degenerate_character_boxes_are_repaired(tmp_path, leading):
    # some fonts yield character boxes of ~zero height on the descender
    # line; nothing was removed there and the label was invisibly small
    from reportlab.pdfgen import canvas
    src, dst = tmp_path / "thin-fake.pdf", tmp_path / "out.pdf"
    c = canvas.Canvas(str(src))
    c.setFont("Helvetica", 9)
    lines = ["FAKE TEST DOCUMENT ALL VALUES FABRICATED", "Line above stays",
             "REF 987650001 TAXPAYER ID: ***-**-4321 END", "Line below stays"]
    for i, line in enumerate(lines):
        c.drawString(72, 700 - i * leading, line)
    c.save()
    pages = redact.extract_pdf_pages(src)
    spans = []
    redact.redact_text(redact.pages_to_text(pages), [], redact.TokenMap(),
                       defaultdict(int), spans=spans)
    rects = redact.redaction_rects(pages, spans)
    # flatten every box onto the descender line, as those fonts report them
    thin = {pi: [((x0, bottom + 0.4, x1, bottom + 0.401), tok)
                 for (x0, _top, x1, bottom), tok in items]
            for pi, items in rects.items()}
    assert redact.write_redacted_pdf(src, dst, thin) is None
    assert redact.extract_pdf_text(dst).splitlines() == [
        lines[0], lines[1], "REF [ACCT-...0001] TAXPAYER ID: [SSN-1] END", lines[3]]


def test_box_is_cleared_whole_when_the_band_misses(tmp_path, monkeypatch):
    # glyphs whose PyMuPDF position differs from their pdfplumber box are
    # missed by the thin band; simulate that by moving the band off the line
    from reportlab.pdfgen import canvas
    src, dst = tmp_path / "band-fake.pdf", tmp_path / "out.pdf"
    c = canvas.Canvas(str(src))
    c.drawString(72, 720, "*** FAKE TEST DOCUMENT - ALL VALUES FABRICATED ***")
    c.drawString(72, 700, "EMPLOYEE SSN 987-65-4321 WAGES 1,000.00")
    c.save()
    pages = redact.extract_pdf_pages(src)
    spans = []
    redact.redact_text(redact.pages_to_text(pages), [], redact.TokenMap(),
                       defaultdict(int), spans=spans)
    rects = redact.redaction_rects(pages, spans)
    monkeypatch.setattr(redact, "_text_band", lambda top, bottom: (top - 40, top - 39))
    assert redact.write_redacted_pdf(src, dst, rects) is None
    text = redact.extract_pdf_text(dst)
    assert "987-65-4321" not in text
    assert "EMPLOYEE SSN [SSN-1] WAGES 1,000.00" in text


def test_small_print_columns_do_not_merge_lines(tmp_path):
    # 4.5 pt rows 5.4 pt apart with a second column set 2.7 pt lower:
    # pdfplumber's 3 pt line chaining merged every row into one line and
    # interleaved the letters ("14 it h W st" was then read as a street)
    from reportlab.pdfgen import canvas
    c = canvas.Canvas(str(tmp_path / "cols-fake.pdf"))
    c.setFont("Helvetica", 4.5)
    left = ["FAKE TEST DOCUMENT", "Bay H1A, Sampletown Industrial, Estate,",
            "Samplecity, V14 FX94, Fakeland", "Dividends 1,234.56", "Interest 78.90"]
    right = ["ALL VALUES FABRICATED", "Payer note one", "Payer note two",
             "Payer note three", "Payer note four"]
    for i, (a, b) in enumerate(zip(left, right)):
        c.drawString(72, 700 - i * 5.44, a)
        c.drawString(300, 700 - i * 5.44 - 2.7, b)
    c.save()
    lines = redact.extract_pdf_text(tmp_path / "cols-fake.pdf").splitlines()
    assert [ln for ln in lines if ln in left] == left
    assert [ln for ln in lines if ln in right] == right
    assert len(lines) == 10
    proc = run_script(tmp_path, "--yes", "--no-ocr")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    txt = (tmp_path / "redacted" / "cols-fake.txt").read_text()
    assert "Bay H1A, Sampletown Industrial, Estate," in txt
    assert "[ADDR-" not in txt


def test_e2e_small_print_keeps_labels_and_passes_check(tmp_path):
    # PyMuPDF drops the label of a short redaction box; the redacted PDF then
    # read differently from the .txt and the self-check failed on a city line
    from reportlab.pdfgen import canvas
    c = canvas.Canvas(str(tmp_path / "small-fake.pdf"))
    c.setFont("Helvetica", 6)
    for y, line in ((720, "*** FAKE TEST DOCUMENT - ALL VALUES FABRICATED ***"),
                    (712, "RECIPIENT JOHN A SAMPLE"),
                    (704, "1234 EXAMPLE STREET SAMPLETOWN, CA 90000"),
                    (696, "1 A ST 5 Total dividends 1,234.56")):
        c.drawString(72, y, line)
    c.save()
    (tmp_path / "redaction_list.txt").write_text("name: JOHN A SAMPLE\n")
    proc = run_script(tmp_path, "--yes", "--no-ocr")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    out = tmp_path / "redacted"
    pdf_text = redact.extract_pdf_text(out / "small-fake.redacted.pdf")
    for text in ((out / "small-fake.txt").read_text(), pdf_text):
        assert "RECIPIENT [NAME-1]" in text
        assert "[ADDR-1] [ADDR-2]" in text
        assert "[ADDR-3] 5 Total dividends 1,234.56" in text
        for leak in ("SAMPLE", "90000", "EXAMPLE"):
            assert leak not in text.replace("FAKE TEST DOCUMENT", "")
    assert run_script(out, "--audit").returncode == 0


def test_id_rule_does_not_take_zip_of_city_line():
    for line in ("STATE ID SAMPLETOWN, CA 90000-1234",
                 "DL SAMPLETOWN, CA 90000-1234"):
        assert run_text(line)[0] == "[ADDR-1]", line
    assert run_text("STATE ID: CA 123-4567-8")[0] == "STATE ID: CA [ID-1]"
    # the late run still catches a city left alone by an earlier redaction
    tokens, findings = redact.TokenMap(), defaultdict(int)
    out = redact.redact_text("ACCT 12345678 SAMPLETOWN, CA 90000", [], tokens,
                             findings, ocr=True)
    assert out.endswith("[ADDR-1]") and "SAMPLETOWN" not in out


def test_city_inside_a_line():
    cases = {
        "SAMPLETOWN, CA 90000-1234 Recipient ID No. XXX-XX-4321 "
        "Payer's Fed ID Number 12-3456789":
            "[ADDR-1] Recipient ID No. [SSN-1] Payer's Fed ID Number [EIN-1]",
        "PO BOX 4321 SAMPLETOWN, CA 90000-1234 Account No. X12-345678":
            "[ADDR-1] [ADDR-2] Account No. [ACCT-...5678]",
        "1234 EXAMPLE STREET SAMPLETOWN, CA 90000 Recipient ID No. 987-65-4321":
            "[ADDR-1] [ADDR-2] Recipient ID No. [SSN-1]",
        "ACCT 12345678 SAMPLETOWN, CA 90000": "ACCT [ACCT-...5678] [ADDR-1]",
        # ZIP+4 is redacted even on a form-vocabulary line; 5 digits is not
        "FORM 1099 SAMPLETOWN CA 90000-1234 for 2025": "FORM 1099 [ADDR-1] for 2025",
        # a country field between state and ZIP, two addresses on one line
        "SAMPLETOWN CA US 90000 OTHERVILLE NY US 10000": "[ADDR-1] [ADDR-2]",
        "SAMPLE LAKE TOWN CA US 90000-1234 OTHERVILLE NY USA 10000":
            "[ADDR-1] [ADDR-2]",
        "1234 EXAMPLE STREET SAMPLETOWN CA US 90000 500 INDUSTRY WAY "
        "OTHERVILLE NY US 10000": "[ADDR-1] [ADDR-3] [ADDR-2] [ADDR-4]",
        "Shipped to CA US 90000 units": "Shipped to CA US 90000 units",
        "Paid In US 10000.00": "Paid In US 10000.00",
        # a street-name word is never a bare number
        "123 5TH AVE": "[ADDR-1]",
        "100 200 MAIN ST": "100 [ADDR-1]",
        # comma with no space after it
        "SAMPLE LAKE TOWN,CA 90000-1234": "[ADDR-1]",
        "SAMPLE LAKE TOWN,CA 90000": "[ADDR-1]",
        "SAMPLETOWN,CA 90000-1234 Recipient ID No. 987-65-4321":
            "[ADDR-1] Recipient ID No. [SSN-1]",
        "SAMPLETOWN,CA 90000 Recipient ID No. 987-65-4321":
            "[ADDR-1] Recipient ID No. [SSN-1]",
        "P.O. BOX 12345,SAMPLETOWN,CA 90000-1234": "[ADDR-1]",
        "wages,IN 10000 and tips": "wages,IN 10000 and tips",
        "Proceeds,OR 12345.00": "Proceeds,OR 12345.00",
        # unchanged
        "FORM 1099 for SAMPLETOWN, CA 90000 filers":
            "FORM 1099 for SAMPLETOWN, CA 90000 filers",
        "STATE ID: CA 123-4567-8": "STATE ID: CA [ID-1]",
        "12bAA  9477.36  1234 EXAMPLE STREET": "12bAA  9477.36  [ADDR-1]",
        "wages, IN 10000 and tips": "wages, IN 10000 and tips",
        "Total proceeds, OR 12345.00": "Total proceeds, OR 12345.00",
    }
    for line, want in cases.items():
        for ocr in (False, True):
            out = redact.redact_text(line, [], redact.TokenMap(),
                                     defaultdict(int), ocr=ocr)
            assert out == want, (line, ocr)
            assert not redact.audit_text(out, [], ocr=ocr)[0], (line, ocr)


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
    # text-layer extracts do not get the edge rule: a comma-less city merged
    # into other wording is left to the sweep; the whole-line rule still fires
    plain_merged = "IMPORTANT TAX RETURN DOCUMENT ENCLOSED  SAMPLETOWN CA 90000"
    assert run_text(plain_merged)[0] == plain_merged
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


def test_first_and_last_name_apart_on_one_line():
    entries = redact.load_list(TESTDATA / "redaction_list.txt")

    def red(text):
        out, _ = run_text(text, entries)
        assert not redact.audit_text(out, entries)[0], text
        return out
    assert (red("First name JOHN Middle initial A Last name SAMPLE")
            == "First name [NAME-1] Middle initial A Last name [NAME-1]")
    assert (red("First name John A. Last name Sample Suffix")
            == "First name [NAME-1] Last name [NAME-1] Suffix")
    assert red("Last SAMPLE First JOHN") == "Last [NAME-1] First [NAME-1]"
    # a shared last name: both first names go, each under its own token
    # (JANE SAMPLE matches as a full name first, so it takes the first token)
    assert red("JOHN & JANE SAMPLE") == "[NAME-2] & [NAME-1]"
    assert (red("First JOHN Spouse JANE Last SAMPLE")
            == "First [NAME-1] Spouse [NAME-2] Last [NAME-1]")
    # one part alone is left: many names are ordinary words
    for line in ("JOHN called on Monday", "SAMPLE of the product"):
        assert red(line) == line


def test_list_matching_case_and_whitespace_insensitive():
    entries = redact.load_list(TESTDATA / "redaction_list.txt")
    out, f = run_text("employee: John  A  Sample of ACME WIDGETS INC", entries)
    assert "Sample" not in out and "ACME" not in out
    assert "[NAME-1]" in out and "[EMPLOYER-1]" in out
    assert any(reason == "[LIST:name]" for reason, _, _ in f)


def test_unknown_list_prefix_is_redacted_as_name_and_reported(tmp_path):
    lst = tmp_path / "redaction_list.txt"
    lst.write_text("# comment\ntrust: SAMPLE FAMILY TRUST\nname: JOHN A SAMPLE\n")
    entries = redact.load_list(lst)
    assert ("name", "SAMPLE FAMILY TRUST") in {(e[0], e[1]) for e in entries}
    # reported by line number only
    assert redact.list_unknown_prefixes(lst) == [2]
    from reportlab.pdfgen import canvas
    c = canvas.Canvas(str(tmp_path / "trust-fake.pdf"))
    c.drawString(72, 720, "*** FAKE TEST DOCUMENT - ALL VALUES FABRICATED ***")
    c.drawString(72, 700, "ACCOUNT OWNER SAMPLE FAMILY TRUST")
    c.save()
    proc = run_script(tmp_path, "--yes", "--no-ocr")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    line = next(l for l in proc.stdout.splitlines() if "UNKNOWN LIST PREFIX" in l)
    assert "redaction list line(s) 2" in line and "trust" not in line.lower()
    assert "ACCOUNT OWNER [NAME-" in (tmp_path / "redacted" / "trust-fake.txt").read_text()


def test_ssn_list_entry(tmp_path):
    lst = tmp_path / "redaction_list.txt"
    lst.write_text("social: 987-65-4321\nssn: 123 45 6789\n")
    entries = redact.load_list(lst)
    assert {e[0] for e in entries} == {"ssn"}
    assert redact.list_unknown_prefixes(lst) == []
    # any grouping, including bare digits on an unlabeled line
    out, _ = run_text("REF 987654321 and 987 65 4321 and 123-45-6789", entries)
    assert out == "REF [SSN-1] and [SSN-1] and [SSN-2]"
    # only masked forms in the documents: tail and mask share the listed token
    from reportlab.pdfgen import canvas
    c = canvas.Canvas(str(tmp_path / "masked-fake.pdf"))
    for y, text in ((720, "*** FAKE TEST DOCUMENT - ALL VALUES FABRICATED ***"),
                    (700, "RECIPIENT TIN XXX-XX-4321"),
                    (680, "COPY B FOR -4321 RECORDS"),
                    (660, "OTHER TIN XXX-XX-9999")):
        c.drawString(72, y, text)
    c.save()
    proc = run_script(tmp_path, "--yes", "--no-ocr")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    txt = (tmp_path / "redacted" / "masked-fake.txt").read_text()
    assert "RECIPIENT TIN [SSN-1]" in txt and "COPY B FOR [SSN-1] RECORDS" in txt
    assert "OTHER TIN [SSN-2]" in txt


def test_address_list_entry_ignores_punctuation_and_spacing(tmp_path):
    lst = tmp_path / "redaction_list.txt"
    lst.write_text("address: 77 QUIET HOLLOW, SAMPLETOWN, CA 90000\n")
    entries = redact.load_list(lst)
    assert {e[0] for e in entries} == {"addr"}
    assert redact.list_unknown_prefixes(lst) == []
    for line in ("77 QUIET HOLLOW, SAMPLETOWN, CA 90000",
                 "77 QUIET HOLLOW     SAMPLETOWN     CA 90000",
                 "77 Quiet Hollow,Sampletown,CA 90000"):
        assert run_text(f"MAIL {line} END", entries)[0] == "MAIL [ADDR-1] END", line


def test_address_list_entry_matches_either_suffix_spelling(tmp_path):
    # the list says DRIVE, the form says DR (or DR., or OCR-glued): same address
    lst = tmp_path / "redaction_list.txt"
    lst.write_text("addr: 500 INDUSTRY DRIVE, SAMPLETOWN, CA 90001\n")
    entries = redact.load_list(lst)
    for line in ("500 INDUSTRY DRIVE, SAMPLETOWN, CA 90001",
                 "500 INDUSTRY DR, SAMPLETOWN, CA 90001",
                 "500 Industry Dr. Sampletown CA 90001"):
        assert run_text(f"MAIL {line} END", entries)[0] == "MAIL [ADDR-1] END", line
    glued = redact.redact_text("500INDUSTRYDR,SAMPLETOWN,CA90001", entries,
                               redact.TokenMap(), defaultdict(int), ocr=True)
    assert glued == "[ADDR-1]"
    # a different house number, and a word that merely starts with the
    # suffix, are not the listed street (the generic ADDR pattern may still
    # box the line, but not on the list entry's account)
    for line in ("501 INDUSTRY DR", "500 INDUSTRY DRIVER"):
        _out, findings = run_text(line, entries)
        assert not any(reason.startswith("[LIST:") for reason, _o, _t in findings), line
    # reverse direction, directionals and unit words
    lst.write_text("addr: 12 N MAIN ST APT 4\n")
    entries = redact.load_list(lst)
    for line in ("12 N MAIN ST APT 4", "12 NORTH MAIN STREET APARTMENT 4",
                 "12 N. Main St., Apt. 4"):
        assert run_text(f"AT {line} END", entries)[0] == "AT [ADDR-1] END", line


def test_address_list_entry_matches_split_lines(tmp_path):
    # forms print the street on one line and city/state/ZIP on the next; an
    # OCR row may glue the street to unrelated fragments. Both halves of a
    # full entry match on their own, under the entry's one token.
    lst = tmp_path / "redaction_list.txt"
    for entry in ("addr: 500 INDUSTRY DRIVE, SAMPLETOWN, CA 90001",
                  "addr: 500 INDUSTRY DRIVE SAMPLETOWN CA 90001"):
        lst.write_text(entry + "\n")
        entries = redact.load_list(lst)
        tokens = redact.TokenMap()
        text = ("[ACCT-...5678]-XX00  500INDUSTRYDR  Return file date:  10/7/2026\n"
                "SAMPLETOWN,CA90001\n"
                "500 INDUSTRY DRIVE, SAMPLETOWN, CA 90001")
        out = redact.redact_text(text, entries, tokens, defaultdict(int), ocr=True)
        assert out.splitlines() == [
            "[ACCT-...5678]-XX00  [ADDR-1]  Return file date:  10/7/2026",
            "[ADDR-1]", "[ADDR-1]"], entry
    # a unit after the street stays with the street half
    assert list(redact._addr_variants("123 MAIN DR, APT 4, SAMPLETOWN, CA 90000")) == [
        "123 MAIN DR, APT 4, SAMPLETOWN, CA 90000", "123 MAIN DR, APT 4", "SAMPLETOWN, CA 90000"]
    assert list(redact._addr_variants("123 MAIN DR APT 4 SAMPLETOWN CA 90000")) == [
        "123 MAIN DR APT 4 SAMPLETOWN CA 90000", "123 MAIN DR APT 4", "SAMPLETOWN CA 90000"]
    lst.write_text("addr: 123 MAIN DR, APT 4, SAMPLETOWN, CA 90000\n")
    entries = redact.load_list(lst)
    tokens = redact.TokenMap()
    out = redact.redact_text("AT 123 Main Dr Apt 4\nIN Sampletown CA 90000", entries,
                             tokens, defaultdict(int))
    assert out == "AT [ADDR-1]\nIN [ADDR-1]"
    # no comma and no recognisable suffix, or a street-only entry: no split
    assert list(redact._addr_variants("77 QUIET HOLLOW SAMPLETOWN CA 90000")) == [
        "77 QUIET HOLLOW SAMPLETOWN CA 90000"]
    assert list(redact._addr_variants("500 INDUSTRY DRIVE")) == ["500 INDUSTRY DRIVE"]
    assert list(redact._addr_variants("500 INDUSTRY DRIVE, SAMPLETOWN")) == [
        "500 INDUSTRY DRIVE, SAMPLETOWN"]


def test_address_filed_as_a_name_is_not_split(tmp_path):
    # the first-and-last-name rule must not treat a street number and a ZIP
    # as someone's first and last name
    lst = tmp_path / "redaction_list.txt"
    lst.write_text("name: 77 QUIET HOLLOW, SAMPLETOWN, CA 90000\n"
                   "home: 78 QUIET HOLLOW, SAMPLETOWN, CA 90001\n")
    entries = redact.load_list(lst)
    for line in ("77 QUIET HOLLOW     SAMPLETOWN     CA 90000",
                 "78 QUIET HOLLOW     SAMPLETOWN     CA 90001"):
        out, _ = run_text(line, entries)
        assert "[NAME-" not in out, line


def test_email_list_entry(tmp_path):
    lst = tmp_path / "redaction_list.txt"
    lst.write_text("email: john.sample@example.com\n")
    entries = redact.load_list(lst)
    assert redact.list_unknown_prefixes(lst) == []
    # listed and pattern-found addresses use the same EMAIL tokens
    out, _ = run_text("CONTACT John.Sample@Example.com OR jane@example.org", entries)
    assert out == "CONTACT [EMAIL-1] OR [EMAIL-2]"
    assert run_text("CONTACT john.sample@example.com")[0] == "CONTACT [EMAIL-1]"


def test_dob_id_phone_list_entries(tmp_path):
    lst = tmp_path / "redaction_list.txt"
    lst.write_text("dob: 01/02/1980\nid: D1234567\nphone: (555) 010-0199\n"
                   "dob: September 30, 1975\nphone: 555-0142\n")
    entries = redact.load_list(lst)
    assert redact.list_unknown_prefixes(lst) == []

    def red(text):
        return run_text(text, entries)[0]
    # no DOB / license label on any of these lines
    for form in ("01/02/1980", "1/2/1980", "1-2-80", "01.02.1980", "1980-01-02",
                 "January 2, 1980", "JAN 2 1980", "Jan. 2nd, 1980", "2 January 1980"):
        assert red(f"SEEN {form} HERE") == "SEEN [DOB-1] HERE", form
    for form in ("9/30/1975", "Sept 30, 1975", "1975-09-30"):
        assert red(f"SEEN {form} HERE") == "SEEN [DOB-1] HERE", form
    for other in ("01/02/1981", "11/02/1980", "01/02/19801", "2/1/1980",
                  "January 12, 1980", "PAID 1/2/8012"):
        assert red(f"SEEN {other} HERE") == f"SEEN {other} HERE", other
    assert red("REF D1234567 X") == "REF [ID-1] X"
    assert red("REF D12345678 X") == "REF D[ACCT-...5678] X"   # not the listed ID
    for form in ("(555) 010-0199", "555-010-0199", "555.010.0199", "5550100199",
                 "1-555-010-0199", "+1 555 010 0199"):
        assert red(f"CALL {form} NOW") == "CALL [PHONE-1] NOW", form
    assert red("CALL 555-0142 NOW") == "CALL [PHONE-1] NOW"
    assert red("CALL 555 0142 NOW") == "CALL [PHONE-1] NOW"
    assert red("TOTAL 15550142 NOW") != "TOTAL [PHONE-1] NOW"


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
    # A text-layer PDF: a city/state/zip that is in no list entry (a listed
    # address's city line would be matched by the entry's locality half),
    # once on its own line (found by the whole-line rule) and once merged
    # into other wording (found by nothing but the sweep: --no-ocr keeps the
    # OCR edge rule out of play, and with no comma and a 5-digit ZIP the
    # in-line city rule does not apply).
    from reportlab.pdfgen import canvas
    c = canvas.Canvas(str(workdir / "envelope-fake.pdf"))
    c.drawString(72, 720, "*** FAKE TEST DOCUMENT - ALL VALUES FABRICATED ***")
    c.drawString(72, 700, "OTHERTOWN CA 90002")
    c.drawString(72, 680, "IMPORTANT TAX RETURN DOCUMENT ENCLOSED OTHERTOWN CA 90002")
    c.save()
    proc = run_script(workdir, "--yes", "--no-ocr")
    assert proc.returncode == 0, proc.stderr
    assert "[SWEEP:ADDR]" in proc.stdout
    out = workdir / "redacted"
    txt = (out / "envelope-fake.txt").read_text()
    assert "OTHERTOWN" not in txt and "90002" not in txt
    assert "IMPORTANT TAX RETURN DOCUMENT ENCLOSED [ADDR-" in txt
    pdf_text = redact.extract_pdf_text(out / "envelope-fake.redacted.pdf")
    assert "OTHERTOWN" not in pdf_text and "90002" not in pdf_text


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


def _rotated_pdf(path, rotation):
    """A page stored sideways and shown upright via /Rotate, as scanners and
    payroll exports produce."""
    import pymupdf
    doc = pymupdf.open()
    page = doc.new_page()
    page.set_rotation(rotation)
    for y, line in ((72, "EMPLOYEE JOHN A SAMPLE SSN 987-65-4321 WAGES 1,000.00"),
                    (100, "12bAA  9477.36  1234 EXAMPLE STREET")):
        page.insert_text(pymupdf.Point(72, y) * page.derotation_matrix, line,
                         rotate=rotation)
    doc.save(str(path))
    doc.close()


@pytest.mark.parametrize("rotation", [90, 180, 270])
def test_rotated_pages_are_unrotated_and_redacted(tmp_path, rotation):
    import pymupdf
    src = tmp_path / "rotated-fake.pdf"
    _rotated_pdf(src, rotation)
    (tmp_path / "redaction_list.txt").write_text("name: JOHN A SAMPLE\n")
    before = src.read_bytes()
    proc = run_script(tmp_path, "--yes", "--no-ocr")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "ROTATION REMOVED: rotated-fake.pdf had 1 rotated page(s)" in proc.stdout
    assert "PDF SKIPPED" not in proc.stdout
    out = tmp_path / "redacted"
    pdf_text = redact.extract_pdf_text(out / "rotated-fake.redacted.pdf")
    for text in ((out / "rotated-fake.txt").read_text(), pdf_text):
        assert "[NAME-1]" in text and "[SSN-" in text and "[ADDR-" in text
        assert "WAGES 1,000.00" in text and "9477.36" in text
        for leak in ("SAMPLE", "987-65-4321", "EXAMPLE STREET"):
            assert leak not in text
    doc = pymupdf.open(str(out / "rotated-fake.redacted.pdf"))
    assert doc[0].rotation == 0
    # same visible page size as the rotated source
    assert tuple(doc[0].rect) == tuple(pymupdf.open(str(src))[0].rect)
    doc.close()
    # source untouched, and no unrotated copy left anywhere
    assert src.read_bytes() == before
    assert sorted(p.name for p in tmp_path.iterdir()) == [
        "redacted", "redaction_list.txt", "rotated-fake.pdf"]
    assert run_script(out, "--audit").returncode == 0


@pytest.mark.parametrize("noise", [
    b"-0.00001 1 -1 0.00001 0 0 cm", b"0.00001 1 -1 -0.00001 0 0 cm"])
def test_rotation_noise_does_not_make_text_sideways(tmp_path, noise):
    # a rotation written with +/-1e-5 instead of 0 made pdfminer flag every
    # character as sideways; the lines came out as interleaved letters
    import pymupdf
    lines = ["FAKE TEST DOCUMENT ALL VALUES FABRICATED",
             "Bay H1A, Sampletown Industrial, Estate,",
             "Samplecity, V14 FX94, Fakeland", "EMPLOYEE SSN 987-65-4321"]
    doc = pymupdf.open()
    page = doc.new_page()
    page.set_rotation(90)
    for i, text in enumerate(lines):
        page.insert_text(pymupdf.Point(72, 72 + 13 * i) * page.derotation_matrix,
                         text, rotate=90, fontsize=11)
    for xref in page.get_contents():
        stream = doc.xref_stream(xref)
        assert b"0 1 -1 0 0 0 cm" in stream
        doc.update_stream(xref, stream.replace(b"0 1 -1 0 0 0 cm", noise))
    doc.save(str(tmp_path / "noise-fake.pdf"))
    doc.close()
    proc = run_script(tmp_path, "--yes", "--no-ocr")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    want = lines[:3] + ["EMPLOYEE SSN [SSN-1]"]
    out = tmp_path / "redacted"
    assert (out / "noise-fake.txt").read_text().splitlines()[-4:] == want
    pdf_text = redact.extract_pdf_text(out / "noise-fake.redacted.pdf")
    assert pdf_text.splitlines()[-4:] == want


def test_unrotate_leaves_plain_pdf_alone(workdir):
    assert redact.unrotate_pdf(workdir / "w2-fake.pdf") is None


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


def test_form_wording_is_not_suggested():
    text = "\n".join([
        "COPY B FOR RECIPIENT",
        "INSTRUCTIONS FOR RECIPIENTS OF FORM 1099",
        "RECIPIENT: KEEP FOR YOUR RECORDS",
        "THIS IS YOUR FORM RECIPIENT",
        "IRS FATCA FILING REQUIREMENT RECIPIENT",
        "DEPARTMENT OF THE TREASURY RECIPIENT COPY",
        "SALE ELECTION UNDER SECTION 754 PER TREAS REG 1.754 PARTNER NAME",
        "PTE FEIN 12-3456789 TAXPAYER COPY",
        "TOTAL WAGES ACME HOLDINGS GROUP PAID TO EMPLOYEE",
        "RECIPIENT NAME: JOHN A SAMPLE",
        "PAYER: FIRST FEDERAL CREDIT UNION",
        "PAYER: BANK OF EXAMPLE",
    ])
    assert redact.suggest_entries({"x.pdf": text}, []) == [
        "name: JOHN A SAMPLE", "employer: FIRST FEDERAL CREDIT UNION",
        "employer: BANK OF EXAMPLE"]


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


def _image_only_pdf(path, n_pages):
    """A PDF of n_pages blank white photos and no text layer, like a phone scan."""
    from PIL import Image
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.utils import ImageReader
    from reportlab.pdfgen import canvas
    c = canvas.Canvas(str(path), pagesize=letter)
    for _ in range(n_pages):
        c.drawImage(ImageReader(Image.new("RGB", (850, 1100), "white")),
                    0, 0, width=letter[0], height=letter[1])
        c.showPage()
    c.save()


def test_page_text_chars_ignores_page_separators():
    five_blank_pages = [[("", [])] for _ in range(5)]
    assert len(redact.pages_to_text(five_blank_pages).strip()) >= redact.MIN_TEXT_CHARS
    assert redact.page_text_chars(five_blank_pages) == 0
    assert redact.page_text_chars([[("abc", [None] * 3), ("  d ", [None] * 4)]]) == 4


def test_multipage_scan_is_detected_as_needing_ocr(tmp_path):
    # Regression: a 5-page image-only PDF (phone scan) used to pass the
    # text-layer check on the strength of its PAGE_SEP lines alone, so OCR
    # never ran and nothing was redacted.
    _image_only_pdf(tmp_path / "phone-scan.pdf", 5)
    shutil.copy(TESTDATA / "redaction_list.txt", tmp_path)
    proc = run_script(tmp_path, "--preview", "--no-ocr")
    assert proc.returncode == 0, proc.stderr
    assert "NEEDS OCR" in proc.stdout
    assert "0 planned redaction" in proc.stdout


def test_ocr_render_scale_is_capped_for_oversized_pages():
    assert redact._ocr_scale(612, 792) == pytest.approx(300 / 72)
    # a phone scan stored at its pixel size renders no larger than a letter
    # page at 300 DPI
    scale = redact._ocr_scale(1993, 2562)
    assert 2562 * scale == pytest.approx(redact._OCR_MAX_SIDE)
    assert scale < 300 / 72
