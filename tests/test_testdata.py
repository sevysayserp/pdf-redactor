"""Sanity checks on the generated fake document set in testdata/."""

from pathlib import Path

import pdfplumber
import pytest

TESTDATA = Path(__file__).resolve().parents[1] / "testdata"

EXPECTED_PDFS = [
    "w2-fake.pdf",
    "1099int-fake.pdf",
    "1099div-fake.pdf",
    "1099b-fake.pdf",
    "bankstmt-fake.pdf",
    "return-fake.pdf",
]


def extract_text(name):
    with pdfplumber.open(TESTDATA / name) as pdf:
        return "\n".join(page.extract_text() or "" for page in pdf.pages)


@pytest.mark.parametrize("name", EXPECTED_PDFS)
def test_pdf_exists_and_has_text(name):
    assert (TESTDATA / name).exists(), f"missing {name} — run make_testdata.py"
    text = extract_text(name)
    assert len(text) > 100, f"{name} yielded no extractable text"
    assert "FAKE" in text, f"{name} must be marked as a fake document"


def test_scanned_pdf_has_no_text_layer():
    # scanned-fake.pdf exists to exercise the OCR path; if it ever gains a
    # text layer, the OCR tests silently stop testing OCR.
    assert (TESTDATA / "scanned-fake.pdf").exists()
    assert len(extract_text("scanned-fake.pdf").strip()) < 20


def test_fake_ssn_present_in_raw_testdata():
    # The raw fakes DO contain the fake SSN; the redaction tests assert it is
    # absent from every output. This pins the precondition.
    assert "123-45-6789" in extract_text("w2-fake.pdf")
