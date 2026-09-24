#!/usr/bin/env python3
"""Generate the FAKE document set in testdata/ used by the redactor's tests.

Every value here is fabricated (SSN 123-45-6789, JOHN A SAMPLE, ACME WIDGETS
INC, ...). The set covers the document shapes the redactor is built for: a
W-2, a 1099-INT, a consolidated-style 1099-DIV, a 1099-B, a bank statement
(DOB, driver's license, routing number, PO Box, two-line address), an
image-only "scanned" letter for the OCR path, and a multi-page prepared tax
return (federal 1040 + schedules + a state return) that repeats the same
identities so cross-document token stability can be tested.

Usage:
    python make_testdata.py [--filing-status {mfj,single}] [--out testdata]

The return's numbers are only meant to look plausible (they carry a few
deliberate inconsistencies inherited from the project this generator came
from); nothing here is tax advice or a real computation.
"""

import argparse
from pathlib import Path

from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

TAX_YEAR = 2025

PEOPLE = {
    "mfj": {
        "taxpayer": ("JOHN A SAMPLE", "123-45-6789"),
        "spouse": ("JANE B SAMPLE", "987-65-4321"),
        "filing_status_label": "Married filing jointly",
        "std_deduction": 30_000,
        "ca_std_deduction": 11_080,
    },
    "single": {
        "taxpayer": ("JOHN A SAMPLE", "123-45-6789"),
        "spouse": None,
        "filing_status_label": "Single",
        "std_deduction": 15_000,
        "ca_std_deduction": 5_540,
    },
}

ADDRESS = "1234 EXAMPLE STREET, SAMPLETOWN, CA 90000"

# ---------------------------------------------------------------- source facts
W2 = {
    "employer": "ACME WIDGETS INC",
    "employer_ein": "12-3456789",
    "employer_addr": "500 INDUSTRY WAY, SAMPLETOWN, CA 90001",
    "box1_wages": 120_450.00,
    "box2_fed_wh": 18_000.00,
    "box3_ss_wages": 120_450.00,
    "box4_ss_tax": 7_467.90,
    "box5_medicare_wages": 120_450.00,
    "box6_medicare_tax": 1_746.53,
    "box15_state": "CA 999-9999-9",
    "box16_state_wages": 120_450.00,
    "box17_state_tax": 7_000.00,
}

INT_1099 = {
    "payer": "FIRST EXAMPLE BANK",
    "payer_tin": "98-7654321",
    "account": "00012345678",
    "box1_interest": 850.00,
    "box3_treasury": 1_200.00,
    "box4_fed_wh": 0.00,
}

DIV_1099 = {
    "payer": "EXAMPLE BROKERAGE LLC",
    "payer_tin": "45-6789012",
    "account": "98765432",
    "box1a_ordinary": 4_000.00,
    "box1b_qualified": 3_000.00,
    "box2a_cap_gain": 500.00,
    "box5_199a": 200.00,
    "box7_foreign_tax": 150.00,
    "box12_exempt_interest": 2_000.00,
    "box13_pab_interest": 100.00,
    "exempt_ca_pct": 60,  # supplemental info: CA vs other-state muni split
}

B_1099_LOTS = [
    # (description, acquired, sold, proceeds, basis, wash_sale_disallowed, term)
    ("100 SH XYZ CORP", "03/15/2025", "06/20/2025", 5_000.00, 5_500.00, 500.00, "SHORT"),
    ("50 SH ABC INC", "01/10/2025", "08/05/2025", 3_000.00, 2_500.00, 0.00, "SHORT"),
    ("200 SH DEF FUND", "02/01/2020", "09/15/2025", 12_000.00, 8_000.00, 0.00, "LONG"),
]

# Deliberate inconsistency: Schedule B lists this payer but no 1099-INT exists.
PHANTOM_INT_PAYER = ("SECOND NATIONAL BANK", 300.00)

# Non-tax documents exercising the redaction patterns (DOB, driver's license,
# routing number, PO Box, two-line address, OCR). Deliberately carry no tax
# amounts, so the return's totals are unaffected.
BANK_STMT = {
    "institution": "EXAMPLE CREDIT UNION",
    "dob": "03/15/1980",
    "dl": "A1234567",
    "routing": "121099999",
    "account": "00012345678",
    "balance": 12_345.67,
}


def fmt(x):
    return f"{x:,.2f}"


def approx_ordinary_tax(taxable, status):
    """Very approximate 2025 federal brackets — plausibility only."""
    brackets = {
        "mfj": [(0, 0.10), (23_850, 0.12), (96_950, 0.22), (206_700, 0.24)],
        "single": [(0, 0.10), (11_925, 0.12), (48_475, 0.22), (103_350, 0.24)],
    }[status]
    tax = 0.0
    edges = brackets + [(float("inf"), None)]
    for (lo, rate), (hi, _) in zip(edges, edges[1:]):
        if taxable > lo:
            tax += (min(taxable, hi) - lo) * rate
    return round(tax)


def approx_ca_tax(taxable, status):
    """Very approximate 2025 CA brackets — plausibility only."""
    single = [(0, 0.01), (10_756, 0.02), (25_499, 0.04), (40_245, 0.06),
              (55_866, 0.08), (70_606, 0.093)]
    brackets = ([(lo * 2, r) for lo, r in single] if status == "mfj" else single)
    tax = 0.0
    edges = brackets + [(float("inf"), None)]
    for (lo, rate), (hi, _) in zip(edges, edges[1:]):
        if taxable > lo:
            tax += (min(taxable, hi) - lo) * rate
    return round(tax)


def compute_return(status):
    """The preparer's (deliberately flawed) numbers, internally consistent."""
    p = PEOPLE[status]
    r = {}
    r["1a_wages"] = 120_540.00            # ERROR 1: transposed digit (true 120,450)
    r["2a_tax_exempt"] = DIV_1099["box12_exempt_interest"]
    r["2b_interest"] = (INT_1099["box1_interest"] + INT_1099["box3_treasury"]
                        + PHANTOM_INT_PAYER[1])
    r["3a_qualified"] = 2_000.00          # ERROR 3: true 3,000 (1099-DIV box 1b)
    r["3b_ordinary"] = DIV_1099["box1a_ordinary"]

    st_gain = sum(pr - b for _, _, _, pr, b, _, t in B_1099_LOTS if t == "SHORT")
    lt_gain = sum(pr - b for _, _, _, pr, b, _, t in B_1099_LOTS if t == "LONG")
    # ERROR 5: wash-sale loss NOT disallowed — preparer nets the full ST loss.
    r["schD_st"] = st_gain                # 0.00 as filed; correct is +500
    r["schD_lt"] = lt_gain + DIV_1099["box2a_cap_gain"]
    r["7_cap_gain"] = r["schD_st"] + r["schD_lt"]

    r["9_total_income"] = (r["1a_wages"] + r["2b_interest"] + r["3b_ordinary"]
                           + r["7_cap_gain"])
    r["11_agi"] = r["9_total_income"]
    r["12_std_ded"] = float(p["std_deduction"])
    r["15_taxable"] = r["11_agi"] - r["12_std_ded"]

    pref = r["3a_qualified"] + r["schD_lt"]  # QDCGT-worksheet-style split
    r["16_tax"] = approx_ordinary_tax(r["15_taxable"] - pref, status) + round(pref * 0.15)
    # ERROR 6: foreign tax credit omitted — no Schedule 3, line 20 = 0.
    r["22_after_credits"] = r["16_tax"]
    r["24_total_tax"] = r["16_tax"]
    r["25a_wh"] = W2["box2_fed_wh"]
    r["33_payments"] = r["25a_wh"]
    r["34_refund"] = r["33_payments"] - r["24_total_tax"]

    # California
    r["ca_fed_agi"] = r["11_agi"]
    # ERROR 2: no Schedule CA subtraction for Treasury interest (should be 1,200).
    # ERROR 7: no Schedule CA addition for non-CA muni interest (should be 800).
    r["ca_agi"] = r["ca_fed_agi"]
    r["ca_std_ded"] = float(p["ca_std_deduction"])
    r["ca_taxable"] = r["ca_agi"] - r["ca_std_ded"]
    r["ca_tax"] = approx_ca_tax(r["ca_taxable"], status)
    r["ca_wh"] = W2["box17_state_tax"]
    r["ca_refund"] = r["ca_wh"] - r["ca_tax"]
    return r


# ---------------------------------------------------------------- PDF plumbing
class Doc:
    def __init__(self, path):
        self.c = canvas.Canvas(str(path), pagesize=letter)
        self.y = 750

    def line(self, text, indent=72, bold=False, size=10):
        if self.y < 60:
            self.c.showPage()
            self.y = 750
        self.c.setFont("Helvetica-Bold" if bold else "Helvetica", size)
        self.c.drawString(indent, self.y, text)
        self.y -= 14 if size <= 10 else 20

    def kv(self, label, value):
        self.line(f"{label}: {value}")

    def gap(self):
        self.y -= 10

    def save(self):
        self.c.save()


def recipient_lines(d, status):
    p = PEOPLE[status]
    name = p["taxpayer"][0]
    if p["spouse"]:
        name += f" & {p['spouse'][0]}"
    d.kv("RECIPIENT", name)
    d.kv("RECIPIENT TIN", p["taxpayer"][1])
    d.kv("RECIPIENT ADDRESS", ADDRESS)


def make_w2(path, status):
    p = PEOPLE[status]
    d = Doc(path)
    d.line(f"FORM W-2  WAGE AND TAX STATEMENT  {TAX_YEAR}", bold=True, size=14)
    d.line("*** FAKE TEST DOCUMENT — ALL VALUES FABRICATED ***", bold=True)
    d.gap()
    d.kv("EMPLOYER", W2["employer"])
    d.kv("EMPLOYER EIN", W2["employer_ein"])
    d.kv("EMPLOYER ADDRESS", W2["employer_addr"])
    d.kv("EMPLOYEE", p["taxpayer"][0])
    d.kv("EMPLOYEE SSN", p["taxpayer"][1])
    d.kv("EMPLOYEE ADDRESS", ADDRESS)
    d.gap()
    d.kv("BOX 1  WAGES, TIPS, OTHER COMPENSATION", fmt(W2["box1_wages"]))
    d.kv("BOX 2  FEDERAL INCOME TAX WITHHELD", fmt(W2["box2_fed_wh"]))
    d.kv("BOX 3  SOCIAL SECURITY WAGES", fmt(W2["box3_ss_wages"]))
    d.kv("BOX 4  SOCIAL SECURITY TAX WITHHELD", fmt(W2["box4_ss_tax"]))
    d.kv("BOX 5  MEDICARE WAGES AND TIPS", fmt(W2["box5_medicare_wages"]))
    d.kv("BOX 6  MEDICARE TAX WITHHELD", fmt(W2["box6_medicare_tax"]))
    d.kv("BOX 15 STATE / EMPLOYER STATE ID", W2["box15_state"])
    d.kv("BOX 16 STATE WAGES", fmt(W2["box16_state_wages"]))
    d.kv("BOX 17 STATE INCOME TAX", fmt(W2["box17_state_tax"]))
    d.save()


def make_1099int(path, status):
    d = Doc(path)
    d.line(f"FORM 1099-INT  INTEREST INCOME  {TAX_YEAR}", bold=True, size=14)
    d.line("*** FAKE TEST DOCUMENT — ALL VALUES FABRICATED ***", bold=True)
    d.gap()
    d.kv("PAYER", INT_1099["payer"])
    d.kv("PAYER TIN", INT_1099["payer_tin"])
    d.kv("ACCOUNT NUMBER", INT_1099["account"])
    recipient_lines(d, status)
    d.gap()
    d.kv("BOX 1  INTEREST INCOME", fmt(INT_1099["box1_interest"]))
    d.kv("BOX 3  INTEREST ON U.S. SAVINGS BONDS AND TREASURY OBLIGATIONS",
         fmt(INT_1099["box3_treasury"]))
    d.kv("BOX 4  FEDERAL INCOME TAX WITHHELD", fmt(INT_1099["box4_fed_wh"]))
    d.save()


def make_1099div(path, status):
    d = Doc(path)
    d.line(f"FORM 1099-DIV  DIVIDENDS AND DISTRIBUTIONS  {TAX_YEAR}", bold=True, size=14)
    d.line("*** FAKE TEST DOCUMENT — ALL VALUES FABRICATED ***", bold=True)
    d.gap()
    d.kv("PAYER", DIV_1099["payer"])
    d.kv("PAYER TIN", DIV_1099["payer_tin"])
    d.kv("ACCOUNT NUMBER", DIV_1099["account"])
    recipient_lines(d, status)
    d.gap()
    d.kv("BOX 1a  TOTAL ORDINARY DIVIDENDS", fmt(DIV_1099["box1a_ordinary"]))
    d.kv("BOX 1b  QUALIFIED DIVIDENDS", fmt(DIV_1099["box1b_qualified"]))
    d.kv("BOX 2a  TOTAL CAPITAL GAIN DISTRIBUTIONS", fmt(DIV_1099["box2a_cap_gain"]))
    d.kv("BOX 4   FEDERAL INCOME TAX WITHHELD", fmt(0))
    d.kv("BOX 5   SECTION 199A DIVIDENDS", fmt(DIV_1099["box5_199a"]))
    d.kv("BOX 7   FOREIGN TAX PAID", fmt(DIV_1099["box7_foreign_tax"]))
    d.kv("BOX 12  EXEMPT-INTEREST DIVIDENDS", fmt(DIV_1099["box12_exempt_interest"]))
    d.kv("BOX 13  SPECIFIED PRIVATE ACTIVITY BOND INTEREST DIVIDENDS",
         fmt(DIV_1099["box13_pab_interest"]))
    d.gap()
    d.line("SUPPLEMENTAL INFORMATION (NOT REPORTED TO IRS)", bold=True)
    ca = DIV_1099["exempt_ca_pct"]
    amt = DIV_1099["box12_exempt_interest"]
    d.kv(f"EXEMPT-INTEREST DIVIDENDS SOURCED TO CALIFORNIA ({ca}%)",
         fmt(amt * ca / 100))
    d.kv(f"EXEMPT-INTEREST DIVIDENDS SOURCED TO OTHER STATES ({100-ca}%)",
         fmt(amt * (100 - ca) / 100))
    d.save()


def make_1099b(path, status):
    d = Doc(path)
    d.line(f"FORM 1099-B  PROCEEDS FROM BROKER TRANSACTIONS  {TAX_YEAR}", bold=True, size=14)
    d.line("*** FAKE TEST DOCUMENT — ALL VALUES FABRICATED ***", bold=True)
    d.gap()
    d.kv("PAYER", DIV_1099["payer"])
    d.kv("PAYER TIN", DIV_1099["payer_tin"])
    d.kv("ACCOUNT NUMBER", DIV_1099["account"])
    recipient_lines(d, status)
    for desc, acq, sold, proceeds, basis, wash, term in B_1099_LOTS:
        d.gap()
        d.kv("BOX 1a  DESCRIPTION", desc)
        d.kv("BOX 1b  DATE ACQUIRED", acq)
        d.kv("BOX 1c  DATE SOLD", sold)
        d.kv("BOX 1d  PROCEEDS", fmt(proceeds))
        d.kv("BOX 1e  COST OR OTHER BASIS", fmt(basis))
        if wash:
            d.kv("BOX 1g  WASH SALE LOSS DISALLOWED", fmt(wash))
        d.kv("TERM", f"{term}-TERM (BASIS REPORTED TO IRS)")
    d.save()


def make_bankstmt(path, status):
    p = PEOPLE[status]
    d = Doc(path)
    d.line(f"{BANK_STMT['institution']} — ACCOUNT STATEMENT  DECEMBER {TAX_YEAR}",
           bold=True, size=14)
    d.line("*** FAKE TEST DOCUMENT — ALL VALUES FABRICATED ***", bold=True)
    d.gap()
    d.kv("CUSTOMER", p["taxpayer"][0])
    d.kv("DATE OF BIRTH", BANK_STMT["dob"])
    d.kv("DRIVER LICENSE NO", BANK_STMT["dl"])
    d.line("MAILING ADDRESS: P.O. BOX 4321")
    d.line("SAMPLETOWN, CA 90000")
    d.line("STREET ADDRESS: 1234 EXAMPLE STREET APT 12")
    d.gap()
    d.kv("ROUTING NUMBER (ABA)", BANK_STMT["routing"])
    d.kv("ACCOUNT NUMBER", BANK_STMT["account"])
    d.kv("ENDING BALANCE", fmt(BANK_STMT["balance"]))
    d.kv("CONTACT", "(555) 010-4321  support@example-cu.example")
    d.save()


def make_scanned(path, status):
    """An image-only PDF (no text layer) — exercises the --ocr path."""
    from PIL import Image, ImageDraw, ImageFont
    from reportlab.lib.utils import ImageReader

    p = PEOPLE[status]
    img = Image.new("RGB", (1700, 2200), "white")
    draw = ImageDraw.Draw(img)
    font = ImageFont.load_default(size=40)
    y = 150
    for text in [
        BANK_STMT["institution"],
        "ACCOUNT VERIFICATION LETTER (SCANNED COPY)",
        "*** FAKE TEST DOCUMENT - ALL VALUES FABRICATED ***",
        "",
        f"CUSTOMER: {p['taxpayer'][0]}",
        f"SSN: {p['taxpayer'][1]}",
        f"DATE OF BIRTH: {BANK_STMT['dob']}",
        f"ACCOUNT NUMBER: {BANK_STMT['account']}",
        "THIS LETTER CONFIRMS THE ACCOUNT ABOVE IS IN GOOD STANDING.",
    ]:
        draw.text((120, y), text, fill="black", font=font)
        y += 90
    c = canvas.Canvas(str(path), pagesize=letter)
    c.drawImage(ImageReader(img), 0, 0, width=letter[0], height=letter[1])
    c.showPage()
    c.save()


def make_return(path, status, r):
    p = PEOPLE[status]
    d = Doc(path)
    d.line(f"FORM 1040  U.S. INDIVIDUAL INCOME TAX RETURN  {TAX_YEAR}", bold=True, size=14)
    d.line("*** FAKE TEST DOCUMENT — ALL VALUES FABRICATED ***", bold=True)
    d.gap()
    d.kv("FILING STATUS", p["filing_status_label"])
    d.kv("TAXPAYER", f"{p['taxpayer'][0]}  SSN {p['taxpayer'][1]}")
    if p["spouse"]:
        d.kv("SPOUSE", f"{p['spouse'][0]}  SSN {p['spouse'][1]}")
    d.kv("HOME ADDRESS", ADDRESS)
    d.gap()
    d.kv("LINE 1a  TOTAL AMOUNT FROM FORM(S) W-2, BOX 1", fmt(r["1a_wages"]))
    d.kv("LINE 2a  TAX-EXEMPT INTEREST", fmt(r["2a_tax_exempt"]))
    d.kv("LINE 2b  TAXABLE INTEREST", fmt(r["2b_interest"]))
    d.kv("LINE 3a  QUALIFIED DIVIDENDS", fmt(r["3a_qualified"]))
    d.kv("LINE 3b  ORDINARY DIVIDENDS", fmt(r["3b_ordinary"]))
    d.kv("LINE 7   CAPITAL GAIN OR (LOSS), SCHEDULE D ATTACHED", fmt(r["7_cap_gain"]))
    d.kv("LINE 9   TOTAL INCOME", fmt(r["9_total_income"]))
    d.kv("LINE 11  ADJUSTED GROSS INCOME", fmt(r["11_agi"]))
    d.kv("LINE 12  STANDARD DEDUCTION", fmt(r["12_std_ded"]))
    d.kv("LINE 15  TAXABLE INCOME", fmt(r["15_taxable"]))
    d.kv("LINE 16  TAX (QUALIFIED DIV AND CAP GAIN TAX WORKSHEET)", fmt(r["16_tax"]))
    d.kv("LINE 20  SCHEDULE 3, LINE 8", fmt(0))
    d.kv("LINE 22  TAX AFTER CREDITS", fmt(r["22_after_credits"]))
    d.kv("LINE 24  TOTAL TAX", fmt(r["24_total_tax"]))
    d.kv("LINE 25a FEDERAL TAX WITHHELD FROM W-2", fmt(r["25a_wh"]))
    d.kv("LINE 25b FEDERAL TAX WITHHELD FROM 1099", fmt(0))
    d.kv("LINE 33  TOTAL PAYMENTS", fmt(r["33_payments"]))
    d.kv("LINE 34  OVERPAYMENT (REFUND)", fmt(r["34_refund"]))

    d.c.showPage(); d.y = 750
    d.line(f"SCHEDULE B  INTEREST AND ORDINARY DIVIDENDS  {TAX_YEAR}", bold=True, size=14)
    d.gap()
    d.line("PART I — INTEREST", bold=True)
    d.kv("  FIRST EXAMPLE BANK", fmt(INT_1099["box1_interest"]))
    d.kv("  FIRST EXAMPLE BANK — U.S. TREASURY OBLIGATIONS", fmt(INT_1099["box3_treasury"]))
    d.kv(f"  {PHANTOM_INT_PAYER[0]}", fmt(PHANTOM_INT_PAYER[1]))
    d.kv("LINE 2  TOTAL INTEREST", fmt(r["2b_interest"]))
    d.gap()
    d.line("PART II — ORDINARY DIVIDENDS", bold=True)
    d.kv("  EXAMPLE BROKERAGE LLC", fmt(DIV_1099["box1a_ordinary"]))
    d.kv("LINE 6  TOTAL ORDINARY DIVIDENDS", fmt(DIV_1099["box1a_ordinary"]))

    d.c.showPage(); d.y = 750
    d.line(f"SCHEDULE D  CAPITAL GAINS AND LOSSES  {TAX_YEAR}", bold=True, size=14)
    d.gap()
    st_proceeds = sum(pr for _, _, _, pr, _, _, t in B_1099_LOTS if t == "SHORT")
    st_basis = sum(b for _, _, _, _, b, _, t in B_1099_LOTS if t == "SHORT")
    lt_proceeds = sum(pr for _, _, _, pr, _, _, t in B_1099_LOTS if t == "LONG")
    lt_basis = sum(b for _, _, _, _, b, _, t in B_1099_LOTS if t == "LONG")
    d.kv("LINE 1b  SHORT-TERM — PROCEEDS", fmt(st_proceeds))
    d.kv("LINE 1b  SHORT-TERM — COST BASIS", fmt(st_basis))
    d.kv("LINE 1b  SHORT-TERM — ADJUSTMENTS", fmt(0))
    d.kv("LINE 7   NET SHORT-TERM CAPITAL GAIN OR (LOSS)", fmt(r["schD_st"]))
    d.kv("LINE 8b  LONG-TERM — PROCEEDS", fmt(lt_proceeds))
    d.kv("LINE 8b  LONG-TERM — COST BASIS", fmt(lt_basis))
    d.kv("LINE 13  CAPITAL GAIN DISTRIBUTIONS", fmt(DIV_1099["box2a_cap_gain"]))
    d.kv("LINE 15  NET LONG-TERM CAPITAL GAIN OR (LOSS)", fmt(r["schD_lt"]))
    d.kv("LINE 16  TOTAL CAPITAL GAIN OR (LOSS)", fmt(r["7_cap_gain"]))

    d.c.showPage(); d.y = 750
    d.line(f"FORM 540  CALIFORNIA RESIDENT INCOME TAX RETURN  {TAX_YEAR}", bold=True, size=14)
    d.gap()
    d.kv("FILING STATUS", p["filing_status_label"])
    d.kv("LINE 13  FEDERAL AGI", fmt(r["ca_fed_agi"]))
    d.kv("LINE 14  CA ADJUSTMENTS — SUBTRACTIONS (SCHEDULE CA)", fmt(0))
    d.kv("LINE 16  CA ADJUSTMENTS — ADDITIONS (SCHEDULE CA)", fmt(0))
    d.kv("LINE 17  CA ADJUSTED GROSS INCOME", fmt(r["ca_agi"]))
    d.kv("LINE 18  STANDARD DEDUCTION", fmt(r["ca_std_ded"]))
    d.kv("LINE 19  TAXABLE INCOME", fmt(r["ca_taxable"]))
    d.kv("LINE 31  TAX", fmt(r["ca_tax"]))
    d.kv("LINE 71  CA INCOME TAX WITHHELD", fmt(r["ca_wh"]))
    d.kv("LINE 99  OVERPAID TAX (REFUND)", fmt(r["ca_refund"]))
    d.gap()
    d.line("SCHEDULE CA (540)  CALIFORNIA ADJUSTMENTS", bold=True)
    d.kv("  SECTION A LINE 2  TAXABLE INTEREST — FEDERAL AMOUNT", fmt(r["2b_interest"]))
    d.kv("  SECTION A LINE 2  TAXABLE INTEREST — SUBTRACTIONS", fmt(0))
    d.kv("  SECTION A LINE 2  TAXABLE INTEREST — ADDITIONS", fmt(0))
    d.kv("  SECTION A LINE 8  OTHER ADDITIONS (NON-CA EXEMPT INTEREST)", fmt(0))
    d.save()


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--filing-status", choices=["mfj", "single"], default="mfj")
    ap.add_argument("--out", default="testdata")
    args = ap.parse_args()

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    r = compute_return(args.filing_status)

    make_w2(out / "w2-fake.pdf", args.filing_status)
    make_1099int(out / "1099int-fake.pdf", args.filing_status)
    make_1099div(out / "1099div-fake.pdf", args.filing_status)
    make_1099b(out / "1099b-fake.pdf", args.filing_status)
    make_bankstmt(out / "bankstmt-fake.pdf", args.filing_status)
    make_scanned(out / "scanned-fake.pdf", args.filing_status)
    make_return(out / "return-fake.pdf", args.filing_status, r)

    for f in sorted(out.iterdir()):
        print(f"wrote {f}")


if __name__ == "__main__":
    main()
