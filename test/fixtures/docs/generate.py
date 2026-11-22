# Regenerates the real-*.{docx,pptx,xlsx,pdf,odt} fixtures used by test/scanners.test.mjs.
# Usage: uv run --with python-docx --with python-pptx --with openpyxl --with reportlab --with odfpy python generate.py .

import os, sys
out = sys.argv[1]
os.makedirs(out, exist_ok=True)

# ---------------- DOCX ----------------
from docx import Document
def docx(path, header, footer, title, paras, core_title=None):
    d = Document()
    sec = d.sections[0]
    sec.header.paragraphs[0].text = header
    sec.footer.paragraphs[0].text = footer
    d.add_heading(title, level=0)
    for p in paras:
        d.add_paragraph(p)
    if core_title:
        d.core_properties.title = core_title
    d.core_properties.author = "Test Author"
    d.save(path)

docx(os.path.join(out, "real-confidential.docx"),
     "Northwind Trading \u2014 CONFIDENTIAL", "Internal use only \u2014 page 1",
     "Supplier pricing review",
     ["This review covers the negotiated supplier prices for the next fiscal year.",
      "Volumes are estimates and subject to change."], core_title="Supplier pricing review")
docx(os.path.join(out, "real-clean.docx"),
     "Northwind Trading \u2014 Newsletter", "Page 1",
     "Spring newsletter",
     ["Welcome to the spring edition of our public newsletter.",
      "The cafeteria menu has been refreshed and the bike shed is open again."], core_title="Spring newsletter")

# ---------------- PPTX ----------------
from pptx import Presentation
from pptx.util import Inches
def pptx(path, title, bullets, stamp=None, notes=None):
    prs = Presentation()
    s1 = prs.slides.add_slide(prs.slide_layouts[0])
    if stamp:
        # python-pptx cannot add shapes to a master directly: build the text box on a slide, then move it
        tb = s1.shapes.add_textbox(Inches(0.3), Inches(6.9), Inches(4), Inches(0.4))
        tb.text_frame.text = stamp
        el = tb._element
        el.getparent().remove(el)
        prs.slide_master.shapes._spTree.append(el)
    s1.shapes.title.text = title
    s1.placeholders[1].text = "Planning session"
    s2 = prs.slides.add_slide(prs.slide_layouts[1])
    s2.shapes.title.text = "Agenda"
    s2.placeholders[1].text = "\n".join(bullets)
    if notes:
        s2.notes_slide.notes_text_frame.text = notes
    prs.save(path)

pptx(os.path.join(out, "real-confidential.pptx"), "Product roadmap", ["Launch plan", "Budget", "Risks"],
     stamp="CONFIDENTIAL", notes="Remember: figures are not final.")
pptx(os.path.join(out, "real-clean.pptx"), "Team offsite", ["Arrival", "Workshops", "Dinner"],
     notes="Bring comfortable shoes.")

# ---------------- XLSX ----------------
from openpyxl import Workbook
def xlsx(path, header_text, rows, sheet="Data"):
    wb = Workbook()
    ws = wb.active
    ws.title = sheet
    for r in rows:
        ws.append(r)
    if header_text:
        ws.oddHeader.center.text = header_text
        ws.oddFooter.right.text = "Page &P of &N"
    wb.save(path)

xlsx(os.path.join(out, "real-confidential.xlsx"), "STRICTLY CONFIDENTIAL",
     [["Region", "Margin"], ["North", 0.31], ["South", 0.27]], sheet="Margins")
xlsx(os.path.join(out, "real-clean.xlsx"), None,
     [["Item", "Qty"], ["Pens", 12], ["Paper", 40]], sheet="Stock")

# ---------------- PDF ----------------
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import A4
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
import reportlab
W, H = A4
LOREM = ("The quarterly figures are summarised in the following table and discussed "
         "in the sections below. Each region reports separately.")
def pdf(path, header, footer, watermark, pages=3, title="Quarterly report", keywords=None, font="Helvetica"):
    c = canvas.Canvas(path, pagesize=A4, pageCompression=1)
    c.setTitle(title)
    c.setAuthor("Test Author")
    if keywords:
        c.setKeywords(keywords)
    for n in range(1, pages + 1):
        c.setFont(font, 9)
        if header:
            c.drawString(40, H - 30, header)
        if footer:
            c.drawString(40, 25, footer.replace("{n}", str(n)).replace("{t}", str(pages)))
        if watermark:
            c.saveState()
            c.setFont(font, 46)
            c.setFillGray(0.85)
            c.translate(W / 2, H / 2)
            c.rotate(45)
            c.drawCentredString(0, 0, watermark)
            c.restoreState()
        c.setFont(font, 11)
        y = H - 120
        c.drawString(40, y, "Section %d" % n)
        for i in range(8):
            y -= 18
            c.drawString(40, y, LOREM)
        c.showPage()
    c.save()

pdf(os.path.join(out, "real-confidential.pdf"), "Northwind Trading - CONFIDENTIAL",
    "Page {n} of {t} - Internal use only", "DO NOT DISTRIBUTE")
pdf(os.path.join(out, "real-clean.pdf"), "Northwind Trading - Annual newsletter", "Page {n} of {t}", None)
pdf(os.path.join(out, "real-keywords.pdf"), None, None, None, pages=1, title="Pricing notes", keywords="pricing, confidential, 2026")

vera = os.path.join(os.path.dirname(reportlab.__file__), "fonts", "Vera.ttf")
pdfmetrics.registerFont(TTFont("Vera", vera))
pdf(os.path.join(out, "real-confidential-ttf.pdf"), "CONFIDENTIEL - Diffusion restreinte", "Page {n} / {t}", None, pages=2, font="Vera")
print("generated", sorted(os.listdir(out)))

# ---------------- encrypted PDF ----------------
c = canvas.Canvas(os.path.join(out, "real-encrypted.pdf"), pagesize=A4, encrypt="s3cret-pw")
c.drawString(40, H - 60, "CONFIDENTIAL - you cannot read this without the password")
c.showPage(); c.save()

# ---------------- ODT ----------------
from odf.opendocument import OpenDocumentText
from odf.text import P, H as OH
from odf.style import MasterPage, PageLayout, Header, Footer
from odf import dc, meta as odfmeta
def odt(path, header, title, paras, classification=None):
    doc = OpenDocumentText()
    pl = PageLayout(name="pl")
    doc.automaticstyles.addElement(pl)
    mp = MasterPage(name="Standard", pagelayoutname=pl)
    h = Header(); h.addElement(P(text=header)); mp.addElement(h)
    f = Footer(); f.addElement(P(text="Page 1")); mp.addElement(f)
    doc.masterstyles.addElement(mp)
    doc.meta.addElement(dc.Title(text=title))
    if classification:
        doc.meta.addElement(odfmeta.UserDefined(name="Classification", text=classification))
    doc.text.addElement(OH(outlinelevel=1, text=title))
    for p in paras:
        doc.text.addElement(P(text=p))
    doc.save(path)

odt(os.path.join(out, "real-confidential.odt"), "Northwind Trading - Usage interne uniquement", "Plan d'achats",
    ["Ce plan couvre les achats de l'exercice.", "Les volumes sont des estimations."], classification="Restricted")
odt(os.path.join(out, "real-clean.odt"), "Northwind Trading - Newsletter", "Lettre de printemps",
    ["Bienvenue dans notre lettre publique.", "Le menu de la cantine a changé."])
print("generated", sorted(os.listdir(out)))
