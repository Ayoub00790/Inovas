import sys
from playwright.sync_api import sync_playwright
from pypdf import PdfReader, PdfWriter
src, out = sys.argv[1], sys.argv[2]
FOOT = ('<div style="width:100%;font-size:7.5pt;color:#7A7E99;padding:0 17mm;display:flex;'
        'justify-content:space-between;font-family:sans-serif"><span>INOVA · Dossier technique et cahier des charges</span>'
        '<span class="pageNumber"></span></div>')
with sync_playwright() as p:
    b = p.chromium.launch(); pg = b.new_page()
    pg.goto("file://" + src); pg.wait_for_timeout(800)
    pg.pdf(path="cover.pdf", format="A4", print_background=True, prefer_css_page_size=True, page_ranges="1")
    pg.pdf(path="body.pdf", format="A4", print_background=True, prefer_css_page_size=True,
           display_header_footer=True, header_template="<span></span>", footer_template=FOOT, page_ranges="2-")
    b.close()
w = PdfWriter()
for f in ("cover.pdf", "body.pdf"):
    for page in PdfReader(f).pages:
        w.add_page(page)
w.add_metadata({"/Title": "INOVA — Dossier technique et cahier des charges", "/Author": "Ayoub Benkhajjou"})
with open(out, "wb") as fh:
    w.write(fh)
