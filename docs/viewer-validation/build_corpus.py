"""Build a viewer-validation corpus: sanitised outputs to open in Word/Acrobat.

Purpose: every CDR verdict to date is confirmed against pikepdf/python-docx/
openpyxl/Pillow. The bug class we keep finding (#54, #55) IS parser
disagreement, so the outstanding question is whether the shipping viewers agree
with the Python parsers. This produces the artefacts to answer that by eye.

Each case emits BOTH:
  in_<name>   -- the malicious input (do NOT open in a viewer; reference only)
  out_<name>  -- the sanitised output, saved under the REMAPPED extension
and a row in CHECKLIST.md stating what the viewer should show.
"""
import io, os, sys, json, zipfile, shutil
sys.path.insert(0, "/Users/douglasmun/Develop/aws-cdr-gateway/src")
os.environ.setdefault("SANITISED_BUCKET","t"); os.environ.setdefault("QUARANTINE_BUCKET","t")
import lambda_function as cdr

OUT = "/Users/douglasmun/Develop/aws-cdr-gateway/docs/viewer-validation"
FIX = "/Users/douglasmun/Develop/aws-cdr-gateway/docs/fixtures"
os.makedirs(f"{OUT}/sanitised", exist_ok=True)
os.makedirs(f"{OUT}/originals", exist_ok=True)
rows = []

def emit(name, raw, ext, what_to_check, why):
    """Run the real dispatcher and save the sanitised output for viewing."""
    res = cdr.cdr_dispatch(raw, ext)
    status = res["status"]
    if status != "sanitised":
        rows.append((name, ext, "-", status, res.get("reason") or "", what_to_check, why))
        print(f"  {name:38} {status.upper()} ({res.get('reason')})")
        return
    sext = res["sanitised_ext"]
    open(f"{OUT}/originals/in_{name}.{ext}", "wb").write(raw)
    open(f"{OUT}/sanitised/{name}.{sext}", "wb").write(res["data"])
    nrem = len(res["report"].get("removed", []))
    rows.append((name, ext, sext, "sanitised", f"{nrem} item(s) removed", what_to_check, why))
    print(f"  {name:38} sanitised -> .{sext}  removed={nrem}")

# ── 1. The two bypasses we fixed this week — the highest-value viewer checks ──
WML = "application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"
PAY = ('<?xml version="1.0"?><w:document xmlns:w="http://schemas.openxmlformats.org'
       '/wordprocessingml/2006/main"><w:body>'
       '<w:p><w:r><w:t>CDR viewer-validation sample. The paragraph below carried a '
       'DDEAUTO field code before sanitisation.</w:t></w:r></w:p>'
       '<w:p><w:r><w:instrText>DDEAUTO c:\\\\windows\\\\system32\\\\cmd.exe "/c calc.exe"</w:instrText></w:r></w:p>'
       '</w:body></w:document>')

def opc(part, decl, target):
    ct = ('<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
          '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
          + decl + '</Types>')
    rels = ('<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/'
            'relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument'
            f'/2006/relationships/officeDocument" Target="{target}"/></Relationships>')
    b = io.BytesIO()
    with zipfile.ZipFile(b, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", ct); z.writestr("_rels/.rels", rels); z.writestr(part, PAY)
    return b.getvalue()

print("=== pitfall #54 / #55 — the declaration bypasses ===")
emit("p54_override_bin", opc("word/document.bin",
     f'<Override PartName="/word/document.bin" ContentType="{WML}"/>', "word/document.bin"),
     "docx",
     "Opens and shows the sample text. The DDE line must be inert — NO 'update links' / "
     "'remote data' prompt, and no calc.exe.",
     "pitfall #54: document part named .bin, declared XML via Override")
emit("p55_default_dat", opc("word/doc.dat",
     f'<Default Extension="dat" ContentType="{WML}"/>', "word/doc.dat"),
     "docx",
     "Same as above. This is the #55 variant with NO Override at all — the one that "
     "shipped a live payload before PR #91.",
     "pitfall #55: declared solely by Default Extension")

# ── 2. Real fixtures already in the repo (fidelity, not just neutralisation) ──
print("\n=== existing repo fixtures — does Word still render them? ===")
# EXCLUDED on purpose: docx_dde_field, docx_autoopen_field, docx_multithreat and
# docx_vba_macro are synthetic packages with no officeDocument relationship, so
# python-docx cannot open the *inputs* either. Word would reject them for reasons
# unrelated to CDR and produce a false alarm. p55_realistic.docx covers the same
# ground with a genuine python-docx package. See CHECKLIST.md "Known exclusions".
for fn, note in [
    ("macro-sample.docm",     "MACRO-ENABLED input: output is .docx by EXT_REMAP. Word must open it "
                              "cleanly and offer NO macros (Alt+F8 should list none)"),
    ("xlsm_vba_realistic.xlsm","Excel: output is .xlsx. Cells/formulas must survive; no macros"),
    ("xlsx_dde_formula.xlsx", "DDE formula neutralised; other cell values must be intact"),
    ("pptx_activex.pptx",     "ActiveX control removed; slides must still render"),
]:
    p = os.path.join(FIX, fn)
    if not os.path.exists(p):
        print(f"  {fn:38} MISSING - skipped"); continue
    emit(fn.rsplit(".",1)[0], open(p,"rb").read(), fn.rsplit(".",1)[-1], note,
         "repo fixture — checks fidelity as well as neutralisation")

print("\n=== PDF — Acrobat is the target here ===")
for fn, note in [
    ("pdf_openaction_js.pdf",   "Opens in Acrobat with NO JavaScript prompt; page renders"),
    ("pdf_acroform_js.pdf",     "Form fields render; no JS on focus/calculate"),
    ("pdf_embedded_file.pdf",   "No attachment in Acrobat's attachments pane"),
    ("pdf_multithreat.pdf",     "Several vectors stripped at once; page still renders"),
    ("pdf_lejon_multithreat.pdf","malicious-pdf taxonomy sample"),
    ("pdf_javascript_realistic.pdf","Realistic JS-bearing PDF; must render, no script"),
]:
    p = os.path.join(FIX, fn)
    if not os.path.exists(p):
        print(f"  {fn:38} MISSING - skipped"); continue
    emit(fn.rsplit(".",1)[0], open(p,"rb").read(), "pdf", note, "repo PDF fixture")

# NOTE: four synthetic fixtures (docx_dde_field, docx_autoopen_field,
# docx_multithreat, docx_vba_macro) are intentionally NOT in the viewer corpus —
# they have no officeDocument rel, so python-docx cannot open the *inputs*
# either and Word would fail them for reasons unrelated to CDR. See CHECKLIST.md.
# `p55_realistic.docx` (built by build_realistic.py) covers what they cannot.

# ── 3. PDF container-layer outputs — the sweep that found no bypass ──────────
print("\n=== PDF container layer (the 2026-08-14 sweep) ===")
import pikepdf, re
def minimal(js=None):
    ra = f" /OpenAction << /S /JavaScript /JS ({js}) >>" if js else ""
    objs=[f"1 0 obj\n<< /Type /Catalog /Pages 2 0 R{ra} >>\nendobj\n",
          "2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n",
          "3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 50] /Contents 4 0 R >>\nendobj\n",
          "4 0 obj\n<< /Length 60 >>\nstream\nBT /F1 10 Tf 10 20 Td (CDR container sample) Tj ET\nendstream\nendobj\n"]
    out="%PDF-1.7\n"; offs=[]
    for o in objs: offs.append(len(out)); out+=o
    x=len(out); n=len(objs)+1
    out+=f"xref\n0 {n}\n0000000000 65535 f \n"
    for off in offs: out+=f"{off:010d} 00000 n \n"
    out+=f"trailer\n<< /Size {n} /Root 1 0 R >>\nstartxref\n{x}\n%%EOF\n"
    return out.encode("latin-1")

base = minimal()
upd = b"5 0 obj\n<< /Type /Catalog /Pages 2 0 R /OpenAction << /S /JavaScript /JS (app.alert('x')) >> >>\nendobj\n"
off5=len(base); body=base+upd; x2=len(body)
prev=int(re.search(rb"startxref\s+(\d+)",base).group(1))
body += (b"xref\n0 1\n0000000000 65535 f \n5 1\n"+f"{off5:010d} 00000 n \n".encode()
         +f"trailer\n<< /Size 6 /Root 5 0 R /Prev {prev} >>\nstartxref\n{x2}\n%%EOF\n".encode())
emit("pdfc_incremental_update", body, "pdf",
     "Acrobat must open it and show NO JavaScript alert. Confirms the rebuild collapsed "
     "the two revisions into one.",
     "container sweep: incremental update repointed /Root at a payload catalog")

p = pikepdf.new(); p.add_blank_page()
p.Root["/OpenAction"] = p.make_indirect(pikepdf.Dictionary(
    S=pikepdf.Name("/JavaScript"), JS="app.alert('x')"))
b = io.BytesIO(); p.save(b, encryption=pikepdf.Encryption(owner="", user="", R=6))
emit("pdfc_encrypted_input", b.getvalue(), "pdf",
     "Input was ENCRYPTED; output should open with no password prompt (encryption is "
     "stripped, by design) and show no JS alert.",
     "container sweep: encryption stripped rather than propagated")

json.dump(rows, open("/tmp/corpus_rows.json","w"))
print(f"\n{len(rows)} cases -> {OUT}")
