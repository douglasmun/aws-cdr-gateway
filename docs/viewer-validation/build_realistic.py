"""A REAL Word document (built by python-docx, so it has proper styles, theme,
settings, fonts) whose document part is then relocated + declared via #55's
Default Extension. If Word renders this cleanly, the verdict is meaningful;
a minimal hand-built package could fail rendering for unrelated reasons."""
import io,os,sys,zipfile,shutil
sys.path.insert(0,"/Users/douglasmun/Develop/aws-cdr-gateway/src")
os.environ.setdefault("SANITISED_BUCKET","t"); os.environ.setdefault("QUARANTINE_BUCKET","t")
import lambda_function as cdr
import docx
OUT="/Users/douglasmun/Develop/aws-cdr-gateway/docs/viewer-validation"

d=docx.Document()
d.add_heading("CDR Viewer Validation", 0)
d.add_paragraph("This document was produced by python-docx, then modified so its main "
                "document part is stored as word/doc.dat and declared wordprocessingml "
                "via an OPC Default Extension entry (pitfall #55).")
d.add_paragraph("Before PR #91 the DDE field below survived sanitisation intact.")
p=d.add_paragraph(); p.add_run("Bold run").bold=True; p.add_run(" and normal run.")
t=d.add_table(rows=2, cols=2); t.style="Table Grid"
for i,row in enumerate(t.rows):
    for j,c in enumerate(row.cells): c.text=f"cell {i},{j}"
d.add_paragraph("End of sample.")
b=io.BytesIO(); d.save(b); base=b.getvalue()

# inject the DDE field into document.xml, relocate the part, swap the declaration
zin=zipfile.ZipFile(io.BytesIO(base))
docxml=zin.read("word/document.xml").decode()
docxml=docxml.replace("</w:body>",
    '<w:p><w:r><w:instrText>DDEAUTO c:\\\\windows\\\\system32\\\\cmd.exe "/c calc.exe"'
    '</w:instrText></w:r></w:p></w:body>')
WML="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"
out=io.BytesIO()
with zipfile.ZipFile(out,"w",zipfile.ZIP_DEFLATED) as z:
    for it in zin.infolist():
        data=zin.read(it.filename)
        if it.filename=="word/document.xml":
            z.writestr("word/doc.dat", docxml)          # relocated, non-XML suffix
        elif it.filename=="[Content_Types].xml":
            ct=data.decode()
            ct=ct.replace(f'<Override PartName="/word/document.xml" ContentType="{WML}"/>','')
            ct=ct.replace("</Types>", f'<Default Extension="dat" ContentType="{WML}"/></Types>')
            z.writestr(it.filename, ct)
        elif it.filename=="_rels/.rels":
            z.writestr(it.filename, data.decode().replace("word/document.xml","word/doc.dat"))
        elif it.filename=="word/_rels/document.xml.rels":
            z.writestr("word/_rels/doc.dat.rels", data)
        else:
            z.writestr(it.filename, data)
raw=out.getvalue()

pre = "DDEAUTO" in docx.Document(io.BytesIO(raw)).element.xml
print("INPUT realistic #55 package: python-docx sees DDEAUTO =", pre)
res=cdr.cdr_dispatch(raw,"docx")
print("dispatch:", res["status"], "removed:", res["report"]["removed"])
open(f"{OUT}/originals/in_p55_realistic.docx","wb").write(raw)
open(f"{OUT}/sanitised/p55_realistic.docx","wb").write(res["data"])
dd=docx.Document(io.BytesIO(res["data"]))
print("OUTPUT paragraphs:", len(dd.paragraphs), "tables:", len(dd.tables))
print("OUTPUT still has a live DDEAUTO target:", "_CDR_REMOVED_" not in dd.element.xml and "DDEAUTO" in dd.element.xml)
