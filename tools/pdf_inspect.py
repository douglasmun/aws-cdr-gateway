#!/usr/bin/env python3
"""Inspect a PDF for active content WITHOUT modifying it.

Usage:
    /tmp/cdrvenv/bin/python tools/pdf_inspect.py <path-to-pdf>

Reports the same vectors cdr_pdf strips: OpenAction, AA, JavaScript,
AcroForm/XFA, embedded files, auto-run annotations, JBIG2/JPX filters, metadata.
Do NOT rename this file to inspect.py (shadows stdlib -> pikepdf import fails).
"""
import sys
import pikepdf


def has(d, k):
    try:
        return k in d
    except Exception:
        return False


def main():
    if len(sys.argv) != 2:
        sys.exit("usage: pdf_inspect.py <path-to-pdf>")
    src = sys.argv[1]
    pdf = pikepdf.open(src)
    root = pdf.Root

    print("=== Catalog-level ===")
    for k in ["/OpenAction", "/AA", "/JavaScript", "/JS", "/AcroForm"]:
        print(f"{k}: {'YES' if has(root, k) else '-'}")
        if has(root, k):
            print("    ->", repr(root.get(k)))

    names = root.get("/Names")
    if names:
        for k in ["/JavaScript", "/EmbeddedFiles"]:
            print(f"/Names{k}: {'YES' if has(names, k) else '-'}")
    else:
        print("/Names: -")

    print("\n=== Per-page annotations / actions ===")
    counts = {}
    for page in pdf.pages:
        for a in (page.get("/Annots") or []):
            sub = str(a.get("/Subtype", "?"))
            for k in ["/A", "/AA"]:
                if has(a, k):
                    counts[f"annot{k}"] = counts.get(f"annot{k}", 0) + 1
            if sub in ("/FileAttachment", "/RichMedia", "/Screen",
                       "/3D", "/Movie", "/Sound"):
                counts[f"annot {sub}"] = counts.get(f"annot {sub}", 0) + 1
    print("annotation action/subtype counts:", counts or "none")

    print("\n=== Risky image filters (decoder-RCE) ===")
    risky = {"/JBIG2Decode", "/JPXDecode"}
    hits = []
    for obj in pdf.objects:
        try:
            f = obj.get("/Filter")
        except Exception:
            continue
        if f is None:
            continue
        fs = [str(f)] if not isinstance(f, pikepdf.Array) else [str(x) for x in f]
        hits += [n for n in fs if n in risky]
    print("JBIG2/JPX:", hits or "none")

    print("\n=== Metadata ===")
    print("/Metadata stream:", "YES" if has(root, "/Metadata") else "-")
    print("docinfo keys:", list(pdf.docinfo.keys()) if pdf.docinfo else "none")
    for k, v in (pdf.docinfo or {}).items():
        print(f"    {k}: {v}")


if __name__ == "__main__":
    main()
