#!/usr/bin/env python3
"""Disarm one file locally via the shared cdr_dispatch core (no server, no AWS).

Usage:
    /tmp/cdrvenv/bin/python tools/disarm.py <path-to-file>

Writes <name>.cdr.<ext> next to the original on a 'sanitised' verdict.
Prints status + report for any verdict.
"""
import sys, os, json

REPO = os.path.join(os.path.dirname(__file__), "..", "src")
sys.path.insert(0, os.path.abspath(REPO))
# cdr_dispatch is pure/I-O-free, but importing lambda_function builds a boto3
# client at module load, so give it dummy creds/region to construct.
os.environ.setdefault("SANITISED_BUCKET", "x")
os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")
os.environ.setdefault("AWS_ACCESS_KEY_ID", "x")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "x")

import lambda_function as cdr


def main():
    if len(sys.argv) != 2:
        sys.exit("usage: disarm.py <path-to-file>")
    src = sys.argv[1]
    data = open(src, "rb").read()
    ext = src.rsplit(".", 1)[-1].lower()

    res = cdr.cdr_dispatch(data, ext)
    print("status:", res.get("status"))
    print("report:", json.dumps(res.get("report"), indent=2))

    if res.get("status") == "sanitised" and res.get("data") is not None:
        out_ext = res.get("sanitised_ext") or ext  # engine may remap (e.g. docm->docx, xlsb->xlsx)
        out = src.rsplit(".", 1)[0] + ".cdr." + out_ext
        open(out, "wb").write(res["data"])
        print("WROTE:", out, len(res["data"]), "bytes")
    else:
        print("NOT sanitised -- nothing written")


if __name__ == "__main__":
    main()
