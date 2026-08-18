"""Minimal, real Starlette app isolating the exact Content-Disposition
header construction used by src/external/routes/cases.py's
download_evidence route and src/external/routes/audit.py's export route
-- run under a real uvicorn server (not the in-process TestClient, which
never serializes to real HTTP/1.1 bytes and so never exercises h11's own
header validation) to prove the real, wire-level crash this PoC exists to
document, per CLAUDE.md SS F ("real observed output... not assumed").

--sanitize flag selects between the pre-fix (`.replace('"', "")` only)
and post-fix (`sanitize_content_disposition_filename`) behavior, so both
states can be demonstrated against the same real server code path.
"""

from __future__ import annotations

import os
import sys

from starlette.applications import Starlette
from starlette.responses import StreamingResponse
from starlette.routing import Route

sys.path.insert(0, "/home/reca/Claude/Kronos/KronOS_template")
from src.external.routes._http_helpers import sanitize_content_disposition_filename

USE_FIX = os.environ.get("REPRO_USE_FIX") == "1"
CRAFTED_FILENAME = 'evil\r\nSet-Cookie: x=1\r\n".evtx'


async def gen():
    yield b"real evidence bytes"


async def download(request):
    filename = (
        sanitize_content_disposition_filename(CRAFTED_FILENAME)
        if USE_FIX
        else CRAFTED_FILENAME.replace('"', "")
    )
    return StreamingResponse(
        gen(),
        media_type="application/octet-stream",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


app = Starlette(routes=[Route("/download", download)])
