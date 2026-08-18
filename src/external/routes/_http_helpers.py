"""Small, shared HTTP response-shaping helpers used by multiple route modules."""

from __future__ import annotations


def sanitize_content_disposition_filename(filename: str) -> str:
    """Strip characters that would break a ``Content-Disposition`` header value.

    Real bug fixed here (Gap Audit Milestone DD): ``Content-Disposition``
    filenames built from user-controlled strings (``Evidence.metadata.
    original_filename`` in ``cases.py``'s evidence-download route,
    ``TenantContext.org_alias`` in ``audit.py``'s export route) only ever
    had their double quotes escaped, not CR/LF/other C0 control characters.
    Confirmed live, not assumed, against a real running uvicorn server: a
    filename containing a raw ``\\r``/``\\n`` reaches h11's own HTTP/1.1
    header serializer, which raises ``LocalProtocolError: Illegal header
    value`` -- a real 500 on every subsequent download attempt by anyone
    in the org, not just the original uploader. Not exploitable as header
    injection/response-splitting (h11 defends against that at the
    protocol level, confirmed the same way), but a real, live availability
    bug: any authenticated user with ordinary upload permission could
    permanently break download access to a case's evidence for the whole
    org with a single crafted filename -- and a DFIR platform must accept
    evidence with exactly this kind of adversarial/malformed filename from
    a compromised host (validation intentionally bounds only length, not
    content, at intake -- see ``UploadRequestIn.filename``).

    Strips all C0 control characters (``0x00``-``0x1F``) and DEL
    (``0x7F``) plus the double quote (matching the pre-existing
    quote-escaping behavior) -- real Unicode filenames (CJK, Cyrillic,
    emoji, etc.) are left untouched, only actual control characters are
    removed.
    """
    return "".join(ch for ch in filename if ch != '"' and 0x20 <= ord(ch) != 0x7F)
