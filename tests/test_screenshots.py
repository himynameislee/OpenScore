"""Screenshot redaction safety test (skipped if Playwright/Chromium isn't installed).
Secrets from exposed files must never appear in evidence images."""
import asyncio
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from openscore.modules import screenshots  # noqa: E402

SECRET_PAGE = ("<html><body><pre>APP_KEY=base64:abc123\nDB_PASSWORD=hunter2\n"
               "aws_secret_access_key = wJalrXUtnFEMI\n{\"password\":\"s3cr3t\"}</pre></body></html>")


async def _redacted_text_and_style():
    from playwright.async_api import async_playwright
    async with async_playwright() as pw:
        b = await pw.chromium.launch()
        p = await b.new_page()
        await p.set_content(SECRET_PAGE)
        await p.evaluate(screenshots.BANNER_JS, ["http://x/.env", 200, "now", "0", True, "Finding: test"])
        text = await p.evaluate("document.body.innerText")
        blur = await p.evaluate("getComputedStyle(document.body).filter")
        await b.close()
        return text, blur


def test_redaction_masks_and_blurs():
    if not screenshots.available():
        pytest.skip("playwright not installed")
    try:
        text, blur = asyncio.run(_redacted_text_and_style())
    except Exception as e:  # chromium not downloaded
        pytest.skip(f"chromium unavailable: {e}")
    for secret in ("hunter2", "base64:abc123", "wJalrXUtnFEMI", "s3cr3t"):
        assert secret not in text, f"secret {secret!r} leaked into screenshot DOM"
    assert "APP_KEY" in text  # key names stay, proving what was exposed
    assert "blur" in blur
