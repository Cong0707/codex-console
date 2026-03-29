"""
Playwright request helper.

This module provides a minimal wrapper to send HTTP requests using a
Playwright-launched system browser (headful by default).
"""

from __future__ import annotations

from typing import Any, Dict, Optional, Tuple


class PlaywrightRequestError(RuntimeError):
    """Raised when Playwright request fails."""


def _import_playwright():
    try:
        from playwright.sync_api import sync_playwright, Error as PlaywrightError  # type: ignore
    except Exception as exc:  # pragma: no cover - import guard
        raise PlaywrightRequestError(
            "Playwright is not installed. Run: pip install playwright"
        ) from exc
    return sync_playwright, PlaywrightError


def playwright_request(
    method: str,
    url: str,
    *,
    headers: Optional[Dict[str, str]] = None,
    json_data: Any = None,
    data: Any = None,
    multipart: Optional[Dict[str, Any]] = None,
    browser_channel: str = "chrome",
    headless: bool = False,
    timeout: int = 30,
) -> Tuple[int, str]:
    """
    Send a request through Playwright.

    Returns:
        (status_code, response_text)
    """
    if not url:
        raise PlaywrightRequestError("Request URL is empty")

    sync_playwright, PlaywrightError = _import_playwright()

    browser = None
    context = None
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(channel=browser_channel, headless=headless)
            context = browser.new_context(
                user_agent=(
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/131.0.0.0 Safari/537.36"
                ),
                locale="zh-CN",
            )

            # Open a blank page to ensure headful window is visible.
            if not headless:
                page = context.new_page()
                page.goto("about:blank")

            request = context.request
            method_upper = (method or "POST").upper()
            timeout_ms = int(timeout * 1000)

            if method_upper == "POST":
                response = request.post(
                    url,
                    headers=headers,
                    json=json_data,
                    data=data,
                    multipart=multipart,
                    timeout=timeout_ms,
                )
            elif method_upper == "GET":
                response = request.get(
                    url,
                    headers=headers,
                    timeout=timeout_ms,
                )
            else:
                response = request.fetch(
                    url,
                    method=method_upper,
                    headers=headers,
                    json=json_data,
                    data=data,
                    multipart=multipart,
                    timeout=timeout_ms,
                )

            status = response.status
            text = response.text()
            return status, text
    except PlaywrightError as exc:
        raise PlaywrightRequestError(str(exc)) from exc
    except Exception as exc:
        raise PlaywrightRequestError(str(exc)) from exc
    finally:
        try:
            if context:
                context.close()
        except Exception:
            pass
        try:
            if browser:
                browser.close()
        except Exception:
            pass
