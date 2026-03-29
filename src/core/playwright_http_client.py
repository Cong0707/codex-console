"""
Playwright-based HTTP client adapters.

Provides a session interface compatible with the registration engine while
driving requests through a headful Playwright browser context.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from types import SimpleNamespace
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.parse import unquote, urlparse

logger = logging.getLogger(__name__)


class PlaywrightClientError(RuntimeError):
    """Raised when Playwright client setup or request fails."""


def _import_playwright():
    try:
        from playwright.sync_api import sync_playwright, Error as PlaywrightError  # type: ignore
    except Exception as exc:  # pragma: no cover - import guard
        raise PlaywrightClientError(
            "Playwright is not installed. Run: pip install playwright && playwright install chromium"
        ) from exc
    return sync_playwright, PlaywrightError


class CaseInsensitiveHeaders:
    """Simple case-insensitive headers mapping."""

    def __init__(self, data: Optional[Dict[str, str]] = None):
        self._store: Dict[str, Tuple[str, str]] = {}
        if data:
            for key, value in data.items():
                self[key] = value

    def __setitem__(self, key: str, value: str) -> None:
        self._store[str(key).lower()] = (key, value)

    def __getitem__(self, key: str) -> str:
        return self._store[str(key).lower()][1]

    def __contains__(self, key: object) -> bool:
        return str(key).lower() in self._store

    def get(self, key: str, default: Optional[str] = None) -> Optional[str]:
        return self._store.get(str(key).lower(), (None, default))[1]

    def get_list(self, key: str) -> List[str]:
        value = self.get(key)
        if value is None:
            return []
        if isinstance(value, list):
            return value
        if isinstance(value, str) and "\n" in value:
            return [item for item in value.split("\n") if item]
        return [str(value)]

    def get_all(self, key: str) -> List[str]:
        return self.get_list(key)

    def items(self) -> Iterable[Tuple[str, str]]:
        return ((orig, val) for (orig, val) in self._store.values())

    def keys(self) -> Iterable[str]:
        return (orig for (orig, _val) in self._store.values())

    def values(self) -> Iterable[str]:
        return (val for (_orig, val) in self._store.values())


@dataclass
class CookieEntry:
    name: str
    value: str
    domain: Optional[str] = None
    path: Optional[str] = None


class PlaywrightCookieJar:
    """Cookie jar adapter for Playwright BrowserContext."""

    def __init__(self, context):
        self._context = context

    def _all(self) -> List[Dict[str, Any]]:
        return list(self._context.cookies())

    @staticmethod
    def _domain_match(cookie_domain: str, requested_domain: str) -> bool:
        if not cookie_domain or not requested_domain:
            return False
        c_dom = cookie_domain.lstrip(".").lower()
        r_dom = requested_domain.lstrip(".").lower()
        return c_dom == r_dom or c_dom.endswith("." + r_dom) or r_dom.endswith("." + c_dom)

    def get(self, name: str, default: Optional[str] = None, domain: Optional[str] = None, path: Optional[str] = None):
        for cookie in self._all():
            if cookie.get("name") != name:
                continue
            if domain and not self._domain_match(str(cookie.get("domain") or ""), domain):
                continue
            if path and cookie.get("path") != path:
                continue
            return cookie.get("value")
        return default

    def set(self, name: str, value: str, domain: Optional[str] = None, path: str = "/"):
        cookie: Dict[str, Any] = {
            "name": name,
            "value": value,
            "path": path or "/",
        }

        if domain:
            cookie["domain"] = domain.lstrip(".")
        else:
            cookie["url"] = "https://chatgpt.com"

        try:
            self._context.add_cookies([cookie])
        except Exception as exc:
            logger.warning("Playwright cookie set failed: %s", exc)

    def items(self) -> Iterable[Tuple[str, str]]:
        return [(cookie.get("name"), cookie.get("value")) for cookie in self._all()]

    @property
    def jar(self) -> List[CookieEntry]:
        return [
            CookieEntry(
                name=cookie.get("name", ""),
                value=cookie.get("value", ""),
                domain=cookie.get("domain"),
                path=cookie.get("path"),
            )
            for cookie in self._all()
        ]


class PlaywrightResponse:
    """Response adapter with requests-like attributes."""

    def __init__(self, response):
        self._response = response
        self.status_code = getattr(response, "status", None)

        try:
            headers = response.headers
        except Exception:
            headers = {}
        self.headers = CaseInsensitiveHeaders(headers)

        try:
            req = response.request
            req_headers = getattr(req, "headers", {}) if req else {}
        except Exception:
            req_headers = {}
        self.request = SimpleNamespace(headers=CaseInsensitiveHeaders(req_headers))

        try:
            self.text = response.text()
        except Exception:
            self.text = ""

    def json(self) -> Any:
        try:
            return self._response.json()
        except Exception:
            try:
                return json.loads(self.text or "")
            except Exception:
                return {}


def _parse_proxy(proxy_url: str) -> Optional[Dict[str, str]]:
    try:
        parsed = urlparse(proxy_url)
    except Exception:
        return None
    if not parsed.scheme or not parsed.hostname:
        return None

    server = f"{parsed.scheme}://{parsed.hostname}"
    if parsed.port:
        server = f"{server}:{parsed.port}"

    proxy: Dict[str, str] = {"server": server}
    if parsed.username:
        proxy["username"] = unquote(parsed.username)
    if parsed.password:
        proxy["password"] = unquote(parsed.password)
    return proxy


class PlaywrightSession:
    """Session adapter that routes requests via Playwright context."""

    def __init__(
        self,
        *,
        proxy_url: Optional[str] = None,
        browser_channel: str = "chrome",
        headless: bool = False,
        user_agent: Optional[str] = None,
        locale: str = "zh-CN",
        initial_url: Optional[str] = None,
    ):
        sync_playwright, _playwright_error = _import_playwright()

        self._playwright = sync_playwright().start()
        self._browser = None
        self._context = None
        self._request = None
        self._page = None
        self._closed = False

        launch_kwargs: Dict[str, Any] = {
            "headless": headless,
        }
        if browser_channel:
            launch_kwargs["channel"] = browser_channel
        if proxy_url:
            proxy = _parse_proxy(proxy_url)
            if proxy:
                launch_kwargs["proxy"] = proxy

        self._browser = self._playwright.chromium.launch(**launch_kwargs)
        self._context = self._browser.new_context(
            user_agent=user_agent,
            locale=locale,
        )
        self._request = self._context.request
        self.cookies = PlaywrightCookieJar(self._context)

        if not headless:
            try:
                self._page = self._context.new_page()
                if initial_url:
                    self._page.goto(initial_url, wait_until="domcontentloaded", timeout=15000)
                else:
                    self._page.goto("about:blank")
            except Exception as exc:
                logger.debug("Playwright headful page open failed: %s", exc)

    @property
    def is_closed(self) -> bool:
        return self._closed

    @property
    def page(self):
        if not self._page and self._context:
            try:
                self._page = self._context.new_page()
                self._page.goto("about:blank")
            except Exception as exc:
                logger.debug("Playwright page init failed: %s", exc)
        return self._page

    def open_page(self, url: str) -> None:
        if not self._page or not url:
            return
        try:
            self._page.goto(url, wait_until="domcontentloaded", timeout=15000)
        except Exception as exc:
            logger.debug("Playwright page navigation failed: %s", exc)

    def request(self, method: str, url: str, **kwargs) -> PlaywrightResponse:
        if not self._request:
            raise PlaywrightClientError("Playwright request context not initialized")

        headers = kwargs.get("headers") or {}
        data = kwargs.get("data")
        json_data = kwargs.get("json")
        timeout = kwargs.get("timeout", 30)
        allow_redirects = kwargs.get("allow_redirects", True)

        form = None
        if isinstance(data, dict) and json_data is None:
            form = data
            data = None
        if json_data is not None:
            if not any(k.lower() == "content-type" for k in headers.keys()):
                headers["content-type"] = "application/json"
            data = json.dumps(json_data)
            json_data = None
        if form is not None:
            if not any(k.lower() == "content-type" for k in headers.keys()):
                headers["content-type"] = "application/x-www-form-urlencoded"
            try:
                from urllib.parse import urlencode
                data = urlencode(form, doseq=True)
                form = None
            except Exception:
                pass

        timeout_ms = int(timeout * 1000)
        extra_kwargs: Dict[str, Any] = {}
        if allow_redirects is False:
            extra_kwargs["max_redirects"] = 0

        method_upper = (method or "GET").upper()
        if method_upper == "GET":
            request_kwargs: Dict[str, Any] = {
                "headers": headers,
                "timeout": timeout_ms,
            }
            request_kwargs.update(extra_kwargs)
            response = self._request.get(url, **request_kwargs)
        elif method_upper == "POST":
            request_kwargs = {
                "headers": headers,
                "timeout": timeout_ms,
            }
            if data is not None:
                request_kwargs["data"] = data
            request_kwargs.update(extra_kwargs)
            response = self._request.post(url, **request_kwargs)
        else:
            request_kwargs = {
                "method": method_upper,
                "headers": headers,
                "timeout": timeout_ms,
            }
            if data is not None:
                request_kwargs["data"] = data
            request_kwargs.update(extra_kwargs)
            response = self._request.fetch(url, **request_kwargs)

        return PlaywrightResponse(response)

    def get(self, url: str, **kwargs) -> PlaywrightResponse:
        return self.request("GET", url, **kwargs)

    def post(self, url: str, data: Any = None, json: Any = None, **kwargs) -> PlaywrightResponse:
        return self.request("POST", url, data=data, json=json, **kwargs)

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            if self._context:
                self._context.close()
        except Exception:
            pass
        try:
            if self._browser:
                self._browser.close()
        except Exception:
            pass
        try:
            if self._playwright:
                self._playwright.stop()
        except Exception:
            pass


class PlaywrightOpenAIClient:
    """OpenAI client backed by Playwright session."""

    def __init__(
        self,
        *,
        proxy_url: Optional[str] = None,
        browser_channel: str = "chrome",
        headless: bool = False,
    ):
        self.proxy_url = proxy_url
        self.browser_channel = browser_channel or "chrome"
        self.headless = headless
        self._session: Optional[PlaywrightSession] = None

        self.default_headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                         "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Accept": "application/json",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive",
            "Sec-Fetch-Dest": "empty",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Site": "same-site",
        }

    @property
    def session(self) -> PlaywrightSession:
        if self._session is None or self._session.is_closed:
            self._session = PlaywrightSession(
                proxy_url=self.proxy_url,
                browser_channel=self.browser_channel,
                headless=self.headless,
                user_agent=self.default_headers.get("User-Agent"),
                locale="zh-CN",
                initial_url="https://chatgpt.com/",
            )
        return self._session

    def open_browser_url(self, url: str) -> None:
        try:
            self.session.open_page(url)
        except Exception as exc:
            logger.debug("Playwright open browser url failed: %s", exc)

    def close(self) -> None:
        if self._session:
            self._session.close()
            self._session = None

    def check_ip_location(self) -> Tuple[bool, Optional[str]]:
        try:
            response = self.session.get("https://cloudflare.com/cdn-cgi/trace", timeout=10)
            trace_text = response.text or ""

            import re
            loc_match = re.search(r"loc=([A-Z]+)", trace_text)
            loc = loc_match.group(1) if loc_match else None

            if loc in ["CN", "HK", "MO", "TW"]:
                return False, loc
            return True, loc
        except Exception as exc:
            logger.error("Failed to check IP location: %s", exc)
            return False, None

    def check_sentinel(self, did: str, proxies: Optional[Dict] = None) -> Optional[str]:
        from ..config.constants import OPENAI_API_ENDPOINTS
        from .openai.sentinel import SentinelPOWError, build_sentinel_pow_token

        try:
            pow_token = build_sentinel_pow_token(self.default_headers.get("User-Agent", ""))
            sen_req_body = json.dumps({
                "p": pow_token,
                "id": did,
                "flow": "authorize_continue",
            }, separators=(",", ":"))

            response = self.session.post(
                OPENAI_API_ENDPOINTS["sentinel"],
                headers={
                    "origin": "https://sentinel.openai.com",
                    "referer": "https://sentinel.openai.com/backend-api/sentinel/frame.html?sv=20260219f9f6",
                    "content-type": "text/plain;charset=UTF-8",
                },
                data=sen_req_body,
            )

            if response.status_code == 200:
                return (response.json() or {}).get("token")
            logger.warning("Sentinel check failed: %s", response.status_code)
            return None

        except SentinelPOWError as exc:
            logger.error("Sentinel POW solving failed: %s", exc)
            return None
        except Exception as exc:
            logger.error("Sentinel check error: %s", exc)
            return None
