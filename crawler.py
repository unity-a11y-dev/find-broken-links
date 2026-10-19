"""Static HTML discovery scoped to a starting host and path."""

import csv
import io
import posixpath
import time
from collections import deque
from html.parser import HTMLParser
from pathlib import Path
from typing import Callable, Dict, List, Optional, Set, Tuple, TypedDict
from urllib.parse import unquote, urldefrag, urljoin, urlsplit, urlunsplit

import requests

from broken_link_check import LinkResult, build_session, check_one_url

CRAWL_LIMIT = 600


class CrawlReports(TypedDict):
    good_csv: str
    bad_csv: str
    redirected_csv: str
    crawl_errors_csv: str
    total_good: int
    total_bad: int
    total_redirected: int
    total_crawl_errors: int
    pages_crawled: int
    crawl_limit: int
    crawl_limit_reached: bool
    pages_remaining: int


def normalize_url(value: str) -> Optional[str]:
    try:
        value = urldefrag(value.strip())[0]
        parts = urlsplit(value)
        if parts.scheme.lower() not in ("http", "https") or not parts.hostname:
            return None
        if parts.username is not None or parts.password is not None:
            return None
        port = parts.port
        host = parts.hostname.lower()
        if ":" in host:
            host = f"[{host}]"
        if port is not None and port != (443 if parts.scheme.lower() == "https" else 80):
            host += f":{port}"
        path = parts.path or "/"
        # Resolve literal dot segments without conflating encoded URL identities.
        trailing_slash = path.endswith(("/", "/.", "/.."))
        path = posixpath.normpath(path)
        if trailing_slash and path != "/":
            path += "/"
        return urlunsplit((parts.scheme.lower(), host, path, parts.query, ""))
    except ValueError:
        return None


def validate_start_url(value: str) -> str:
    url = normalize_url(value)
    if url is None:
        raise ValueError("Enter a valid HTTP or HTTPS starting URL without credentials.")
    return url


def resolve_url(base: str, href: str) -> Optional[str]:
    try:
        return normalize_url(urljoin(base, href))
    except ValueError:
        return None


def in_scope(url: str, start_url: str) -> bool:
    candidate, start = urlsplit(url), urlsplit(start_url)
    if (candidate.hostname, candidate.port) != (start.hostname, start.port):
        return False
    # Decode before comparison so encoded traversal cannot escape the path boundary.
    root = posixpath.normpath(unquote(start.path)).rstrip("/")
    path = posixpath.normpath(unquote(candidate.path))
    return not root or path == root or path.startswith(root + "/")


class PageLinks(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.base: Optional[str] = None
        self.hrefs: List[str] = []

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]) -> None:
        attributes = dict(attrs)
        href = attributes.get("href")
        if href is None:
            return
        if tag == "base" and self.base is None:
            self.base = href
        elif tag in ("a", "area"):
            self.hrefs.append(href)


def results_csv(results: List[LinkResult], sources: Dict[str, Set[str]]) -> str:
    output = io.StringIO(newline="")
    writer = csv.DictWriter(output, fieldnames=[
        "source_page", "url", "final_url", "status_code", "ok", "error", "redirect_chain",
    ])
    writer.writeheader()
    for result in sorted(results, key=lambda item: item.url):
        for source in sorted(sources[result.url]):
            writer.writerow({
                "source_page": source, "url": result.url, "final_url": result.final_url,
                "status_code": result.status_code if result.status_code is not None else "",
                "ok": str(result.ok).lower(), "error": result.error,
                "redirect_chain": " | ".join(result.redirect_chain),
            })
    return output.getvalue()


def crawl_site(
    start_url: str,
    timeout: float = 12.0,
    retries: int = 2,
    delay: float = 0.0,
    treat_403_active: bool = False,
    progress: Optional[Callable[[Dict[str, object]], None]] = None,
) -> CrawlReports:
    start_url = validate_start_url(start_url)
    pending = deque([start_url])
    scheduled = {start_url}
    sources: Dict[str, Set[str]] = {start_url: {start_url}}
    page_errors: List[Tuple[str, str]] = []
    pages_crawled = 0

    def notify(phase: str, processed: int, total: int) -> None:
        if progress is not None:
            progress({
                "phase": phase, "processed": processed, "total": total,
                "pages_crawled": pages_crawled, "links_discovered": len(sources),
                "crawl_limit": CRAWL_LIMIT,
                "crawl_limit_reached": pages_crawled >= CRAWL_LIMIT,
                "pages_remaining": len(pending),
            })

    with build_session(retries) as session:
        while pending and pages_crawled < CRAWL_LIMIT:
            url = pending.popleft()
            notify("discovering", pages_crawled, len(scheduled))
            if delay > 0:
                time.sleep(delay)
            pages_crawled += 1
            try:
                # Never follow discovery redirects automatically: their targets may be external.
                with session.get(url, timeout=timeout, allow_redirects=False, stream=True) as response:
                    if response.is_redirect:
                        target = resolve_url(url, response.headers["Location"])
                        if target is None:
                            page_errors.append((url, "Redirect target is not a valid HTTP(S) URL."))
                        elif in_scope(target, start_url) and target not in scheduled:
                            scheduled.add(target)
                            pending.append(target)
                        continue
                    if not 200 <= response.status_code < 300:
                        page_errors.append((url, f"HTTP {response.status_code} during page discovery"))
                        continue
                    content_type = response.headers.get("Content-Type", "").split(";")[0].lower().strip()
                    if content_type not in ("text/html", "application/xhtml+xml"):
                        continue
                    parser = PageLinks()
                    parser.feed(response.text)
                    base = resolve_url(url, parser.base) if parser.base is not None else url
                    base = base or url
                    for href in parser.hrefs:
                        target = resolve_url(base, href)
                        if target is None:
                            continue
                        sources.setdefault(target, set()).add(url)
                        if in_scope(target, start_url) and target not in scheduled:
                            scheduled.add(target)
                            pending.append(target)
            except requests.RequestException as exc:
                page_errors.append((url, f"{type(exc).__name__}: {exc}"))

        if pages_crawled >= CRAWL_LIMIT:
            page_errors.append((
                start_url,
                f"Crawl limit of {CRAWL_LIMIT} URLs reached; "
                f"{len(pending)} discovered in-scope URLs were not crawled. "
                "All links found on crawled pages are still checked.",
            ))

        good: List[LinkResult] = []
        bad: List[LinkResult] = []
        redirected: List[LinkResult] = []
        notify("checking", 0, len(sources))
        for index, url in enumerate(sorted(sources), 1):
            result = check_one_url(session, url, timeout, delay, treat_403_active)
            (good if result.ok else bad).append(result)
            if result.redirect_chain:
                redirected.append(result)
            notify("checking", index, len(sources))

    errors = io.StringIO(newline="")
    writer = csv.writer(errors)
    writer.writerow(["page_url", "error"])
    writer.writerows(page_errors)
    return {
        "good_csv": results_csv(good, sources),
        "bad_csv": results_csv(bad, sources),
        "redirected_csv": results_csv(redirected, sources),
        "crawl_errors_csv": errors.getvalue(),
        "total_good": len(good), "total_bad": len(bad),
        "total_redirected": len(redirected), "total_crawl_errors": len(page_errors),
        "pages_crawled": pages_crawled,
        "crawl_limit": CRAWL_LIMIT,
        "crawl_limit_reached": pages_crawled >= CRAWL_LIMIT,
        "pages_remaining": len(pending),
    }


def write_crawl_reports(output_dir: Path, reports: CrawlReports) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    for name, content in (
        ("crawl_good", reports["good_csv"]), ("crawl_bad", reports["bad_csv"]),
        ("crawl_redirected", reports["redirected_csv"]), ("crawl_errors", reports["crawl_errors_csv"]),
    ):
        (output_dir / f"{name}.csv").write_text(content, encoding="utf-8")
