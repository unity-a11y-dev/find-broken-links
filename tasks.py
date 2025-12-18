import csv
import re
import time
import io
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Set, Tuple
from urllib.parse import urlparse

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

URL_RE = re.compile(
    r"""(?xi)
    \b(
        https?://[^\s<>"'\]\)}]+
    )
    """
)

@dataclass(frozen=True)
class LinkResult:
    url: str
    final_url: str
    status_code: Optional[int]
    ok: bool
    error: str
    method: str
    elapsed_s: float

def build_session(retries: int) -> requests.Session:
    session = requests.Session()
    retry = Retry(
        total=retries,
        connect=retries,
        read=retries,
        status=retries,
        backoff_factor=0.5,
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=frozenset(["HEAD", "GET"]),
        raise_on_status=False,
    )
    adapter = HTTPAdapter(max_retries=retry, pool_connections=100, pool_maxsize=100)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    session.headers.update(
        {
            "User-Agent": "Mozilla/5.0 (compatible; LinkChecker/1.0; +https://example.com)",
            "Accept": "*/*",
        }
    )
    return session

def is_probably_url(s: str) -> bool:
    if not s:
        return False
    u = s.strip()
    if not (u.startswith("http://") or u.startswith("https://")):
        return False
    try:
        p = urlparse(u)
        return bool(p.scheme and p.netloc)
    except Exception:
        return False

def extract_urls_from_row(values: Iterable[str]) -> List[str]:
    urls: List[str] = []
    for v in values:
        if v is None:
            continue
        text = str(v)
        for m in URL_RE.findall(text):
            url = m.rstrip(").,;:'\"!?]}>")
            urls.append(url)
    return urls

def sniff_dialect(sample: str) -> csv.Dialect:
    try:
        return csv.Sniffer().sniff(sample)
    except Exception:
        return csv.excel

def read_csv_urls_from_string(csv_content: str) -> Tuple[Set[str], Dict[str, int]]:
    """
    Reads CSV content string and extracts URLs from ANY column.
    Returns:
      - set of unique URLs
      - frequency count per URL (how many times it appeared)
    """
    urls: Set[str] = set()
    counts: Dict[str, int] = {}

    try:
        # We assume the content is already decoded to string by the uploader or we handle bytes before calling this
        f = io.StringIO(csv_content)
        sample = f.read(8192)
        f.seek(0)
        dialect = sniff_dialect(sample)
        reader = csv.DictReader(f, dialect=dialect)
        for row in reader:
            row_urls = extract_urls_from_row(row.values())
            for u in row_urls:
                if not is_probably_url(u):
                    continue
                urls.add(u)
                counts[u] = counts.get(u, 0) + 1
        return urls, counts
    except Exception as e:
        # If basic parsing fails, we might want to log it or re-raise
        print(f"Error parsing CSV: {e}")
        return set(), {}

def check_one_url(
    session: requests.Session,
    url: str,
    timeout: float,
    delay: float,
    treat_403_active: bool,
) -> LinkResult:
    if delay > 0:
        time.sleep(delay)

    start = time.time()
    final_url = url
    status_code: Optional[int] = None
    method_used = ""
    last_err = ""

    def ok_status(code: int) -> bool:
        if 200 <= code <= 399:
            return True
        if code == 403 and treat_403_active:
            return True
        return False

    # HEAD first
    try:
        method_used = "HEAD"
        resp = session.head(url, allow_redirects=True, timeout=timeout)
        final_url = str(resp.url)
        status_code = int(resp.status_code)

        if ok_status(status_code):
            return LinkResult(url, final_url, status_code, True, "", method_used, round(time.time() - start, 3))

        # fall back to GET for likely HEAD-blocking / transient cases
        if status_code in (400, 401, 403, 405, 406, 409, 415) or status_code >= 500:
            last_err = f"HEAD returned {status_code}"
        else:
            return LinkResult(url, final_url, status_code, False, f"HTTP {status_code}", method_used, round(time.time() - start, 3))

    except requests.RequestException as e:
        last_err = f"HEAD exception: {type(e).__name__}: {e}"

    # GET fallback
    try:
        method_used = "GET"
        resp = session.get(url, allow_redirects=True, timeout=timeout, stream=True)
        final_url = str(resp.url)
        status_code = int(resp.status_code)
        try:
            resp.close()
        except Exception:
            pass

        ok = ok_status(status_code)
        return LinkResult(
            url,
            final_url,
            status_code,
            ok,
            "" if ok else f"HTTP {status_code}",
            method_used,
            round(time.time() - start, 3),
        )
    except requests.RequestException as e:
        return LinkResult(
            url,
            final_url,
            status_code,
            False,
            f"{last_err} | GET exception: {type(e).__name__}: {e}",
            method_used or "GET",
            round(time.time() - start, 3),
        )

def generate_results_csv(results: List[LinkResult], counts: Dict[str, int]) -> str:
    fieldnames = [
        "url",
        "final_url",
        "status_code",
        "ok",
        "error",
        "method",
        "elapsed_s",
        "occurrences_in_input",
    ]
    output = io.StringIO()
    w = csv.DictWriter(output, fieldnames=fieldnames)
    w.writeheader()
    for r in results:
        w.writerow(
            {
                "url": r.url,
                "final_url": r.final_url,
                "status_code": r.status_code if r.status_code is not None else "",
                "ok": "true" if r.ok else "false",
                "error": r.error,
                "method": r.method,
                "elapsed_s": r.elapsed_s,
                "occurrences_in_input": counts.get(r.url, 0),
            }
        )
    return output.getvalue()

def process_csv_task(csv_content: str, timeout=12.0, workers=20, delay=0.0, treat_403_active=False):
    """
    Task to be executed by RQ worker.
    Returns a dictionary with 'good_csv' and 'bad_csv' strings.
    """
    session = build_session(retries=2)
    urls, counts = read_csv_urls_from_string(csv_content)
    
    if not urls:
        empty_csv = generate_results_csv([], counts)
        return {
            "good_csv": empty_csv,
            "bad_csv": empty_csv,
            "total_good": 0,
            "total_bad": 0
        }

    active: List[LinkResult] = []
    broken: List[LinkResult] = []

    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = [
            ex.submit(check_one_url, session, u, timeout, delay, treat_403_active)
            for u in urls
        ]
        for fut in as_completed(futures):
            res = fut.result()
            (active if res.ok else broken).append(res)

    active.sort(key=lambda r: (r.status_code or 999, r.url))
    broken.sort(key=lambda r: (r.status_code or 999, r.url))

    good_csv = generate_results_csv(active, counts)
    bad_csv = generate_results_csv(broken, counts)

    return {
        "good_csv": good_csv,
        "bad_csv": bad_csv,
        "total_good": len(active),
        "total_bad": len(broken)
    }
