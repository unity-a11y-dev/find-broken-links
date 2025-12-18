#!/usr/bin/env python3
"""
Batch broken link checker for CSVs in ./input
- Reads every .csv in input/
- Extracts URLs from any cell (supports multiple URLs per cell)
- Checks each unique URL concurrently (HEAD then GET fallback)
- Writes outputs into output/:
    <input_basename>_good_urls.csv
    <input_basename>_bad_urls.csv

Usage:
  python broken_link_check_batch.py

Optional flags:
  --timeout 12
  --workers 20
  --retries 2
  --delay 0.0
  --treat-403-active
  --input-dir input
  --output-dir output
"""

import argparse
import csv
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
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


def read_csv_urls(path: Path) -> Tuple[Set[str], Dict[str, int]]:
    """
    Reads CSV and extracts URLs from ANY column.
    Returns:
      - set of unique URLs
      - frequency count per URL (how many times it appeared)
    """
    urls: Set[str] = set()
    counts: Dict[str, int] = {}

    # Try utf-8-sig first; if it fails, fall back to latin-1
    for enc in ("utf-8-sig", "utf-8", "latin-1"):
        try:
            with path.open("r", encoding=enc, newline="") as f:
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
        except UnicodeDecodeError:
            continue

    raise UnicodeDecodeError("Unable to decode file with utf-8/latin-1", b"", 0, 1, "decode error")


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


def write_results_csv(path: Path, results: List[LinkResult], counts: Dict[str, int]) -> None:
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
    with path.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
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


def process_file(
    csv_path: Path,
    out_dir: Path,
    session: requests.Session,
    timeout: float,
    workers: int,
    delay: float,
    treat_403_active: bool,
) -> Tuple[Path, Path, int, int]:
    urls, counts = read_csv_urls(csv_path)
    if not urls:
        # still create empty outputs
        good_path = out_dir / f"{csv_path.stem}_good_urls.csv"
        bad_path = out_dir / f"{csv_path.stem}_bad_urls.csv"
        write_results_csv(good_path, [], counts)
        write_results_csv(bad_path, [], counts)
        return good_path, bad_path, 0, 0

    active: List[LinkResult] = []
    broken: List[LinkResult] = []

    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = [
            ex.submit(check_one_url, session, u, timeout, delay, treat_403_active)
            for u in urls
        ]
        done = 0
        total = len(futures)
        for fut in as_completed(futures):
            res = fut.result()
            (active if res.ok else broken).append(res)
            done += 1
            if done % 50 == 0 or done == total:
                print(f"  {csv_path.name}: {done}/{total} checked...")

    active.sort(key=lambda r: (r.status_code or 999, r.url))
    broken.sort(key=lambda r: (r.status_code or 999, r.url))

    good_path = out_dir / f"{csv_path.stem}_good_urls.csv"
    bad_path = out_dir / f"{csv_path.stem}_bad_urls.csv"
    write_results_csv(good_path, active, counts)
    write_results_csv(bad_path, broken, counts)

    return good_path, bad_path, len(active), len(broken)


def main() -> int:
    parser = argparse.ArgumentParser(description="Batch broken link checker for CSVs in a folder.")
    parser.add_argument("--input-dir", default="input", help="Folder containing input CSV files.")
    parser.add_argument("--output-dir", default="output", help="Folder to write output CSV files.")
    parser.add_argument("--timeout", type=float, default=12.0, help="Per-request timeout seconds.")
    parser.add_argument("--workers", type=int, default=20, help="Concurrent workers per file.")
    parser.add_argument("--retries", type=int, default=2, help="Retry count for transient failures.")
    parser.add_argument("--delay", type=float, default=0.0, help="Optional delay (seconds) before each request.")
    parser.add_argument(
        "--treat-403-active",
        action="store_true",
        help="Treat HTTP 403 as active (useful when sites block bots).",
    )
    args = parser.parse_args()

    in_dir = Path(args.input_dir)
    out_dir = Path(args.output_dir)

    if not in_dir.exists() or not in_dir.is_dir():
        print(f"ERROR: input directory not found: {in_dir.resolve()}", file=sys.stderr)
        return 2

    out_dir.mkdir(parents=True, exist_ok=True)

    csv_files = sorted(in_dir.glob("*.csv"))
    if not csv_files:
        print(f"No .csv files found in {in_dir.resolve()}", file=sys.stderr)
        return 3

    session = build_session(retries=args.retries)

    print(f"Found {len(csv_files)} CSV file(s) in {in_dir.resolve()}")
    print(f"Writing outputs to {out_dir.resolve()}\n")

    total_good = 0
    total_bad = 0

    for csv_path in csv_files:
        print(f"Processing: {csv_path.name}")
        good_path, bad_path, good_n, bad_n = process_file(
            csv_path=csv_path,
            out_dir=out_dir,
            session=session,
            timeout=args.timeout,
            workers=args.workers,
            delay=args.delay,
            treat_403_active=args.treat_403_active,
        )
        total_good += good_n
        total_bad += bad_n
        print(f"  -> {good_path.name} ({good_n})")
        print(f"  -> {bad_path.name} ({bad_n})\n")

    print(f"Done. Total good: {total_good}, total bad: {total_bad}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
