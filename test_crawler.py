import csv
import io
import subprocess
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from broken_link_check import build_session, check_one_url, process_file
from crawler import crawl_site, in_scope, normalize_url, validate_start_url


class Handler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

    def do_HEAD(self):
        self.respond(False)

    def do_GET(self):
        self.respond(True)

    def respond(self, body):
        self.server.seen.append((self.command, self.path))
        status, headers, content = self.server.routes.get(
            self.path, (404, {"Content-Type": "text/html"}, "Not found")
        )
        if self.command == "HEAD" and self.path.endswith("/fallback"):
            status, headers = 405, {}
        self.send_response(status)
        for key, value in headers.items():
            self.send_header(key, value)
        self.end_headers()
        if body:
            self.wfile.write(content.encode())


def html(content):
    return 200, {"Content-Type": "text/html; charset=utf-8"}, content


class CrawlTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.servers = []
        for _ in range(2):
            server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
            server.routes = {}
            server.seen = []
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            cls.servers.append((server, thread))
        cls.internal, cls.external = [item[0] for item in cls.servers]
        cls.origin = f"http://127.0.0.1:{cls.internal.server_port}"
        cls.external_origin = f"http://127.0.0.1:{cls.external.server_port}"

    @classmethod
    def tearDownClass(cls):
        for server, thread in cls.servers:
            server.shutdown()
            server.server_close()
            thread.join()

    def setUp(self):
        self.internal.seen.clear()
        self.external.seen.clear()
        self.external.routes = {
            "/external": html('<a href="/must-not-discover">outside child</a>'),
        }
        self.internal.routes = {
            "/section/": html(f"""
                <a href="child">child</a><a href="child#duplicate">same child</a>
                <a href="old">redirect</a><a href="exit">external redirect</a>
                <a href="missing">broken</a>
                <a href="/section-other/">sibling</a>
                <a href="{self.external_origin}/external">external</a>
                <a href="{self.external_origin}/broken">external broken</a>
                <a href="document.pdf">document</a><a href="fallback">fallback</a>
                <a href="fetch-fails">GET failure</a>
                <a href="mailto:help@example.com">email</a>
                <a href="http://[invalid">malformed</a>
            """),
            "/section/child": html('<a href="missing">broken again</a><a href="./">cycle</a>'),
            "/section/old": (301, {"Location": "hop"}, ""),
            "/section/hop": (302, {"Location": "new"}, ""),
            "/section/new": html('<base href="/section/nested/"><area href="leaf">'),
            "/section/nested/leaf": html("leaf"),
            "/section/exit": (302, {"Location": self.external_origin + "/external"}, ""),
            "/section-other/": html('<a href="/must-not-discover">outside child</a>'),
            "/section/document.pdf": (200, {"Content-Type": "application/pdf"},
                                      '<a href="/section/not-html">not a link</a>'),
            "/section/fallback": (302, {"Location": "new"}, ""),
            "/section/fetch-fails": (500, {"Content-Type": "text/html"}, "Failure"),
        }

    def rows(self, report):
        return list(csv.DictReader(io.StringIO(report)))

    def test_scoped_discovery_external_checks_redirects_and_sources(self):
        updates = []
        result = crawl_site(self.origin + "/section/", retries=0, progress=updates.append)
        bad = self.rows(result["bad_csv"])
        redirected = self.rows(result["redirected_csv"])
        self.assertTrue(any(row["url"] == self.external_origin + "/broken" for row in bad))
        missing = [row for row in bad if row["url"] == self.origin + "/section/missing"]
        self.assertEqual({row["source_page"] for row in missing}, {
            self.origin + "/section/", self.origin + "/section/child",
        })
        old = next(row for row in redirected if row["url"].endswith("/old"))
        self.assertIn("301", old["redirect_chain"])
        self.assertIn("302", old["redirect_chain"])
        self.assertEqual(old["final_url"], self.origin + "/section/new")
        self.assertTrue(any(row["url"].endswith("/fallback") for row in redirected))
        self.assertIn(("GET", "/section/nested/leaf"), self.internal.seen)
        self.assertNotIn(("GET", "/section-other/"), self.internal.seen)
        self.assertFalse(any(path == "/must-not-discover" for _, path in self.internal.seen))
        self.assertFalse(any(path == "/must-not-discover" for _, path in self.external.seen))
        self.assertFalse(any(path == "/section/not-html" for _, path in self.internal.seen))
        self.assertEqual(self.internal.seen.count(("GET", "/section/child")), 1)
        self.assertTrue(any(row["page_url"].endswith("/fetch-fails")
                            for row in self.rows(result["crawl_errors_csv"])))
        self.assertEqual(updates[-1]["processed"], updates[-1]["total"])
        self.assertEqual(updates[-1]["phase"], "checking")

    def test_root_redirect_does_not_expand_scope(self):
        self.internal.routes["/section/"] = (
            302, {"Location": "/section-other/"}, ""
        )
        result = crawl_site(self.origin + "/section/", retries=0)
        self.assertEqual(result["pages_crawled"], 1)
        self.assertEqual(result["total_redirected"], 1)
        self.assertNotIn(("GET", "/section-other/"), self.internal.seen)

    def test_start_failure_is_explicit(self):
        result = crawl_site(self.origin + "/absent/", retries=0)
        self.assertEqual(result["total_bad"], 1)
        self.assertEqual(result["total_crawl_errors"], 1)
        self.assertIn("HTTP 404", result["crawl_errors_csv"])

    def test_crawl_limit_boundaries(self):
        for count in (599, 600, 601):
            with self.subTest(urls=count):
                self.internal.seen.clear()
                for index in range(count):
                    self.internal.routes[f"/many/{index}"] = html(
                        f'<a href="{index + 1}">next</a>' if index < count - 1 else "last"
                    )
                updates = []
                # Start at the directory URL so every numbered URL is in scope.
                self.internal.routes["/many/"] = self.internal.routes["/many/0"]
                result = crawl_site(self.origin + "/many/", retries=0, progress=updates.append)
                reached = count >= 600
                self.assertEqual(result["pages_crawled"], min(count, 600))
                self.assertEqual(result["crawl_limit"], 600)
                self.assertEqual(result["crawl_limit_reached"], reached)
                self.assertEqual(result["pages_remaining"], max(count - 600, 0))
                self.assertEqual(result["total_good"], count)
                self.assertEqual(result["total_crawl_errors"], int(reached))
                self.assertEqual("Crawl limit of 600" in result["crawl_errors_csv"], reached)
                self.assertEqual(updates[-1]["crawl_limit_reached"], reached)
                if count > 600:
                    self.assertNotIn(("GET", "/many/600"), self.internal.seen)
                    self.assertIn(("HEAD", "/many/600"), self.internal.seen)

    def test_redirect_ending_in_failure_in_both_reports(self):
        self.internal.routes["/section/"] = (302, {"Location": "/absent"}, "")
        result = crawl_site(self.origin + "/section/", retries=0)
        self.assertEqual(result["total_bad"], 1)
        self.assertEqual(result["total_redirected"], 1)
        self.assertEqual(self.rows(result["bad_csv"])[0]["status_code"], "404")

    def test_redirect_loop_is_broken_and_redirected(self):
        self.internal.routes["/section/"] = (302, {"Location": "/section/"}, "")
        result = crawl_site(self.origin + "/section/", retries=0)
        self.assertEqual(result["pages_crawled"], 1)
        self.assertEqual(result["total_bad"], 1)
        self.assertEqual(result["total_redirected"], 1)
        self.assertIn("TooManyRedirects", result["bad_csv"])

    def test_url_normalization_and_scope(self):
        root = "https://example.com/section/"
        for path in ("/section", "/section/", "/section/child?x=1"):
            self.assertTrue(in_scope("https://example.com" + path, root))
        self.assertTrue(in_scope("http://example.com/section/", root))
        for url in (
            "https://example.com/section-other/",
            "https://sub.example.com/section/",
            "https://example.com/section/%2e%2e/outside",
            "https://example.com:444/section/",
        ):
            self.assertFalse(in_scope(url, root), url)
        self.assertEqual(normalize_url("HTTPS://EXAMPLE.COM:443/section/a/../#part"),
                         root)
        for invalid in ("", "file:///etc/passwd", "https://user:pass@example.com/",
                        "http://[bad", "http://example.com:bad"):
            with self.assertRaises(ValueError):
                validate_start_url(invalid)

    def test_connection_failure_report(self):
        with patch("crawler.build_session") as factory:
            import requests
            session = factory.return_value.__enter__.return_value
            session.get.side_effect = requests.ConnectionError("Connection refused")
            session.head.side_effect = requests.ConnectionError("Connection refused")
            result = crawl_site(self.origin + "/section/", retries=0)
        self.assertEqual(result["total_crawl_errors"], 1)
        self.assertEqual(result["total_bad"], 1)
        self.assertIn("Connection refused", result["bad_csv"])

    def test_csv_checker_behavior_is_preserved(self):
        with tempfile.TemporaryDirectory() as directory, build_session(0) as session:
            folder = Path(directory)
            source = folder / "input.csv"
            source.write_text(f"url\n{self.origin}/section/old\n{self.origin}/missing\n",
                              encoding="utf-8")
            good, bad, good_count, bad_count = process_file(
                source, folder, session, 2, 2, 0, False,
            )
            self.assertEqual((good_count, bad_count), (1, 1))
            self.assertEqual(self.rows(good.read_text())[0]["final_url"],
                             self.origin + "/section/new")
            self.assertEqual(self.rows(bad.read_text())[0]["status_code"], "404")

    def test_cli_writes_reports(self):
        self.internal.routes["/section/"] = html("No links")
        with tempfile.TemporaryDirectory() as directory:
            completed = subprocess.run([
                sys.executable, str(Path(__file__).parent / "broken_link_check.py"),
                "--start-url", self.origin + "/section/",
                "--output-dir", directory, "--retries", "0",
            ], capture_output=True, text=True, timeout=20)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual({path.name for path in Path(directory).glob("*.csv")},
                             {"crawl_good.csv", "crawl_bad.csv",
                              "crawl_redirected.csv", "crawl_errors.csv"})

    def test_cli_reports_crawl_limit(self):
        from broken_link_check import main

        reports = {
            "pages_crawled": 600, "total_good": 601, "total_bad": 0,
            "total_redirected": 0, "total_crawl_errors": 1,
            "crawl_limit_reached": True, "crawl_limit": 600, "pages_remaining": 1,
        }
        output = io.StringIO()
        with patch("crawler.crawl_site", return_value=reports), patch(
            "crawler.write_crawl_reports"
        ), patch.object(sys, "argv", [
            "broken_link_check.py", "--start-url", self.origin + "/section/",
        ]), patch("sys.stdout", output):
            self.assertEqual(main(), 0)
        self.assertIn("WARNING: Crawl limit of 600 URLs reached", output.getvalue())
        self.assertIn("1 discovered in-scope URLs were not crawled", output.getvalue())


class WebTests(unittest.TestCase):
    def setUp(self):
        import app
        self.module = app
        self.client = app.app.test_client()

    def test_crawl_form_and_enqueue(self):
        self.assertIn(b'Start Crawl', self.client.get("/").data)
        with patch.object(self.module.q, "enqueue") as enqueue:
            enqueue.return_value.get_id.return_value = "crawl-id"
            response = self.client.post("/", data={
                "mode": "crawl", "start_url": "https://example.com/section/",
            })
            self.assertEqual(response.status_code, 302)
            self.assertIn("/status/crawl-id", response.location)
            enqueue.assert_called_once_with(
                self.module.process_crawl_task, "https://example.com/section/",
                job_timeout=-1, result_ttl=3600,
            )

    def test_invalid_start_url_not_enqueued(self):
        with patch.object(self.module.q, "enqueue") as enqueue:
            response = self.client.post("/", data={"mode": "crawl", "start_url": "bad"})
        self.assertEqual(response.status_code, 400)
        self.assertIn(b'role="alert"', response.data)
        enqueue.assert_not_called()

    def test_csv_upload_unchanged(self):
        with patch.object(self.module.q, "enqueue") as enqueue:
            enqueue.return_value.get_id.return_value = "csv-id"
            response = self.client.post("/", data={
                "file": (io.BytesIO(b"url\nhttps://example.com\n"), "urls.csv"),
            })
        self.assertEqual(response.status_code, 302)
        enqueue.assert_called_once_with(
            self.module.process_csv_task, "url\nhttps://example.com\n", result_ttl=3600,
        )

    def test_crawl_downloads_and_status(self):
        result = {
            "good_csv": "good", "bad_csv": "bad", "redirected_csv": "redirects",
            "crawl_errors_csv": "errors", "total_good": 1, "total_bad": 2,
            "total_redirected": 1, "total_crawl_errors": 1, "pages_crawled": 3,
            "crawl_limit": 600, "crawl_limit_reached": True, "pages_remaining": 5,
        }
        job = SimpleNamespace(
            is_finished=True, is_failed=False, result=result, meta={},
            get_status=lambda: "finished", get_id=lambda: "id",
        )
        with patch.object(self.module.Job, "fetch", return_value=job):
            page = self.client.get("/status/id")
            self.assertEqual(page.status_code, 200)
            self.assertIn(b"Discovery issues", page.data)
            self.assertIn(b"Download Redirected URLs", page.data)
            self.assertIn(b"Crawl limit of 600 URLs reached", page.data)
            self.assertIn(b"5 discovered in-scope URLs were not crawled", page.data)
            for kind in ("good", "bad", "redirected", "crawl_errors"):
                response = self.client.get(f"/download/id/{kind}")
                self.assertEqual(response.status_code, 200)
                self.assertEqual(response.data.decode(), result[f"{kind}_csv"])

    def test_discovery_status(self):
        job = SimpleNamespace(
            is_finished=False, is_failed=False,
            meta={"phase": "discovering", "pages_crawled": 3, "links_discovered": 8},
            get_status=lambda: "started", get_id=lambda: "id",
        )
        with patch.object(self.module.Job, "fetch", return_value=job):
            response = self.client.get("/status/id")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Discovering pages: 3", response.data)

    def test_checking_status_reports_limit(self):
        job = SimpleNamespace(
            is_finished=False, is_failed=False,
            meta={"phase": "checking", "crawl_limit_reached": True,
                  "crawl_limit": 600, "pages_remaining": 1},
            get_status=lambda: "started", get_id=lambda: "id",
        )
        with patch.object(self.module.Job, "fetch", return_value=job):
            response = self.client.get("/status/id")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Crawl limit of 600 URLs reached", response.data)
        self.assertIn(b"1 discovered in-scope URLs were not crawled", response.data)

    def test_background_task_updates_progress(self):
        import tasks
        job = SimpleNamespace(meta={}, save_meta=lambda: None)

        def crawl(start_url, progress):
            progress({"phase": "checking", "processed": 2, "total": 2})
            return {"good_csv": "checked"}

        with patch.object(tasks, "get_current_job", return_value=job), patch(
            "crawler.crawl_site", side_effect=crawl,
        ):
            result = tasks.process_crawl_task("https://example.com/")
        self.assertEqual(result, {"good_csv": "checked"})
        self.assertEqual(job.meta["processed"], 2)
        self.assertEqual(job.meta["phase"], "checking")


if __name__ == "__main__":
    unittest.main()
