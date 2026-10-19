# find-broken-links

Find broken and redirected links using the web interface. You can either:

- **Crawl a website section** from a starting URL, or
- **Upload a CSV file** that contains URLs to check.

## Crawl a website section

1. Open the Broken Link Checker web page.
2. Under **Crawl a website section**, enter the **Starting URL**, for example
   `https://example.com/department/`.
3. Select **Start Crawl**.
4. Keep the status page open. It refreshes every 5 seconds and shows:
   - **Queued**: the check is waiting to start.
   - **Discovering pages**: pages fetched so far and unique links found.
   - **Processing URL _x_ of _y_**: links being checked.
5. When the check is complete, download the reports you need.

### What gets crawled

- Only pages on the **same host** (treating `www` and non-`www` variants as
  equivalent), with the **same port** and **under the starting path**, are crawled.
  Starting at `https://example.com/department/` includes
  `https://example.com/department/team` and `https://www.example.com/department/`,
  but not `https://example.com/department-other/`,
  `https://sub.example.com/department/`, or other websites.
  Redirects between `www` and non-`www` variants are followed during discovery
  when they remain within these path and port boundaries.
- To crawl an entire section, enter the section folder URL (ending in `/`) instead
  of a specific page such as `.../department/index.html`.
- **All links found on crawled pages are checked**, including links to other
  websites and other sections. Those pages are not crawled for more links.
- The crawler reads links in standard HTML link elements (`<a href>` and
  `<area href>`). It does not check links created by JavaScript, images, scripts,
  stylesheets, or whether a `#section` fragment exists on the page.
  `mailto:`, `tel:`, and other non-web links are skipped.

### 600-URL crawl limit

The crawler fetches up to **600 in-scope URLs**. Links found on those pages are
still checked, even if there are more than 600 links.

When the limit is reached, the status page shows **Crawl limit of 600 URLs
reached** and how many discovered pages were not crawled. The warning also
appears in the **Crawl Errors** report. To check the remaining pages, start
separate crawls from smaller subsections.

### Crawl reports

| Download | Contents |
| --- | --- |
| **Good URLs** | Links that worked, including links that redirect to a working page |
| **Bad URLs** | Links that returned an error or could not be reached |
| **Redirected URLs** | Links that redirected, whether the final page worked or failed |
| **Crawl Errors** | Pages that could not be crawled, and any crawl-limit warning |

A redirected link appears in **Redirected URLs** and in either **Good URLs** or
**Bad URLs**, depending on its final result.

Link report columns:

| Column | Meaning |
| --- | --- |
| `source_page` | The page where the link was found |
| `url` | The link as found on the page |
| `final_url` | The address reached after following redirects |
| `status_code` | The final HTTP status code; blank if no response was received |
| `ok` | `true` if the link worked; `false` if it is broken |
| `error` | Why the link failed (see [Errors](#errors-with-no-status-code)) |
| `redirect_chain` | Each redirect step, such as `301 https://old -> https://new` |

A link used on several pages appears once for each page where it was found.
The starting URL is also checked and lists itself as its source page.

If **Crawl Errors** contains entries, some pages may not have been checked for
links. Review the errors and rerun the crawl if needed.

## Check URLs from a CSV file

1. Under **Check URLs from a CSV**, select a `.csv` file.
2. Select **Start Check**.
3. When the check is complete, download **Good URLs** and **Bad URLs**.

URLs beginning with `http://` or `https://` are found in any column, including
cells with multiple URLs. Each unique URL is checked once.

CSV report columns are `url`, `final_url`, `status_code`, `ok`, `error`,
`method`, `elapsed_s`, and `occurrences_in_input` (how many times the URL appeared
in the uploaded file). Links that redirect to a working page are listed as good;
compare `url` and `final_url` to find them.

## Results availability

Reports are available for **one hour** after a check completes. Download them
before then, or run the check again.

## Understanding the results

Each link is checked as follows:

- Redirects are followed to the final page.
- Status codes **200–399** are treated as working (`ok` is `true`).
- All other status codes are treated as broken.
- Requests time out after **12 seconds**.
- **429** and **5xx** responses, and connection errors, are retried up to
  **2 times** before being reported.
- If the server rejects a lightweight check (`HEAD`) with a 400, 401, 403, 405,
  406, 409, 415, or 5xx status, the link is checked again with a normal page
  request (`GET`). The `error` column then begins with `HEAD returned ...`.

### HTTP status codes

| Code | Name | Result | What it means / what to do |
| --- | --- | --- | --- |
| 200 | OK | Working | The page loaded successfully. |
| 201–299 | Other success codes | Working | The server reported success. |
| 301 | Moved Permanently | Redirect | The link moved permanently. Update the link to `final_url`. |
| 302 | Found | Redirect | Temporary redirect. Often normal (e.g., login or tracking pages); review if unexpected. |
| 303 | See Other | Redirect | The server sent the browser to a different page. Usually normal. |
| 307 | Temporary Redirect | Redirect | Temporary redirect. Usually acceptable, but review if unexpected. |
| 308 | Permanent Redirect | Redirect | The link moved permanently. Update the link to `final_url`. |
| 300–399 (final) | Unfollowed redirect | Working | Rare. The server returned a redirect status without a usable destination. Verify manually. |
| 400 | Bad Request | Broken | The server rejected the URL. Check for typos or invalid characters. |
| 401 | Unauthorized | Broken | Sign-in is required. The page may work for signed-in users; verify manually. |
| 403 | Forbidden | Broken | Access was denied. The page may exist but block automated checkers; verify in a browser. |
| 404 | Not Found | Broken | The page does not exist. Fix or remove the link. |
| 405 | Method Not Allowed | Broken | The server rejected the request type even after retrying with `GET`. Verify manually. |
| 406 | Not Acceptable | Broken | The server would not return a format the checker accepts. Verify in a browser. |
| 408 | Request Timeout | Broken | The server took too long to receive the request. Retry later. |
| 410 | Gone | Broken | The page was intentionally removed. Remove or replace the link. |
| 429 | Too Many Requests | Broken | The server is rate-limiting the checker. Retry later or verify manually. |
| 451 | Unavailable for Legal Reasons | Broken | Access is blocked for legal reasons. |
| Other 4xx | Client error | Broken | The link or request is not accepted by the server. Verify manually. |
| 500 | Internal Server Error | Broken | The website had an error. Retry later; report persistent problems to the site owner. |
| 502 | Bad Gateway | Broken | A server between the checker and the website failed. Often temporary. |
| 503 | Service Unavailable | Broken | The website is down, overloaded, or under maintenance. Retry later. |
| 504 | Gateway Timeout | Broken | A server between the checker and the website timed out. Often temporary. |
| Other 5xx | Server error | Broken | The website had a problem. Retry later. |

**401, 403, 429, and 5xx results are not always truly broken.** These links may
work in a browser, for signed-in users, or at another time. Verify them manually
before changing them.

### Errors with no status code

When `status_code` is blank, the website did not return a usable response. The
`error` column contains the reason:

| Error contains | What it means / what to do |
| --- | --- |
| `ConnectionError`, `Failed to resolve`, `Name or service not known`, `getaddrinfo failed` | The domain does not exist or cannot be found. Check the link for typos; the website may no longer exist. |
| `ConnectionError`, `Connection refused`, `Max retries exceeded` | The server could not be reached or refused the connection. It may be down or blocking the checker. |
| `ConnectTimeout` | The server did not accept a connection within 12 seconds. |
| `ReadTimeout` | The server connected but did not respond within 12 seconds. |
| `SSLError`, `CERTIFICATE_VERIFY_FAILED` | The website's security certificate is invalid, expired, or does not match the domain. Visitors may see a security warning. |
| `TooManyRedirects` | The link redirects in a loop or through more than 30 redirects. A status code may also be shown. |
| `InvalidURL`, `InvalidSchema`, `MissingSchema` | The URL is malformed. Correct the link. |
| `ChunkedEncodingError`, `ContentDecodingError` | The server sent an incomplete or corrupt response. Retry later. |

Error text such as `HEAD exception: ... | GET exception: ...` means both the
lightweight check and the normal page request failed.

### Crawl Errors report

| Error | What it means |
| --- | --- |
| `HTTP <code> during page discovery` | The page returned an error status, so its links could not be collected. See [HTTP status codes](#http-status-codes). |
| `ConnectionError`, `ReadTimeout`, `SSLError`, etc. | The page could not be fetched. See [Errors with no status code](#errors-with-no-status-code). |
| `Redirect target is not a valid HTTP(S) URL.` | The page redirected to an invalid address, so crawling could not continue from it. |
| `Crawl limit of 600 URLs reached; ...` | The crawl stopped discovering pages at 600 URLs. Remaining pages were not crawled. |

## Responsible use

Only crawl websites you have permission to scan. The crawler does not read
`robots.txt`, and it requests every crawled page and every link it checks.
