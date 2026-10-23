# Sec Checker

A Docker app for uploading browser history, reviewing domains, and collecting evidence of exposure to the October 2026 PHP and eMudhra certificate incidents. It flags potential problems and unknowns; it does not prove website safety or account compromise.

## Start

Requires Docker Engine/Desktop and Docker Compose.

```sh
docker compose up --build -d
```

Open **http://SERVER_IP:8787** from your browser, or **http://127.0.0.1:8787** on the server itself. The service is published on all host interfaces by default. Rebuild/recreate the existing container after upgrading: `docker compose up --build -d --force-recreate`. To stop and clear container memory:

```sh
docker compose down
```

No browser profile mounts, privileged container, Docker socket mount, account passwords or external APIs are needed. The container runs as a non-root user with a read-only filesystem and temporary upload storage in RAM. Outbound Internet access is required for selected website checks. This is a single-user application. For access beyond a trusted private network, use an HTTPS reverse proxy and set an application password. Set `SEC_CHECKER_PASSWORD` in a local `.env` file, then recreate the container; the browser login username is `reviewer`. The password is optional for trusted local use. Basic authentication and uploaded files need HTTPS protection on untrusted networks. To bind only one interface, set `SEC_CHECKER_BIND_IP=192.168.1.10` (or `127.0.0.1` for local-only access).

## Import, review, check

1. Upload Chrome’s `History` SQLite database or Takeout `BrowserHistory.json`. Optionally attach the same Chrome profile’s `Login Data` database to associate stored-password entries with sites (256 MB combined; unzip archives first).
2. Review the domain list. Nothing is selected initially. Common adult domains are filtered, but automatic filtering is incomplete. Exclude sensitive domains before starting a scan.
3. Select the sites, confirm the review, and run the checks. Select stored-password sites or login-path hints as a selection aid. Stored entries and login paths do not prove when or whether a login occurred.
4. Download HTML, CSV or JSON findings. Stop requests with **Stop scan**, or remove imported domains and results with **Clear imported data**.

Accepted formats:

| Input | File |
| --- | --- |
| Chrome / Chromium / Edge | A copy of the `History` SQLite database |
| Firefox | A copy of `places.sqlite` |
| Chrome Google Takeout | `BrowserHistory.json`, usually with a `Browser History` array |
| JSON URL list | A list of URL strings or objects with a `url` key |
| CSV | A column named `url`; without a header, URLs in the first column |
| Text | One full `https://...` or `http://...` URL per line |

For a browser database, close the browser completely before copying the file so recent WAL entries are checkpointed. A live copy without its WAL may be incomplete. To locate the Chrome profile folder, open `chrome://version` and read **Profile Path**. Copy `History` and optionally `Login Data` from that folder. `History` does not contain stored passwords. Do not export/upload plaintext password CSV files, cookies, or the whole profile. Google Takeout can export Chrome history saved to your Google Account; it may not include all local or unsynced history. Deleted history, incognito activity and missing profiles cannot be recovered by this tool.

## What it checks

- Anonymous `HEAD /` over HTTPS to each selected hostname on port 443. No redirects or historical URL paths are followed.
- Standard TLS hostname, validity and trust verification.
- Certificate provider/issuer identity in the table and HTML/CSV/JSON reports.
- Presented certificate/public-key fingerprints against the bundled affected eMudhra TLS intermediates, including cross-signs. It does not flag the whole company by name.
- Exposed PHP version strings against upstream fixes **8.2.35 / 8.3.36 / 8.4.27 / 8.5.12**, for **CVE-2026-109618** and **CVE-2026-109619**.
- Public DNS addresses only. Private, loopback, reserved and mixed public/private resolutions are blocked; the public address is pinned for the request.

A hidden version stays **Unknown**. Headers can be wrong, vendor backports may retain older version labels, and a CDN can hide its origin server. The further **23 October 2026 session-upload-progress configuration issue (CVE-2026-115560)** cannot be assessed from a public header. Even an advertised version containing the October 21 fixes is not an all-clear.

The certificate check describes the current connection, not certificates your browser saw previously. It does not implement comprehensive revocation checking, inspect Chrome CRLSet, scan other apps' trust stores, or prove the absence of past interception. If TLS validation fails, no HTTP request is sent. If the full presented chain is unavailable, the report says so.

No exploits, port scans, authentication attempts, password leak lookups or credential submissions are performed. Each selected site sees your source IP and an anonymous request. A site can still be vulnerable when these limited checks find no exposed evidence.

## Privacy and retention

Raw uploads are removed after parsing, including on errors; Docker's temporary upload directory is a tmpfs. Only hostnames, login-path hints and stored-password association counts are retained in app memory. Page titles, usernames, historical paths, query strings, fragments and passwords are not retained in the inventory. The optional Chrome Login Data parser selects only `origin_url` from `logins`, checking `length(password_value) > 0` inside SQLite to detect the presence of a stored password. It never returns/decrypts encrypted password bytes or selects usernames. Blocklisted and empty-password entries are skipped. Plaintext password exports are not accepted in the optional saved-login field. This detects account associations, not password strength or password reuse. Uploading a raw database inherently provides its contents to this local app; review or prefilter the file first if even local processing is unacceptable.

No personal history, report, analytics, API key or telemetry is included in this repository or image. The app does not send the domain list to a scanning provider. Browser sessions are isolated and expire after two hours; **Clear imported data** removes the session's imported domains/results immediately when no scan is active. Stopping/restarting the container clears all memory. Downloaded reports remain wherever you save them. The server keeps no request access log by default.

The incident indicator file is a **23 October 2026 snapshot**, not a live general vulnerability feed. Refresh it and review version rules as advisories change. Review upstream changes before installing dependencies or rebuilding later.

## Development and tests

Python 3.11+ (container uses 3.13):

```sh
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
python -m unittest discover -s tests -v
python app.py
```

The development server listens on all interfaces at port 8787; use `BIND_HOST=127.0.0.1 python app.py` to restrict it to the server itself. Production uses one Gunicorn worker with threads because session state is held in memory. Do not increase worker count without moving session/job state to a shared store.

## Sources

- [PHP official advisories](https://www.php.net/archive/2026.php)
- [PHP OOM advisory](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w)
- [PHP stale-state advisory](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp)
- [eMudhra incident tracker](https://emudhra.we-have-a-problem.com/)
- [Bundled indicator source](https://emudhra.we-have-a-problem.com/impacted-intermediates.json)
- [Chrome export help](https://support.google.com/chrome/answer/10248834)
