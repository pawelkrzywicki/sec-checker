# Sec Checker

A Docker app for uploading browser history, reviewing domains, and collecting evidence of exposure to the October 2026 PHP and eMudhra certificate incidents. It flags potential problems and unknowns; it does not prove website safety or account compromise.

## Start

Requires Docker Engine/Desktop and Docker Compose. Set the app password before starting it:

```sh
python3 set_password.py
```

This prompts for a password twice and saves a password hash in the private, Git-ignored `.env` file. Use `python3 set_password.py --generate` instead to generate a strong password in `.initial-password` (also ignored, owner-readable only). The setup script needs Werkzeug, included with Flask in `requirements.txt`. The app refuses access if no password is configured. No default password is built into the image.

```sh
docker compose up --build -d
```

Open **http://SERVER_IP:8787** from your browser, or **http://127.0.0.1:8787** on the server itself. The service is published on all host interfaces by default. Rebuild/recreate the existing container after upgrading: `docker compose up --build -d --force-recreate`. To stop and clear container memory:

```sh
docker compose down
```

No browser profile mounts, privileged container, Docker socket mount, account passwords or external APIs are needed. The container runs as a non-root user with a read-only filesystem and temporary upload storage in RAM. Outbound Internet access is required for selected website checks. Different browser sessions have independent workspaces and can upload and scan concurrently. Password authentication is required. Sign in with the app password; no username is needed. A password hash in `SEC_CHECKER_PASSWORD_HASH` is preferred. The older `SEC_CHECKER_PASSWORD` environment variable remains compatible, but is no longer optional protection. For network access, use an HTTPS reverse proxy and set `SEC_CHECKER_HTTPS=1` for secure cookies. Password protection does not encrypt HTTP traffic. To bind only one interface, set `SEC_CHECKER_BIND_IP=192.168.1.10` (or `127.0.0.1` for local-only access).

## Import, review, check

1. Upload Chrome/Edge `History`, Firefox `places.sqlite`, or Chrome Takeout `BrowserHistory.json`. Optionally attach the same profile’s Chrome/Edge `Login Data` or Firefox `logins.json` to associate stored-password entries with sites (256 MB combined for databases; 32 MB maximum for JSON/CSV/text imports; unzip archives first).
2. Review the domain list. Nothing is selected initially. Common adult domains are filtered, but automatic filtering is incomplete. Exclude sensitive domains before starting a scan.
3. Select the sites, confirm the review, and run the checks. Select stored-password sites or login-path hints as a selection aid. Stored entries and login paths do not prove when or whether a login occurred.
4. Click **Needs investigation** or the clickable investigation summary count to see only flagged sites. Each flagged row shows severity, evidence, a next step and an advisory link where available. **All results** restores the full list; **Incomplete checks** separates failed/partial checks from security evidence. Result search narrows the domains further. HTML, CSV and JSON downloads follow the active filter and search. Hidden PHP versions remain unknown and are not flagged solely for being hidden.
5. Download HTML, CSV or JSON findings. Stop requests with **Stop scan**, or remove imported domains and results with **Clear imported data**.

Accepted formats:

| Input | File |
| --- | --- |
| Chrome / Chromium / Edge | A copy of the `History` SQLite database |
| Firefox | A copy of `places.sqlite` |
| Chrome Google Takeout | `BrowserHistory.json`, usually with a `Browser History` array |
| JSON URL list | A list of URL strings or objects with a `url` key |
| CSV | A column named `url`; without a header, URLs in the first column |
| Text | One full `https://...` or `http://...` URL per line |

Saved-login inputs:

| Browser | History file | Optional saved-login file | Find the profile |
| --- | --- | --- | --- |
| Chrome | `History` (SQLite) | `Login Data` (SQLite `logins` table) | `chrome://version` → Profile Path |
| Edge | `History` (SQLite) | Compatible `Login Data` SQLite stores, including account-store filename variants | `edge://version` → Profile Path |
| Firefox desktop | `places.sqlite` (SQLite) | `logins.json` (encrypted login records) | `about:support` → Profile Folder |

Firefox bookmarks without recorded visits are excluded when the database provides visit information. The login parser uses the public `hostname`/`origin` field and checks whether an encrypted password field is present. It never decrypts the password or username, and **does not need `key4.db`**. Do not upload that encryption-key file. Desktop formats are supported; this does not claim mobile-browser or legacy pre-Chromium Edge compatibility. Import one browser profile per workspace; a new import replaces that workspace’s previous inventory.

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

Raw uploads are removed after parsing, including on errors; Docker's temporary upload directory is a tmpfs. Only hostnames, login-path hints, stored-password association counts and results are retained in a shared SQLite session/queue store. In Docker, that store is on the private `/state` RAM filesystem, not a persistent volume. Raw history and raw saved-login uploads are never written to the queue store. Page titles, usernames, historical paths, query strings, fragments and passwords are not retained in the inventory. The optional Chrome/Edge Login Data parser selects only `origin_url` from `logins`, checking `length(password_value) > 0` inside SQLite to detect the presence of a stored password. It never returns/decrypts encrypted password bytes or selects usernames. Blocklisted and empty-password entries are skipped. Firefox `logins.json` is parsed locally; only site association counts are retained, not encrypted fields or usernames. Plaintext password exports are not accepted in the optional saved-login field. This detects account associations, not password strength or password reuse. Uploading a raw database inherently provides its contents to this local app; review or prefilter the file first if even local processing is unacceptable.

No personal history, report, analytics, API key or telemetry is included in this repository or image. The app does not send the domain list to a scanning provider. Browser sessions are isolated and expire after two hours; **Clear imported data** logically removes that session’s imported domains/results when no import or scan is active. Removing/recreating the container clears its temporary state store. Ordinary web-worker restarts keep the workspace and queue. In non-Docker development, the store lives in `/tmp/sec-checker-state` unless `SEC_CHECKER_STATE_DIR` overrides it, so it can survive a process restart. Expired records are removed by the queue workers; this is not a forensic secure-erasure guarantee. Downloaded reports remain wherever you save them. The server keeps no request access log by default.

The incident indicator file is a **23 October 2026 snapshot**, not a live general vulnerability feed. Refresh it and review version rules as advisories change. Review upstream changes before installing dependencies or rebuilding later.

## Concurrent users and capacity

Each browser session has its own unguessable, signed session identifier. Inventory, queued sites, progress, cancellation and report downloads are always scoped to that session. Different users do not select a shared job identifier. Tabs in one browser profile intentionally share one workspace; use separate browser profiles/private windows for separate workspaces on the same device. These are temporary sessions, not named user accounts or an SSO/account system.

The queue is shared across processes and uses transactional claims to avoid duplicate work. Sessions take turns, with defaults of **8 active site checks globally**, **2 per session**, and **2 simultaneous imports**. Additional scans wait; excess imports get a retryable busy response instead of allocating unbounded resources. Duplicate imports/scans in the same session are rejected. Queued scans can be cancelled independently. If a worker dies, its task lease expires after 120 seconds and the check can be retried (at most three attempts); stale results cannot overwrite a retried task. Network requests can therefore repeat during worker recovery.

Limits are configurable through `.env` and Compose:

```text
WEB_WORKERS=2
MAX_ACTIVE_CHECKS=8
CHECKS_PER_SESSION=2
MAX_PARALLEL_IMPORTS=2
```

There is a 1,000-live-session admission ceiling, 10,000 domains per import and a bounded temporary store; that is an admission limit, not a claim that 1,000 full-size uploads can run simultaneously. Large imports are bounded at 256 MB combined per request; JSON/CSV/text is limited to 32 MB to bound parsing memory. No load-test throughput guarantee is implied. Increase CPU/RAM/storage and benchmark before raising limits. Each web worker starts four check threads by default (`CHECK_THREADS_PER_WORKER`); the shared queue enforces the global and per-session ceilings regardless of worker count.

Put network access behind HTTPS and set `SEC_CHECKER_HTTPS=1` for secure session cookies. The shared app password controls entry; it does not grant access to another browser’s workspace. This is one shared password, not individual user accounts. Successful login creates a new server-verified session valid for two hours. Sign-out deletes that workspace and invalidates its access even if an old cookie is replayed. Changing the configured password invalidates existing sign-ins. Ten login attempts from one source address within ten minutes trigger a temporary limit shared by web workers. Source addresses are stored only as salted hash buckets for this limiter. Keep the session cookie private. Multiple hosts, persistent accounts, account recovery, and distributed queues are outside this version.

## Change the password

Run `python3 set_password.py` on the server, then `docker compose up --build -d --force-recreate`. The script preserves other `.env` settings, removes an old generated `.initial-password` file when setting a custom password, and never prints the password or hash. Container recreation clears current temporary workspaces, so download reports first. Keep `.env` and any initial-password file out of version control. An administrator can reset access by setting a new password with this script.

## Development and tests

Python 3.11+ (container uses 3.13):

```sh
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
python set_password.py
python -m unittest discover -s tests -v
node tests/test_result_view.cjs  # optional UI renderer checks, requires Node.js
# Native development: export SEC_CHECKER_PASSWORD_HASH or SEC_CHECKER_PASSWORD first.
python app.py
```

The development server listens on all interfaces at port 8787; use `BIND_HOST=127.0.0.1 python app.py` to restrict it to the server itself. Production defaults to two Gunicorn workers sharing the SQLite session/queue store. Cookie signing keys are generated atomically in that same store, so requests can go to either worker. The SQLite file must be on a local filesystem; do not put it on NFS or share it across hosts.

## Sources

- [PHP official advisories](https://www.php.net/archive/2026.php)
- [PHP OOM advisory](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w)
- [PHP stale-state advisory](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp)
- [eMudhra incident tracker](https://emudhra.we-have-a-problem.com/)
- [Bundled indicator source](https://emudhra.we-have-a-problem.com/impacted-intermediates.json)
- [Chrome export help](https://support.google.com/chrome/answer/10248834)

- [Firefox profile files](https://support.mozilla.org/en-US/kb/profiles-where-firefox-stores-user-data)
- [Firefox password storage](https://support.mozilla.org/en-US/kb/use-primary-password-protect-stored-logins)
- [Microsoft browser forensics guide](https://cdn-dynmedia-1.microsoft.com/is/content/microsoftcorp/microsoft/final/en-us/microsoft-brand/documents/IR-Guidebook-Final.pdf)
