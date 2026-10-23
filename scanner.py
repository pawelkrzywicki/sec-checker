"""Anonymous public-site evidence checks. No exploit or credential submission."""

import datetime as dt
import hashlib
import http.client
import ipaddress
import json
from pathlib import Path
import re
import socket
import ssl
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parent

FIXED = {(8, 2): 35, (8, 3): 36, (8, 4): 27, (8, 5): 12}

SOURCES = ['https://www.php.net/archive/2026.php',
 'https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w',
 'https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp',
 'https://emudhra.we-have-a-problem.com/']

EXCLUDE = re.compile(r'porn|xxx|xvideos|xnxx|xhamster|redtube|youporn|onlyfans|chaturbate|stripchat|livejasmin|cam4|adultfriendfinder|sex\.com|spankbang|rule34|e621|hentai|nhentai|fetlife', re.I)

def host_of(url):
    try:
        u = urlsplit(url)
        if u.scheme not in ('http', 'https') or not u.hostname or u.username or u.password:
            return None
        host = u.hostname.rstrip('.').encode('idna').decode('ascii').lower()
        # Do not preserve unusual ports, IP addresses, paths, queries or fragments.
        if u.port not in (None, 80, 443) or not re.fullmatch(r'[a-z0-9.-]{1,253}', host):
            return None
        return host
    except (ValueError, UnicodeError):
        return None

def php_status(headers):
    match = re.search(r'\bPHP/(\d+)\.(\d+)\.(\d+)', headers, re.I)
    if not match:
        return {'status': 'Unknown', 'evidence': 'No PHP version exposed in the checked response. This does not establish safety.'}
    version = tuple(map(int, match.groups()))
    fixed = FIXED.get(version[:2])
    if fixed is not None and version[2] >= fixed:
        return {'status': 'Advertised version includes Oct 21 upstream fixes', 'evidence': '.'.join(map(str, version)) + '; header is unverified. Oct 23 session-upload-progress configuration issue remains unknown.'}
    if version[:2] <= (8, 5):
        return {'status': 'Potentially affected PHP — operator confirmation needed', 'evidence': '.'.join(map(str, version)) + '; older than the Oct 21 upstream fixes. Vendor backports may fix it without changing this label.'}
    return {'status': 'Unknown newer PHP version', 'evidence': match.group(0) + '; verify against current vendor guidance.'}

def public_addresses(host):
    addresses = sorted({x[4][0] for x in socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)})
    if not addresses or any(not ipaddress.ip_address(x).is_global for x in addresses):
        raise ValueError('Skipped: private, local, reserved or mixed public/private address.')
    return addresses

def get_chain(sock):
    # CPython exposes chain retrieval here on versions before its public API.
    obj = getattr(sock, '_sslobj', None)
    getter = getattr(sock, 'get_unverified_chain', None) or getattr(obj, 'get_unverified_chain', None)
    if getter is None:
        return [sock.getpeercert(binary_form=True)], False
    chain = []
    for cert in getter():
        raw = cert if isinstance(cert, bytes) else cert.public_bytes()
        if isinstance(raw, str):
            raw = ssl.PEM_cert_to_DER_cert(raw)
        elif raw.startswith(b'-----BEGIN'):
            raw = ssl.PEM_cert_to_DER_cert(raw.decode())
        chain.append(raw)
    return chain, True

def check_site(item):
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    host = item['host']
    result = {'host': host, 'saved_login': item['saved_login'], 'login_page_hint': item['login_page_hint'],
              'checked_utc': dt.datetime.now(dt.timezone.utc).isoformat(),
              'tls': 'Not checked', 'php': {'status': 'Unknown', 'evidence': ''}, 'certificate': {}}
    try:
        addresses = public_addresses(host)
        indicators = json.loads((ROOT / 'affected-certificates.json').read_text())['certificates']
        bad_keys = {x['spki_sha256'].lower() for x in indicators}
        bad_certs = {x['sha256'].lower() for x in indicators}
        context = ssl.create_default_context()
        # Pin the resolved public address; do not re-resolve inside HTTPConnection.
        with socket.create_connection((addresses[0], 443), timeout=8) as raw:
            with context.wrap_socket(raw, server_hostname=host) as sock:
                sock.settimeout(8)
                chain, full_chain = get_chain(sock)
                matches = []
                for der in chain:
                    cert = x509.load_der_x509_certificate(der)
                    spki = cert.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
                    if hashlib.sha256(spki).hexdigest() in bad_keys or hashlib.sha256(der).hexdigest() in bad_certs:
                        matches.append(cert.subject.rfc4514_string())
                if matches:
                    result['tls'] = 'Affected eMudhra key present — stop using this connection'
                    result['certificate']['affected_matches'] = matches
                    return result
                leaf = x509.load_der_x509_certificate(chain[0])
                result['certificate'] = {'issuer': leaf.issuer.rfc4514_string(), 'leaf_sha256': hashlib.sha256(chain[0]).hexdigest(),
                    'chain_certificates_seen': len(chain), 'chain_available': full_chain}
                result['tls'] = ('TLS identity/date/trust validation passed; no affected eMudhra key in presented chain'
                    if full_chain else 'TLS validation passed; full chain unavailable — eMudhra result incomplete')
                # No authentication, cookies, URL parameters, body, exploit, or redirects.
                sock.sendall(('HEAD / HTTP/1.1\r\nHost: ' + host + '\r\nUser-Agent: LocalExposureReview/1.0\r\nConnection: close\r\n\r\n').encode('ascii'))
                response = http.client.HTTPResponse(sock)
                response.begin()
                result['http_status'] = response.status
                exposed = ' '.join(response.getheader(k, '') for k in ('X-Powered-By', 'Server'))
                result['php'] = php_status(exposed)
                if 300 <= response.status < 400:
                    result['php']['evidence'] += ' Root redirected; destination was not followed.'
    except ssl.SSLCertVerificationError as exc:
        result['tls'] = 'TLS validation failed — requires investigation'
        result['error'] = str(exc.verify_message)
    except Exception as exc:
        # Keep messages bounded and do not include any historical URLs.
        result['error'] = str(exc)[:300]
    return result

NOTICE = ('This is a limited external exposure review, not proof of compromise or safety. '
 'Only the current HTTPS root response and presented certificate chain are checked. '
 'Sites behind CDNs, other paths, historical certificates, vendor backports, revocation beyond the pinned incident list, '
 'and server configuration cannot be conclusively assessed. Saved login means a stored entry, not proof it was used; '
 'login-page paths are weak hints. No passwords are checked or disclosed. '
 'PHP published a further configuration-dependent session-upload-progress RCE advisory on 23 Oct 2026 '
 '(CVE-2026-115560); this tool cannot determine that configuration remotely. '
 'Chrome CRLSet/browser protection is separate from this Python TLS trust store.')
