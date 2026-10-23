"""Concurrent Chrome history reviews with isolated sessions and a shared queue."""
import csv
import io
import json
import os
from pathlib import Path
import secrets
import sqlite3
import tempfile
import time
from urllib.parse import urlsplit
from flask import Flask, Request, jsonify, render_template, request, session, Response
from werkzeug.exceptions import HTTPException
from scanner import host_of, EXCLUDE, check_site, NOTICE, SOURCES
from jobs import Store, Runner, Busy
from findings import select as select_findings

STORE = Store(os.environ.get('SEC_CHECKER_STATE_DIR', str(Path(tempfile.gettempdir())/'sec-checker-state')),
    concurrency=int(os.environ.get('MAX_ACTIVE_CHECKS','8')),
    per_session=int(os.environ.get('CHECKS_PER_SESSION','2')),
    max_uploads=int(os.environ.get('MAX_PARALLEL_IMPORTS','2')))
class UploadRequest(Request):
    def _get_file_stream(self, total_content_length, content_type, filename=None, content_length=None):
        # One temporary copy per upload, including large files; never use user filenames.
        return tempfile.NamedTemporaryFile(prefix='sec-checker-upload-', suffix='.tmp')

app = Flask(__name__)
app.request_class=UploadRequest
app.config.update(SECRET_KEY=STORE.secret(), MAX_CONTENT_LENGTH=256*1024*1024,
                  SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE='Strict',
                  SESSION_COOKIE_SECURE=os.environ.get('SEC_CHECKER_HTTPS','0')=='1',
                  MAX_FORM_MEMORY_SIZE=512*1024, MAX_FORM_PARTS=5)
RUNNER = None if os.environ.get('SEC_CHECKER_DISABLE_RUNNER')=='1' else Runner(
    STORE, lambda item: check_site(item), threads=int(os.environ.get('CHECK_THREADS_PER_WORKER','4')))


def urls_from_file(path):
    with open(path, 'rb') as f:
        prefix = f.read(64)
    if prefix.startswith(b'SQLite format 3\x00'):
        db = sqlite3.connect(Path(path).resolve().as_uri()+'?mode=ro', uri=True)
        try:
            db.execute('PRAGMA query_only=ON')
            db.execute('PRAGMA trusted_schema=OFF')
            tables = {x[0] for x in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            table = 'urls' if 'urls' in tables else 'moz_places' if 'moz_places' in tables else None
            if not table:
                raise ValueError('Choose Chrome/Edge History or Firefox places.sqlite, not a password database.')
            deadline = time.monotonic()+30
            def progress(): return int(time.monotonic()>deadline)
            db.set_progress_handler(progress, 10000)
            db.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, 2*1024*1024)
            query='SELECT url FROM '+table
            if table=='moz_places':
                columns={row[1] for row in db.execute('PRAGMA table_info(moz_places)')}
                if 'visit_count' in columns:query+=' WHERE visit_count > 0'
                elif 'moz_historyvisits' in tables:query+=' WHERE EXISTS (SELECT 1 FROM moz_historyvisits v WHERE v.place_id=moz_places.id)'
            for row in db.execute(query):
                yield row[0]
        finally:
            db.close()
        return
    if Path(path).stat().st_size > 32*1024*1024:
        raise ValueError('JSON, CSV and text imports are limited to 32 MB. Use the Chrome History database for larger imports.')
    with open(path, encoding='utf-8-sig') as f:
        start = f.read(1)
        while start and start.isspace(): start=f.read(1)
        f.seek(0)
        if start in ('{', '['):
            data = json.load(f)
            records = data.get('Browser History', data.get('history', data.get('items', []))) if isinstance(data, dict) else data
            if not isinstance(records, list):
                raise ValueError('JSON must contain a history list or a Browser History array.')
            for rec in records:
                if isinstance(rec, str): yield rec
                elif isinstance(rec, dict): yield rec.get('url', rec.get('URL', rec.get('link', '')))
        else:
            # Headerless URL lists and CSV with a url/URL column.
            reader=csv.reader(f)
            column=0
            for index,row in enumerate(reader):
                if not row: continue
                if index==0 and any(x.strip().lower()=='url' for x in row):
                    column=next(i for i,x in enumerate(row) if x.strip().lower()=='url');continue
                if len(row)>column: yield row[column].strip()

def extract(path):
    hosts={}; count=0; excluded=0
    for url in urls_from_file(path):
        count+=1
        if count>2_000_000: raise ValueError('History exceeds the two-million-entry limit. Export a smaller time range.')
        if not isinstance(url,str) or len(url)>65536: continue
        host=host_of(url)
        if not host: continue
        if EXCLUDE.search(host): excluded+=1;continue
        item=hosts.setdefault(host, {'host':host, 'saved_login':False, 'login_page_hint':False})
        import re
        if re.search(r'/(?:login|signin|sign-in|auth)(?:[/?.#]|$)',urlsplit(url).path,re.I): item['login_page_hint']=True
        if len(hosts)>10000: raise ValueError('More than 10,000 domains. Export a smaller time range.')
    if not hosts: raise ValueError('No supported HTTP(S) history URLs were found. Unzip Takeout first and upload BrowserHistory.json.')
    return sorted(hosts.values(),key=lambda x:(not x['login_page_hint'],x['host'])),count,excluded

def extract_firefox_logins(path):
    if Path(path).stat().st_size > 32*1024*1024:
        raise ValueError('Firefox logins.json imports are limited to 32 MB.')
    with open(path,encoding='utf-8-sig') as stream:
        data=json.load(stream)
    if not isinstance(data,dict) or not isinstance(data.get('logins'),list):
        raise ValueError('Choose Firefox logins.json or Chrome/Edge Login Data; plaintext password exports are not accepted.')
    hosts={}
    for index,record in enumerate(data['logins']):
        if index>=2_000_000:raise ValueError('Too many saved-login records.')
        if not isinstance(record,dict):continue
        # Only test presence of the encrypted field. Never decrypt it or retain it.
        if not isinstance(record.get('encryptedPassword'),str) or not record['encryptedPassword']:continue
        origin=record.get('hostname') or record.get('origin')
        if not isinstance(origin,str):continue
        host=host_of(origin)
        if host and not EXCLUDE.search(host):hosts[host]=hosts.get(host,0)+1
        if len(hosts)>10000:raise ValueError('Too many saved-login domains.')
    return hosts

def extract_saved_logins(path):
    with open(path, 'rb') as source:
        is_sqlite=source.read(16) == b'SQLite format 3\x00'
    if not is_sqlite:
        return extract_firefox_logins(path)
    db = sqlite3.connect(Path(path).resolve().as_uri() + '?mode=ro', uri=True)
    try:
        db.execute('PRAGMA query_only=ON')
        db.execute('PRAGMA trusted_schema=OFF')
        tables = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if 'logins' not in tables:
            raise ValueError('Choose Chrome/Edge Login Data or Firefox logins.json for the optional saved-login file.')
        columns = {row[1] for row in db.execute('PRAGMA table_info(logins)')}
        if not {'origin_url', 'password_value'} <= columns:
            raise ValueError('Chromium saved-login database is missing required columns.')
        # SQL checks presence only: encrypted password bytes and usernames are never returned.
        query = 'SELECT origin_url FROM logins WHERE length(password_value) > 0'
        if 'blacklisted_by_user' in columns:
            query += ' AND COALESCE(blacklisted_by_user, 0) = 0'
        deadline = time.monotonic() + 30
        db.set_progress_handler(lambda: int(time.monotonic() > deadline), 10000)
        db.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, 2*1024*1024)
        hosts = {}; records = 0
        for (url,) in db.execute(query):
            records += 1
            if records > 2_000_000:
                raise ValueError('Too many saved-login records.')
            host = host_of(url or '')
            if host and not EXCLUDE.search(host):
                hosts[host] = hosts.get(host, 0) + 1
            if len(hosts) > 10000:
                raise ValueError('Too many saved-login domains.')
        return hosts
    finally:
        db.close()


def current():
    sid=STORE.ensure(session.get('sid'))
    session['sid']=sid
    return sid

@app.before_request
def guard():
    # The user may access the UI by server IP or a configured domain.
    # Keep same-origin CSRF checks; an optional password protects shared servers.
    password = os.environ.get('SEC_CHECKER_PASSWORD', '')
    if password and request.path != '/health':
        auth = request.authorization
        valid = auth and auth.type.lower() == 'basic' and auth.username == 'reviewer' and secrets.compare_digest((auth.password or '').encode(), password.encode())
        if not valid:
            return Response('Authentication required.', 401, {'WWW-Authenticate': 'Basic realm="Sec Checker"'})
    if request.method=='POST':
        expected=session.get('csrf','')
        if not expected or not secrets.compare_digest(request.headers.get('X-CSRF-Token',''),expected) or request.headers.get('Origin')!=request.host_url.rstrip('/'):
            return jsonify(error='Session validation failed. Reload the page.'),403

@app.after_request
def headers(response):
    response.headers.update({'Cache-Control':'no-store','X-Content-Type-Options':'nosniff',
      'Referrer-Policy':'no-referrer','Content-Security-Policy':"default-src 'self'; script-src 'self'; style-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"})
    return response

@app.errorhandler(Exception)
def error(exc):
    if isinstance(exc,Busy):
        return jsonify(error=str(exc)),exc.code
    if isinstance(exc,HTTPException):
        return jsonify(error='Upload too large (256 MB maximum).' if exc.code==413 else exc.name),exc.code
    if isinstance(exc,(ValueError,UnicodeError,json.JSONDecodeError)):
        return jsonify(error=str(exc)[:250]),400
    if isinstance(exc,sqlite3.OperationalError) and any(text in str(exc).lower() for text in ('database is locked','database or disk is full','unable to open database')):
        return jsonify(error='Shared storage is busy or full. Retry shortly or clear older sessions.'),503
    if isinstance(exc,sqlite3.Error):
        return jsonify(error='Could not read this history database. Close the browser and make a fresh copy, including its WAL if needed, or use a JSON export.'),400
    if app.testing:
        raise exc
    # Do not log raw URLs, upload contents, or filenames in exception details.
    return jsonify(error='The operation failed. Check the file format and try again.'),500

@app.get('/')
def index():
    current()
    session.setdefault('csrf',secrets.token_urlsafe(32))
    return render_template('index.html',csrf=session['csrf'])

@app.get('/health')
def health():
    STORE.secret()
    return jsonify(status='ok')

@app.post('/api/upload')
def upload():
    sid=current()
    previous=STORE.begin_upload(sid)
    uploaded_files=[]
    try:
        files=request.files
        uploaded_files=[value for _,value in files.items(multi=True)]
        f=files.get('history')
        if not f: raise ValueError('Choose a browser history file.')
        # Request-owned files are deleted in finally, including on parse errors.
        path=Path(f.stream.name)
        items,count,excluded=extract(path)
        login_file = files.get('logins')
        login_hosts = {}
        if login_file and login_file.filename:
            login_path = Path(login_file.stream.name)
            login_hosts = extract_saved_logins(login_path)
        merged = {item['host']: item for item in items}
        for host, record_count in login_hosts.items():
            item = merged.setdefault(host, {'host': host, 'saved_login': False, 'login_page_hint': False})
            item.update(saved_login=True, saved_login_count=record_count)
        if len(merged) > 10000:
            raise ValueError('Combined uploads exceed the 10,000-domain limit.')
        items = sorted(merged.values(), key=lambda x: (not x['saved_login'], not x['login_page_hint'], x['host']))
        STORE.finish_upload(sid,items)
    except BaseException:
        STORE.abort_upload(sid,previous)
        raise
    finally:
        for upload_file in uploaded_files:
            upload_file.close()
    return jsonify(items=items,entries=count,excluded_entries=excluded,saved_login_domains=len(login_hosts))

@app.post('/api/scan')
def start():
    sid=current();data=request.get_json(silent=True) or {}
    hosts=data.get('hosts')
    if data.get('reviewed') is not True or not isinstance(hosts,list) or not hosts or any(not isinstance(h,str) for h in hosts):
        raise ValueError('Select domains and confirm that you excluded sensitive sites.')
    STORE.enqueue(sid,set(hosts))
    return jsonify(started=True,queued=True),202

@app.post('/api/cancel')
def cancel():
    STORE.cancel(current())
    return jsonify(message='Queued checks cancelled; current requests are finishing.')

@app.post('/api/clear')
def clear():
    STORE.clear(current())
    return jsonify(cleared=True)

@app.get('/api/inventory')
def inventory():
    return jsonify(items=STORE.inventory(current()))

@app.get('/api/status')
def status():
    state=STORE.status(current())
    state['results']=select_findings(state['results'])
    return jsonify(state)

@app.get('/api/report/<kind>')
def report(kind):
    all_results=STORE.status(current())['results']
    mode=request.args.get('filter','all')
    results=select_findings(all_results,mode)
    query=request.args.get('q','').strip().lower()
    if query:results=[row for row in results if query in row['host'].lower()]
    if not all_results: raise ValueError('Run a check first.')
    stamp=time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime())
    if kind=='json':
        body=json.dumps({'generated_utc':stamp,'limitations':NOTICE,'sources':SOURCES,'filter':mode,'results':results},indent=2);mime='application/json'
    elif kind=='csv':
        out=io.StringIO();writer=csv.writer(out);writer.writerow(['Host','Stored password entry','Login-page hint','Certificate provider','Certificate issuer','TLS','PHP','Evidence','Error','Review status','Severity','Why investigate','Next steps'])
        for r in results:
            row=[r['host'],r.get('saved_login',False),r['login_page_hint'],r.get('certificate',{}).get('provider','Unknown'),r.get('certificate',{}).get('issuer','Unknown'),r['tls'],r['php']['status'],r['php']['evidence'],r.get('error',''),r['review_status'],'; '.join(dict.fromkeys(x['severity'] for x in r['findings'])),'; '.join(x['title']+': '+x['reason'] for x in r['findings']),'; '.join(x['action'] for x in r['findings'])]
            writer.writerow(["'"+v if isinstance(v,str) and v.startswith(('=','+','-','@','\t','\r')) else v for v in row])
        body=out.getvalue();mime='text/csv'
    elif kind=='html':
        body=render_template('report.html',results=results,notice=NOTICE,sources=SOURCES,stamp=stamp,mode=mode);mime='text/html'
    else: return jsonify(error='Unknown report format.'),404
    return Response(body,mimetype=mime,headers={'Content-Disposition':f'attachment; filename="site-exposure-report.{kind}"'})

if __name__=='__main__':
    app.run(host=os.environ.get('BIND_HOST','0.0.0.0'),port=int(os.environ.get('PORT','8787')),debug=False)
