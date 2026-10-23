"""Single-user Chrome history and saved-login exposure review."""
import concurrent.futures
import csv
import io
import json
import os
from pathlib import Path
import secrets
import sqlite3
import tempfile
import threading
import time
from urllib.parse import urlsplit
from flask import Flask, jsonify, render_template, request, session, Response
from werkzeug.exceptions import HTTPException
from scanner import host_of, EXCLUDE, check_site, NOTICE, SOURCES

app = Flask(__name__)
app.config.update(SECRET_KEY=secrets.token_hex(32), MAX_CONTENT_LENGTH=256*1024*1024,
                  SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE='Strict',
                  MAX_FORM_MEMORY_SIZE=512*1024, MAX_FORM_PARTS=5)
LOCK = threading.RLock()
JOBS = {}
TTL = 7200

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
                raise ValueError('Choose a Chrome History or Firefox places.sqlite database, not a password database.')
            deadline = time.monotonic()+30
            def progress(): return int(time.monotonic()>deadline)
            db.set_progress_handler(progress, 10000)
            db.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, 2*1024*1024)
            for row in db.execute('SELECT url FROM '+table):
                yield row[0]
        finally:
            db.close()
        return
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

def extract_saved_logins(path):
    with open(path, 'rb') as source:
        if source.read(16) != b'SQLite format 3\x00':
            raise ValueError('The optional saved-login file must be Chrome Login Data, not a plaintext password export.')
    db = sqlite3.connect(Path(path).resolve().as_uri() + '?mode=ro', uri=True)
    try:
        db.execute('PRAGMA query_only=ON')
        db.execute('PRAGMA trusted_schema=OFF')
        tables = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if 'logins' not in tables:
            raise ValueError('The optional file is not a Chrome Login Data database.')
        columns = {row[1] for row in db.execute('PRAGMA table_info(logins)')}
        if not {'origin_url', 'password_value'} <= columns:
            raise ValueError('Chrome saved-login database is missing required columns.')
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


def new_job():
    return {'created':time.monotonic(),'items':[],'results':[], 'running':False,'done':0,'total':0,'cancel':threading.Event(),'error':None}

def current():
    with LOCK:
        now=time.monotonic()
        for key in list(JOBS):
            if now-JOBS[key]['created']>TTL:
                JOBS[key]['cancel'].set();del JOBS[key]
        sid=session.get('sid')
        if sid not in JOBS:
            if len(JOBS)>=16: raise ValueError('Too many local sessions. Restart the app to clear them.')
            sid=secrets.token_urlsafe(24);session['sid']=sid;JOBS[sid]=new_job()
        return JOBS[sid]

def expire_sessions():
    while True:
        time.sleep(30)
        with LOCK:
            for key in list(JOBS):
                if time.monotonic()-JOBS[key]['created']>TTL:
                    JOBS[key]['cancel'].set()
                    del JOBS[key]

threading.Thread(target=expire_sessions,daemon=True).start()


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
    if isinstance(exc,HTTPException):
        return jsonify(error='Upload too large (256 MB maximum).' if exc.code==413 else exc.name),exc.code
    if isinstance(exc,(ValueError,UnicodeError,json.JSONDecodeError)):
        return jsonify(error=str(exc)[:250]),400
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
def health(): return jsonify(status='ok')

@app.post('/api/upload')
def upload():
    job=current()
    with LOCK:
        if job['running']: return jsonify(error='Stop the scan before uploading another file.'),409
    f=request.files.get('history')
    if not f: raise ValueError('Choose a browser history file.')
    # Random path, no user filename, removed even if parsing fails.
    with tempfile.TemporaryDirectory(prefix='history-review-') as tmp:
        path=Path(tmp)/'upload';f.save(path)
        items,count,excluded=extract(path)
        login_file = request.files.get('logins')
        login_hosts = {}
        if login_file and login_file.filename:
            login_path = Path(tmp)/'saved-logins'
            login_file.save(login_path)
            login_hosts = extract_saved_logins(login_path)
        merged = {item['host']: item for item in items}
        for host, record_count in login_hosts.items():
            item = merged.setdefault(host, {'host': host, 'saved_login': False, 'login_page_hint': False})
            item.update(saved_login=True, saved_login_count=record_count)
        if len(merged) > 10000:
            raise ValueError('Combined uploads exceed the 10,000-domain limit.')
        items = sorted(merged.values(), key=lambda x: (not x['saved_login'], not x['login_page_hint'], x['host']))
    with LOCK:
        job.update(items=items,results=[],done=0,total=0,error=None)
    return jsonify(items=items,entries=count,excluded_entries=excluded,saved_login_domains=len(login_hosts))

def scan(job,items):
    try:
        # Keep at most four requests queued so cancellation takes effect quickly.
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            iterator=iter(items);pending=set()
            for _ in range(min(4,len(items))): pending.add(pool.submit(check_site,next(iterator)))
            while pending:
                finished,pending=concurrent.futures.wait(pending,return_when=concurrent.futures.FIRST_COMPLETED)
                for future in finished:
                    result=future.result()
                    with LOCK: job['results'].append(result);job['done']+=1
                    if not job['cancel'].is_set():
                        item=next(iterator,None)
                        if item is not None: pending.add(pool.submit(check_site,item))
    except Exception:
        with LOCK: job['error']='Scan interrupted by an internal error. Completed results remain available.'
    finally:
        with LOCK: job['running']=False

@app.post('/api/scan')
def start():
    job=current();data=request.get_json(silent=True) or {}
    hosts=data.get('hosts')
    if data.get('reviewed') is not True or not isinstance(hosts,list) or not hosts or any(not isinstance(h,str) for h in hosts):
        raise ValueError('Select domains and confirm that you excluded sensitive sites.')
    requested=set(hosts)
    with LOCK:
        if job['running']: return jsonify(error='A scan is already running.'),409
        items=[x for x in job['items'] if x['host'] in requested]
        if len(items)!=len(requested): raise ValueError('Selection contains a domain outside the uploaded history.')
        job.update(results=[],running=True,done=0,total=len(items),cancel=threading.Event(),error=None)
    threading.Thread(target=scan,args=(job,items),daemon=True).start()
    return jsonify(started=True),202

@app.post('/api/cancel')
def cancel():
    current()['cancel'].set()
    return jsonify(message='Stopping after current requests finish.')

@app.post('/api/clear')
def clear():
    job=current()
    with LOCK:
        if job['running']: return jsonify(error='Stop the scan first, then clear the session.'),409
        job.update(items=[],results=[],done=0,total=0,error=None)
    return jsonify(cleared=True)

@app.get('/api/status')
def status():
    job=current()
    with LOCK:
        return jsonify({**{k:job[k] for k in ('results','running','done','total','error')}, 'cancelled':job['cancel'].is_set()})

@app.get('/api/report/<kind>')
def report(kind):
    with LOCK: results=list(current()['results'])
    if not results: raise ValueError('Run a check first.')
    stamp=time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime())
    if kind=='json':
        body=json.dumps({'generated_utc':stamp,'limitations':NOTICE,'sources':SOURCES,'results':results},indent=2);mime='application/json'
    elif kind=='csv':
        out=io.StringIO();writer=csv.writer(out);writer.writerow(['Host','Stored password entry','Login-page hint','Certificate provider','Certificate issuer','TLS','PHP','Evidence','Error'])
        for r in results:
            row=[r['host'],r.get('saved_login',False),r['login_page_hint'],r.get('certificate',{}).get('provider','Unknown'),r.get('certificate',{}).get('issuer','Unknown'),r['tls'],r['php']['status'],r['php']['evidence'],r.get('error','')]
            writer.writerow(["'"+v if isinstance(v,str) and v.startswith(('=','+','-','@','\t','\r')) else v for v in row])
        body=out.getvalue();mime='text/csv'
    elif kind=='html':
        body=render_template('report.html',results=results,notice=NOTICE,sources=SOURCES,stamp=stamp);mime='text/html'
    else: return jsonify(error='Unknown report format.'),404
    return Response(body,mimetype=mime,headers={'Content-Disposition':f'attachment; filename="site-exposure-report.{kind}"'})

if __name__=='__main__':
    app.run(host=os.environ.get('BIND_HOST','0.0.0.0'),port=int(os.environ.get('PORT','8787')),debug=False)
