"""Shared SQLite session store and fair, bounded, cross-process work queue."""
from contextlib import contextmanager, closing
import json
from pathlib import Path
import secrets
import sqlite3
import threading
import time

class Busy(Exception):
    def __init__(self, message, code=409):
        super().__init__(message)
        self.code=code

class Store:
    def __init__(self, directory, *, concurrency=8, per_session=2, max_uploads=2, ttl=7200):
        self.directory=Path(directory)
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.path=self.directory/'jobs.sqlite'
        self.concurrency=concurrency;self.per_session=per_session
        self.max_uploads=max_uploads;self.ttl=ttl
        with closing(self.connect()) as db:
            db.execute('PRAGMA journal_mode=WAL')
            db.execute('PRAGMA max_page_count=65536')
            db.executescript('''
                CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS sessions (
                    sid TEXT PRIMARY KEY, created REAL NOT NULL, expires REAL NOT NULL,
                    items TEXT NOT NULL DEFAULT '[]', state TEXT NOT NULL DEFAULT 'idle',
                    import_until REAL NOT NULL DEFAULT 0, scheduled REAL NOT NULL DEFAULT 0,
                    error TEXT, cancelled INTEGER NOT NULL DEFAULT 0);
                CREATE TABLE IF NOT EXISTS tasks (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    sid TEXT NOT NULL REFERENCES sessions(sid) ON DELETE CASCADE,
                    item TEXT NOT NULL, state TEXT NOT NULL DEFAULT 'pending',
                    owner TEXT, lease_until REAL NOT NULL DEFAULT 0,
                    attempts INTEGER NOT NULL DEFAULT 0, result TEXT);
                CREATE TABLE IF NOT EXISTS login_limits (
                    bucket TEXT PRIMARY KEY, attempts INTEGER NOT NULL, reset_after REAL NOT NULL);
                CREATE INDEX IF NOT EXISTS tasks_session ON tasks(sid,id);
                CREATE INDEX IF NOT EXISTS tasks_queue ON tasks(state,sid);
                CREATE INDEX IF NOT EXISTS sessions_expiry ON sessions(expires);
            ''')
            db.execute('INSERT OR IGNORE INTO settings VALUES (?,?)',('cookie_secret',secrets.token_hex(32)))
        self.path.chmod(0o600)

    def connect(self):
        db=sqlite3.connect(self.path,timeout=10,isolation_level=None)
        db.row_factory=sqlite3.Row
        db.execute('PRAGMA foreign_keys=ON')
        db.execute('PRAGMA busy_timeout=10000')
        db.execute('PRAGMA secure_delete=ON')
        return db

    @contextmanager
    def transaction(self):
        db=self.connect()
        try:
            db.execute('BEGIN IMMEDIATE')
            yield db
            db.commit()
        except BaseException:
            db.rollback();raise
        finally:db.close()

    def secret(self):
        with closing(self.connect()) as db:
            return db.execute("SELECT value FROM settings WHERE key='cookie_secret'").fetchone()[0]

    def cleanup(self,db):
        now=time.time()
        db.execute('DELETE FROM sessions WHERE expires < ?', (now,))
        db.execute('DELETE FROM login_limits WHERE reset_after < ?', (now,))
        db.execute("UPDATE sessions SET state='idle', import_until=0 WHERE state='importing' AND import_until < ?",(now,))
        # A dead worker's task can be retried; owner tokens reject late/stale writes.
        db.execute("UPDATE tasks SET state='pending',owner=NULL WHERE state='running' AND lease_until < ? AND attempts < 3",(now,))
        db.execute("UPDATE tasks SET state='failed', owner=NULL WHERE state='running' AND lease_until < ? AND attempts >= 3",(now,))
        db.execute("UPDATE tasks SET state='cancelled' WHERE state='pending' AND sid IN (SELECT sid FROM sessions WHERE cancelled=1)")
        db.execute("UPDATE sessions SET error='Some checks timed out after worker recovery.' WHERE sid IN (SELECT sid FROM tasks WHERE state='failed')")
        db.execute("UPDATE sessions SET state=CASE WHEN cancelled=1 THEN 'cancelled' ELSE 'complete' END WHERE state IN ('queued','running','stopping') AND NOT EXISTS (SELECT 1 FROM tasks WHERE tasks.sid=sessions.sid AND tasks.state IN ('pending','running'))")

    def ensure(self,sid=None):
        with self.transaction() as db:
            self.cleanup(db)
            if sid and db.execute('SELECT 1 FROM sessions WHERE sid=?',(sid,)).fetchone():return sid
            if db.execute('SELECT count(*) FROM sessions').fetchone()[0]>=1000:
                raise Busy('Server session capacity reached. Please try later.',503)
            sid=secrets.token_urlsafe(32);now=time.time()
            db.execute('INSERT INTO sessions(sid,created,expires) VALUES (?,?,?)',(sid,now,now+self.ttl))
            return sid

    def sign_out(self,sid):
        with self.transaction() as db:
            db.execute('DELETE FROM sessions WHERE sid=?',(sid,))

    def login_wait(self,bucket):
        with closing(self.connect()) as db:
            row=db.execute('SELECT attempts,reset_after FROM login_limits WHERE bucket=?',(bucket,)).fetchone()
            if row and row['attempts']>=10 and row['reset_after']>time.time():
                return max(1,int(row['reset_after']-time.time()))
            return 0

    def login_attempt(self,bucket):
        with self.transaction() as db:
            self.cleanup(db)
            row=db.execute('SELECT attempts,reset_after FROM login_limits WHERE bucket=?',(bucket,)).fetchone()
            if row and row['attempts']>=10:
                return max(1,int(row['reset_after']-time.time()))
            db.execute('INSERT INTO login_limits VALUES (?,1,?) ON CONFLICT(bucket) DO UPDATE SET attempts=attempts+1',(bucket,time.time()+600))
            return 0

    def reset_login_attempts(self,bucket):
        with self.transaction() as db:db.execute('DELETE FROM login_limits WHERE bucket=?',(bucket,))

    def begin_upload(self,sid):
        with self.transaction() as db:
            self.cleanup(db)
            row=db.execute('SELECT state FROM sessions WHERE sid=?',(sid,)).fetchone()
            if not row:raise Busy('Session expired. Reload the page.',409)
            if row['state'] in ('importing','queued','running','stopping'):
                raise Busy('This session is already importing or scanning. Stop the scan first.')
            if db.execute("SELECT count(*) FROM sessions WHERE state='importing'").fetchone()[0]>=self.max_uploads:
                raise Busy('Import slots are busy. Please retry shortly.',429)
            db.execute("UPDATE sessions SET state='importing',import_until=? WHERE sid=?",(time.time()+600,sid))
            return row['state']

    def finish_upload(self,sid,items):
        with self.transaction() as db:
            row=db.execute('SELECT state,expires FROM sessions WHERE sid=?',(sid,)).fetchone()
            if not row or row['state']!='importing' or row['expires']<time.time():raise Busy('Import session expired. Reload and retry.')
            db.execute('DELETE FROM tasks WHERE sid=?',(sid,))
            db.execute("UPDATE sessions SET items=?,state='idle',import_until=0,error=NULL,cancelled=0 WHERE sid=?",(json.dumps(items),sid))

    def abort_upload(self,sid,previous):
        with self.transaction() as db:
            db.execute("UPDATE sessions SET state=?,import_until=0 WHERE sid=? AND state='importing'",(previous,sid))

    def enqueue(self,sid,hosts):
        with self.transaction() as db:
            self.cleanup(db)
            row=db.execute('SELECT * FROM sessions WHERE sid=?',(sid,)).fetchone()
            if not row:raise Busy('Session expired. Reload the page.')
            if row['state'] in ('importing','queued','running','stopping'):raise Busy('This session already has an import or scan in progress.')
            selected=[x for x in json.loads(row['items']) if x['host'] in hosts]
            if len(selected)!=len(hosts):raise ValueError('Selection contains a domain outside your uploaded history.')
            db.execute('DELETE FROM tasks WHERE sid=?',(sid,))
            db.executemany('INSERT INTO tasks(sid,item) VALUES (?,?)',[(sid,json.dumps(x)) for x in selected])
            db.execute("UPDATE sessions SET state='queued',cancelled=0,error=NULL,scheduled=? WHERE sid=?",(time.time(),sid))

    def claim(self):
        with self.transaction() as db:
            self.cleanup(db)
            if db.execute("SELECT count(*) FROM tasks WHERE state='running'").fetchone()[0]>=self.concurrency:return None
            row=db.execute('''SELECT t.id,t.sid,t.item FROM tasks t JOIN sessions s ON s.sid=t.sid
                WHERE t.state='pending' AND s.cancelled=0 AND s.state IN ('queued','running')
                AND (SELECT count(*) FROM tasks busy WHERE busy.sid=s.sid AND busy.state='running') < ?
                ORDER BY s.scheduled,t.id LIMIT 1''',(self.per_session,)).fetchone()
            if not row:return None
            token=secrets.token_urlsafe(24)
            db.execute("UPDATE tasks SET state='running',owner=?,lease_until=?,attempts=attempts+1 WHERE id=?",(token,time.time()+120,row['id']))
            db.execute("UPDATE sessions SET state='running',scheduled=? WHERE sid=?",(time.time(),row['sid']))
            return {'id':row['id'],'sid':row['sid'],'owner':token,'item':json.loads(row['item'])}

    def complete(self,task,result):
        with self.transaction() as db:
            db.execute("UPDATE tasks SET state='done',result=?,owner=NULL WHERE id=? AND owner=? AND state='running'",(json.dumps(result),task['id'],task['owner']))
            self.cleanup(db)

    def status(self,sid):
        with self.transaction() as db:
            self.cleanup(db)
            row=db.execute('SELECT state,error,cancelled FROM sessions WHERE sid=?',(sid,)).fetchone()
            if not row:raise Busy('Session expired. Reload the page.')
            tasks=db.execute('SELECT state,result FROM tasks WHERE sid=? ORDER BY id',(sid,)).fetchall()
            return {'state':row['state'],'running':row['state'] in ('queued','running','stopping'),
                'queued':row['state']=='queued','cancelled':bool(row['cancelled']),
                'done':sum(x['state'] in ('done','failed') for x in tasks),'total':len(tasks),
                'error':row['error'],'results':[json.loads(x['result']) for x in tasks if x['result']]}

    def inventory(self,sid):
        with closing(self.connect()) as db:
            row=db.execute('SELECT items FROM sessions WHERE sid=?',(sid,)).fetchone()
            return json.loads(row['items']) if row else []

    def cancel(self,sid):
        with self.transaction() as db:
            db.execute("UPDATE sessions SET cancelled=1,state='stopping' WHERE sid=? AND state IN ('queued','running')",(sid,))
            db.execute("UPDATE tasks SET state='cancelled' WHERE sid=? AND state='pending'",(sid,))
            self.cleanup(db)

    def clear(self,sid):
        with self.transaction() as db:
            self.cleanup(db)
            row=db.execute('SELECT state FROM sessions WHERE sid=?',(sid,)).fetchone()
            if row and row['state'] in ('importing','queued','running','stopping'):raise Busy('Stop this session’s scan before clearing data.')
            db.execute('DELETE FROM tasks WHERE sid=?',(sid,))
            db.execute("UPDATE sessions SET items='[]',state='idle',cancelled=0,error=NULL WHERE sid=?",(sid,))

class Runner:
    def __init__(self,store,check,threads=4):
        self.store=store;self.check=check;self.stop=threading.Event()
        self.threads=[threading.Thread(target=self.loop,daemon=True) for _ in range(threads)]
        for thread in self.threads:thread.start()

    def loop(self):
        while not self.stop.is_set():
            try:
                task=self.store.claim()
                if not task:
                    self.stop.wait(.2);continue
                try:result=self.check(task['item'])
                except Exception:
                    result={'host':task['item']['host'],'saved_login':task['item']['saved_login'],
                        'login_page_hint':task['item']['login_page_hint'],'certificate':{},'tls':'Unknown',
                        'php':{'status':'Unknown','evidence':''},'error':'Check failed; try again later.'}
                self.store.complete(task,result)
            except Exception:
                # No uploaded content or historical URLs in logs. Retry shared-store contention.
                self.stop.wait(.5)

    def close(self):
        self.stop.set()
        for thread in self.threads:thread.join(timeout=10)
