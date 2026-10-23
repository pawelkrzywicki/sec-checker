import concurrent.futures
import multiprocessing
from pathlib import Path
import sys
import tempfile
import time
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from jobs import Store,Busy

def claim_from_process(directory):
    store=Store(directory,concurrency=2,per_session=1)
    return store.claim()

class QueueTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.store=Store(self.temp.name,concurrency=2,per_session=1)
    def tearDown(self):self.temp.cleanup()
    def seed(self,host,n=3):
        sid=self.store.ensure()
        self.store.begin_upload(sid)
        items=[{'host':f'{i}.{host}','saved_login':False,'login_page_hint':False} for i in range(n)]
        self.store.finish_upload(sid,items)
        self.store.enqueue(sid,{x['host'] for x in items})
        return sid
    def test_more_than_sixteen_isolated_sessions(self):
        ids={self.store.ensure() for _ in range(30)}
        self.assertEqual(len(ids),30)
    def test_parallel_processes_share_limits_and_secret(self):
        sessions={self.seed('a.example'),self.seed('b.example'),self.seed('c.example')}
        ctx=multiprocessing.get_context('spawn')
        with concurrent.futures.ProcessPoolExecutor(max_workers=4,mp_context=ctx) as pool:
            claims=list(pool.map(claim_from_process,[self.temp.name]*4))
        claimed=[x for x in claims if x]
        self.assertEqual(len(claimed),2)
        self.assertEqual(len({x['id'] for x in claimed}),2)
        self.assertEqual(len({x['sid'] for x in claimed}),2)
        self.assertTrue({x['sid'] for x in claimed}<=sessions)
        second=Store(self.temp.name)
        self.assertEqual(second.secret(),self.store.secret())
        for task in claimed:self.assertEqual(second.status(task['sid'])['total'],3)
    def test_fair_queue_per_session_and_global_capacity(self):
        a=self.seed('a.example');b=self.seed('b.example');c=self.seed('c.example')
        first=self.store.claim();second=self.store.claim()
        self.assertEqual({first['sid'],second['sid']},{a,b})
        self.assertIsNone(self.store.claim())
        self.store.complete(first,{'host':first['item']['host']})
        third=self.store.claim()
        self.assertEqual(third['sid'],c)
        self.assertNotIn(first['item']['host'],str(self.store.status(b)['results']))
    def test_cancel_clear_and_reupload_do_not_touch_other_users(self):
        a=self.seed('a.example');b=self.seed('b.example')
        first=self.store.claim()
        self.assertEqual(first['sid'],a)
        with self.assertRaises(Busy):self.store.begin_upload(a)
        self.store.cancel(a)
        self.assertTrue(self.store.status(a)['cancelled'])
        self.assertFalse(self.store.status(b)['cancelled'])
        self.store.complete(first,{'host':first['item']['host']})
        self.assertFalse(self.store.status(a)['running'])
        self.store.clear(a)
        self.assertEqual(self.store.inventory(a),[])
        self.assertEqual(len(self.store.inventory(b)),3)
        self.assertEqual(self.store.status(b)['total'],3)
    def test_import_slots_are_shared_and_duplicate_imports_blocked(self):
        a,b,c=[self.store.ensure() for _ in range(3)]
        self.store.begin_upload(a);self.store.begin_upload(b)
        with self.assertRaises(Busy) as error:self.store.begin_upload(c)
        self.assertEqual(error.exception.code,429)
        with self.assertRaises(Busy):self.store.begin_upload(a)
        self.store.abort_upload(a,'idle')
        self.store.begin_upload(c)
    def test_worker_recovery_rejects_late_result(self):
        sid=self.seed('a.example',n=1)
        old=self.store.claim()
        with self.store.transaction() as db:db.execute('UPDATE tasks SET lease_until=?',(time.time()-1,))
        new=self.store.claim()
        self.assertEqual(old['id'],new['id']);self.assertNotEqual(old['owner'],new['owner'])
        self.store.complete(old,{'host':'STALE RESULT'})
        self.assertEqual(self.store.status(sid)['done'],0)
        self.store.complete(new,{'host':'CORRECT RESULT'})
        self.assertEqual(self.store.status(sid)['results'],[{'host':'CORRECT RESULT'}])
    def test_cancelled_crashed_task_does_not_stick_in_queue(self):
        sid=self.seed('a.example',n=1);self.store.claim();self.store.cancel(sid)
        with self.store.transaction() as db:db.execute('UPDATE tasks SET lease_until=?',(time.time()-1,))
        self.assertFalse(self.store.status(sid)['running'])
        self.assertIsNone(self.store.claim())
    def test_expiry_removes_inventory_tasks_and_rejects_late_result(self):
        sid=self.seed('private.example',n=1);task=self.store.claim()
        with self.store.transaction() as db:db.execute('UPDATE sessions SET expires=? WHERE sid=?',(time.time()-1,sid))
        new=self.store.ensure(sid)
        self.assertNotEqual(new,sid)
        self.store.complete(task,{'host':'private.example'})
        self.assertEqual(self.store.status(new)['results'],[])
        with self.store.transaction() as db:self.assertEqual(db.execute('SELECT count(*) FROM tasks WHERE sid=?',(sid,)).fetchone()[0],0)

if __name__=='__main__':unittest.main()
