import io
import json
from pathlib import Path
import sqlite3
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import os
_BOOT_STATE=tempfile.TemporaryDirectory()
os.environ['SEC_CHECKER_STATE_DIR']=_BOOT_STATE.name
os.environ['SEC_CHECKER_DISABLE_RUNNER']='1'
import app as web
from jobs import Store,Runner
import scanner

class CheckerTests(unittest.TestCase):
    def setUp(self):
        self.password_patch=patch.dict(web.os.environ,{'SEC_CHECKER_PASSWORD':'fixture-password-only','SEC_CHECKER_PASSWORD_HASH':''})
        self.password_patch.start()
        web.app.config['TESTING']=True
        self.state=tempfile.TemporaryDirectory()
        web.STORE=Store(self.state.name)
        self.runner=Runner(web.STORE,lambda item:web.check_site(item),threads=2)
        self.client=web.app.test_client()
        self.authorize(self.client)
        self.client.get('/')
        with self.client.session_transaction() as session: self.csrf=session['csrf']
        self.headers={'X-CSRF-Token':self.csrf,'Origin':'http://localhost'}
    def authorize(self,client,base_url='http://localhost'):
        with client.session_transaction(base_url=base_url) as sess:sess['sid']=web.STORE.sign_in(web.auth_settings()[2])
    def tearDown(self):
        self.runner.close()
        self.state.cleanup()
        self.password_patch.stop()
    def upload(self,content,name='history.json'):
        return self.client.post('/api/upload',data={'history':(io.BytesIO(content),name)},headers=self.headers)
    def test_import_strips_secrets_and_filters(self):
        r=self.upload(json.dumps({'Browser History':[{'url':'https://example.com/login?token=SECRET','title':'PRIVATE TITLE'},{'url':'https://xvideos.com/'},{'url':'file:///private'}]}).encode())
        self.assertEqual(r.status_code,200)
        self.assertEqual(r.json['items'],[{'host':'example.com','saved_login':False,'login_page_hint':True}])
        self.assertNotIn('SECRET',r.text);self.assertNotIn('PRIVATE TITLE',r.text)
    def test_csv_and_firefox_and_chrome(self):
        self.assertEqual(self.upload(b'title,url\nprivate,https://example.org/a','history.csv').json['items'][0]['host'],'example.org')
        for table in ['urls','moz_places']:
            with tempfile.TemporaryDirectory() as tmp:
                p=Path(tmp)/'History';db=sqlite3.connect(p);db.execute(f'CREATE TABLE {table}(url text)');db.execute(f'INSERT INTO {table} VALUES (?)',('https://example.net/login?secret=private',));db.commit();db.close()
                r=self.upload(p.read_bytes(),'History');self.assertEqual(r.status_code,200);self.assertEqual(r.json['items'][0]['host'],'example.net')
    def test_csrf_origin_and_session_isolation(self):
        self.assertEqual(self.client.post('/api/upload').status_code,403)
        self.assertEqual(self.client.post('/api/clear',json={},headers={'X-CSRF-Token':self.csrf,'Origin':'https://evil.example'}).status_code,403)
        self.assertEqual(self.client.get('/',headers={'Host':'192.168.1.10:8787'}).status_code,302)
        self.upload(b'https://example.org\n','urls.txt')
        other=web.app.test_client();self.authorize(other);other.get('/')
        self.assertEqual(other.get('/api/status').json['results'],[])
        self.assertEqual(other.get('/api/report/json').status_code,400)
    def test_private_ip_and_version_rules(self):
        for ip in ['127.0.0.1','169.254.169.254','192.168.0.1','::1']:
            with patch.object(scanner.socket,'getaddrinfo',return_value=[(2,1,6,'',(ip,443))]):
                with self.assertRaises(ValueError):scanner.public_addresses('test.example')
        self.assertIn('Potentially affected',scanner.php_status('PHP/8.1.33')['status'])
        self.assertIn('includes Oct 21',scanner.php_status('PHP/8.4.27')['status'])
        self.assertEqual(scanner.php_status('cloudflare')['status'],'Unknown')
    def test_scan_download_and_clear(self):
        self.upload(b'https://example.org\n','urls.txt')
        self.assertEqual(self.client.post('/api/scan',json={'hosts':['not-uploaded.example'],'reviewed':True},headers=self.headers).status_code,400)
        fixture={'host':'example.org','login_page_hint':False,'tls':'Validated','php':{'status':'Unknown','evidence':'<script>alert(1)</script>'}}
        with patch.object(web,'check_site',return_value=fixture):
            r=self.client.post('/api/scan',json={'hosts':['example.org'],'reviewed':True},headers=self.headers)
            self.assertEqual(r.status_code,202)
            for _ in range(100):
                if not self.client.get('/api/status').json['running']:break
                time.sleep(.01)
        self.assertEqual(self.client.get('/api/status').json['done'],1)
        for kind in ['html','json','csv']:
            r=self.client.get('/api/report/'+kind);self.assertEqual(r.status_code,200);self.assertIn('attachment',r.headers['Content-Disposition'])
        self.assertIn('&lt;script&gt;',self.client.get('/api/report/html').text)
        self.client.post('/api/clear',json={},headers=self.headers)
        self.assertEqual(self.client.get('/api/report/json').status_code,400)
    def test_reject_password_database(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/'Login Data';db=sqlite3.connect(p);db.execute('CREATE TABLE logins(password_value blob)');db.commit();db.close()
            self.assertEqual(self.upload(p.read_bytes()).status_code,400)
    def test_chrome_saved_login_associations_without_secret_values(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/'Login Data'
            db=sqlite3.connect(p)
            db.execute('CREATE TABLE logins(origin_url text, password_value blob, username_value text, blacklisted_by_user int)')
            db.executemany('INSERT INTO logins VALUES (?,?,?,?)',[
                ('https://example.org/login?private=SECRET',b'ENCRYPTED_SECRET','PRIVATE_USERNAME',0),
                ('https://saved-only.example/',b'ENCRYPTED_SECRET','PRIVATE_USERNAME',0),
                ('https://blocked.example/',b'ENCRYPTED_SECRET','PRIVATE_USERNAME',1),
                ('https://empty.example/',b'','PRIVATE_USERNAME',0),
                ('https://xvideos.com/',b'ENCRYPTED_SECRET','PRIVATE_USERNAME',0)])
            db.commit();db.close()
            response=self.client.post('/api/upload',data={
                'history':(io.BytesIO(b'https://example.org/\n'),'History.txt'),
                'logins':(io.BytesIO(p.read_bytes()),'Login Data')},headers=self.headers)
            self.assertEqual(response.status_code,200)
            self.assertEqual(response.json['saved_login_domains'],2)
            self.assertEqual({x['host'] for x in response.json['items']},{'example.org','saved-only.example'})
            self.assertTrue(all(x['saved_login'] for x in response.json['items']))
            for secret in ['ENCRYPTED_SECRET','PRIVATE_USERNAME','SECRET','blocked.example','empty.example','xvideos']:
                self.assertNotIn(secret,response.text)
    def test_upload_and_scan_through_server_ip(self):
        client=web.app.test_client();base='http://192.168.1.10:8787';self.authorize(client,base)
        r=client.get('/',base_url=base)
        self.assertEqual(r.status_code,200)
        with client.session_transaction(base_url=base) as sess:csrf=sess['csrf']
        headers={'X-CSRF-Token':csrf,'Origin':base}
        r=client.post('/api/upload',base_url=base,headers=headers,data={'history':(io.BytesIO(b'https://example.org/'),'History.txt')})
        self.assertEqual(r.status_code,200)
        fixture={'host':'example.org','saved_login':False,'login_page_hint':False,'tls':'Validated','certificate':{'provider':'Test CA','issuer':'CN=Test CA'},'php':{'status':'Unknown','evidence':''}}
        with patch.object(web,'check_site',return_value=fixture):
            r=client.post('/api/scan',base_url=base,headers=headers,json={'hosts':['example.org'],'reviewed':True})
            self.assertEqual(r.status_code,202)
            for _ in range(100):
                if not client.get('/api/status',base_url=base).json['running']:break
                time.sleep(.01)
        for kind in ['html','csv','json']:
            self.assertIn('Test CA',client.get('/api/report/'+kind,base_url=base).text)
    def test_password_is_required(self):
        client=web.app.test_client()
        self.assertEqual(client.get('/').status_code,302)
        self.assertEqual(client.get('/api/status').status_code,401)
        self.assertEqual(client.get('/health').status_code,200)
        with patch.dict(web.os.environ,{'SEC_CHECKER_PASSWORD':'','SEC_CHECKER_PASSWORD_HASH':''}):
            self.assertEqual(client.get('/').status_code,503)
            self.assertEqual(client.get('/login').status_code,503)
            self.assertEqual(client.get('/api/status').status_code,503)

    def test_two_people_upload_scan_and_download_independently(self):
        import concurrent.futures
        import threading
        clients=[web.app.test_client(),web.app.test_client()]
        headers=[]
        for client in clients:
            self.authorize(client)
            client.get('/')
            with client.session_transaction() as sess:token=sess['csrf']
            headers.append({'X-CSRF-Token':token,'Origin':'http://localhost'})
        barrier=threading.Barrier(2)
        original=web.extract
        def simultaneous_extract(path):
            result=original(path);barrier.wait(timeout=5);return result
        def upload_for(index):
            host=['alice.example','bob.example'][index]
            return clients[index].post('/api/upload',headers=headers[index],data={'history':(io.BytesIO(('https://'+host+'/').encode()),'History')})
        with patch.object(web,'extract',side_effect=simultaneous_extract):
            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:responses=list(pool.map(upload_for,[0,1]))
        self.assertTrue(all(r.status_code==200 for r in responses))
        self.assertEqual(responses[0].json['items'][0]['host'],'alice.example')
        self.assertEqual(responses[1].json['items'][0]['host'],'bob.example')
        def check(item):
            return {'host':item['host'],'saved_login':False,'login_page_hint':False,'tls':'Validated','certificate':{},'php':{'status':'Unknown','evidence':''}}
        with patch.object(web,'check_site',side_effect=check):
            for index,host in enumerate(['alice.example','bob.example']):
                self.assertEqual(clients[index].post('/api/scan',headers=headers[index],json={'hosts':[host],'reviewed':True}).status_code,202)
            for _ in range(200):
                if not any(client.get('/api/status').json['running'] for client in clients):break
                time.sleep(.01)
        for index,host in enumerate(['alice.example','bob.example']):
            other=['bob.example','alice.example'][index]
            self.assertIn(host,clients[index].get('/api/report/json').text)
            self.assertNotIn(other,clients[index].get('/api/report/json').text)
            self.assertNotIn(other,clients[index].get('/api/inventory').text)
        clients[0].post('/api/clear',headers=headers[0],json={})
        self.assertEqual(clients[0].get('/api/report/json').status_code,400)
        self.assertIn('bob.example',clients[1].get('/api/report/json').text)

    def test_raw_uploads_removed_on_success_and_error(self):
        filenames=[];original=web.UploadRequest._get_file_stream
        def track(request,*args,**kwargs):
            stream=original(request,*args,**kwargs);filenames.append(stream.name);return stream
        with patch.object(web.UploadRequest,'_get_file_stream',track):
            self.assertEqual(self.upload(b'https://example.org/','History.txt').status_code,200)
            self.assertEqual(self.upload(b'not a valid URL','History.txt').status_code,400)
        self.assertEqual(len(filenames),2)
        self.assertTrue(all(not Path(name).exists() for name in filenames))
    def test_large_text_import_is_bounded(self):
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp)/'history.json'
            with path.open('wb') as stream:stream.write(b'[');stream.truncate(33*1024*1024)
            with self.assertRaisesRegex(ValueError,'32 MB'):web.extract(path)

    def test_firefox_logins_and_visited_history(self):
        with tempfile.TemporaryDirectory() as temp:
            history=Path(temp)/'places.sqlite';db=sqlite3.connect(history)
            db.execute('CREATE TABLE moz_places(id integer,url text,visit_count integer)')
            db.executemany('INSERT INTO moz_places VALUES (?,?,?)',[(1,'https://visited.example/login',2),(2,'https://bookmark-only.example/',0)])
            db.commit();db.close()
            logins={'logins':[{'hostname':'https://visited.example/','encryptedPassword':'SECRET_ENCRYPTED','encryptedUsername':'PRIVATE_NAME'},
                {'origin':'https://saved-only.example/','encryptedPassword':'SECRET_ENCRYPTED'},
                {'hostname':'https://empty.example/','encryptedPassword':''},
                {'hostname':'https://xvideos.com/','encryptedPassword':'SECRET_ENCRYPTED'}]}
            response=self.client.post('/api/upload',headers=self.headers,data={
                'history':(io.BytesIO(history.read_bytes()),'places.sqlite'),
                'logins':(io.BytesIO(json.dumps(logins).encode()),'logins.json')})
            self.assertEqual(response.status_code,200)
            self.assertEqual({x['host'] for x in response.json['items']},{'visited.example','saved-only.example'})
            self.assertEqual(response.json['saved_login_domains'],2)
            for text in ['SECRET_ENCRYPTED','PRIVATE_NAME','empty.example','bookmark-only.example','xvideos']:
                self.assertNotIn(text,response.text)
    def test_findings_filter_and_exports_match(self):
        self.upload(b'https://vulnerable.example/\nhttps://unknown.example/\n','History.txt')
        with self.client.session_transaction() as sess:sid=sess['sid']
        self.runner.close()
        web.STORE.enqueue(sid,{'vulnerable.example','unknown.example'})
        # Use direct claims with the test runner stopped to make fixtures deterministic.
        self.runner.close()
        while True:
            task=web.STORE.claim()
            if not task:break
            host=task['item']['host']
            result={'host':host,'saved_login':False,'login_page_hint':False,'tls':'TLS identity/date/trust validation passed',
                'certificate':{},'php':{'status':'Potentially affected PHP' if host=='vulnerable.example' else 'Unknown','evidence':'PHP/8.1.1'}}
            web.STORE.complete(task,result)
        state=self.client.get('/api/status').json
        flagged=[row for row in state['results'] if row['needs_investigation']]
        self.assertEqual([row['host'] for row in flagged],['vulnerable.example'])
        self.assertIn('Next',self.client.get('/api/report/csv?filter=investigation').text)
        for kind in ['html','csv','json']:
            response=self.client.get('/api/report/'+kind+'?filter=investigation')
            self.assertEqual(response.status_code,200)
            self.assertIn('vulnerable.example',response.text)
            self.assertNotIn('unknown.example',response.text)
            self.assertIn('CVE-2026-109618',response.text)
        self.assertEqual(self.client.get('/api/report/json?filter=investigation&q=nomatch').json['results'],[])
        self.assertEqual(self.client.get('/api/report/json?filter=bad').status_code,400)

    def test_edge_history_and_account_login_database(self):
        with tempfile.TemporaryDirectory() as temp:
            history=Path(temp)/'History';db=sqlite3.connect(history)
            db.execute('CREATE TABLE urls(url text)');db.execute('INSERT INTO urls VALUES (?)',('https://edge-saved.example/',));db.commit();db.close()
            logins=Path(temp)/'Login Data For Account';db=sqlite3.connect(logins)
            db.execute('CREATE TABLE logins(origin_url text,password_value blob)')
            db.execute('INSERT INTO logins VALUES (?,?)',('https://edge-saved.example/',b'EDGE_ENCRYPTED_SECRET'));db.commit();db.close()
            response=self.client.post('/api/upload',headers=self.headers,data={
                'history':(io.BytesIO(history.read_bytes()),'History'),
                'logins':(io.BytesIO(logins.read_bytes()),'Login Data For Account')})
            self.assertEqual(response.status_code,200)
            self.assertTrue(response.json['items'][0]['saved_login'])
            self.assertNotIn('EDGE_ENCRYPTED_SECRET',response.text)

    def test_actual_compromised_key_detection(self):
        # Verify the scanner compares public keys, not just issuer-name strings.
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        import hashlib
        key=ec.derive_private_key(4,ec.SECP384R1()).public_key()
        spki=key.public_bytes(serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo)
        affected=json.loads((scanner.ROOT/'affected-certificates.json').read_text())['certificates']
        self.assertIn(hashlib.sha256(spki).hexdigest().upper(),{x['spki_sha256'] for x in affected})

if __name__=='__main__':unittest.main()
