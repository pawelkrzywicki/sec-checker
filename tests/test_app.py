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
import app as web
import scanner

class CheckerTests(unittest.TestCase):
    def setUp(self):
        web.app.config['TESTING']=True
        web.JOBS.clear()
        self.client=web.app.test_client()
        self.client.get('/')
        with self.client.session_transaction() as session: self.csrf=session['csrf']
        self.headers={'X-CSRF-Token':self.csrf,'Origin':'http://localhost'}
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
        self.assertEqual(self.client.get('/',headers={'Host':'192.168.1.10:8787'}).status_code,200)
        self.upload(b'https://example.org\n','urls.txt')
        other=web.app.test_client();other.get('/')
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
        client=web.app.test_client();base='http://192.168.1.10:8787'
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
    def test_optional_server_password(self):
        with patch.dict(web.os.environ,{'SEC_CHECKER_PASSWORD':'test-only-secret'}):
            self.assertEqual(self.client.get('/').status_code,401)
            self.assertEqual(self.client.get('/health').status_code,200)
            import base64
            auth=base64.b64encode(b'reviewer:test-only-secret').decode()
            self.assertEqual(self.client.get('/',headers={'Authorization':'Basic '+auth}).status_code,200)

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
