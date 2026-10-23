import base64
import unittest
from unittest.mock import patch
from werkzeug.security import generate_password_hash
import test_app as fixtures
import app as web
import auth

class AuthenticationTests(unittest.TestCase):
    setUp=fixtures.CheckerTests.setUp
    tearDown=fixtures.CheckerTests.tearDown
    authorize=fixtures.CheckerTests.authorize
    def header(self,user='reviewer',password='fixture-password-only'):
        return {'Authorization':'Basic '+base64.b64encode((user+':'+password).encode()).decode()}
    def test_browser_challenge_needs_no_login_token(self):
        client=web.app.test_client()
        response=client.get('/')
        self.assertEqual(response.status_code,401)
        self.assertIn('Basic realm="Sec Checker"',response.headers['WWW-Authenticate'])
        self.assertEqual(client.get('/',headers=self.header()).status_code,200)
        self.assertEqual(client.get('/login',headers=self.header()).status_code,302)
        self.assertEqual(client.get('/',headers=self.header('wrong')).status_code,401)
        self.assertEqual(client.get('/',headers=self.header(password='wrong')).status_code,401)
    def test_all_user_data_requires_credentials_every_request(self):
        client=web.app.test_client()
        for path in ['/','/login','/api/status','/api/inventory','/api/report/html','/api/report/json','/api/report/csv']:
            self.assertEqual(client.get(path).status_code,401)
        for path in ['/api/upload','/api/scan','/api/clear','/api/cancel','/logout']:
            self.assertEqual(client.post(path,json={}).status_code,401)
        client.get('/',headers=self.header())
        # A workspace cookie alone never authorizes a request.
        self.assertEqual(client.get('/api/status').status_code,401)
        self.assertEqual(client.get('/health').status_code,200)
    def test_hash_password_and_rotation_invalidate_success_cache(self):
        client=web.app.test_client()
        with patch.dict(web.os.environ,{'SEC_CHECKER_PASSWORD_HASH':generate_password_hash('hash-password-fixture')}):
            header=self.header(password='hash-password-fixture')
            self.assertEqual(client.get('/',headers=header).status_code,200)
            with patch.dict(web.os.environ,{'SEC_CHECKER_PASSWORD_HASH':generate_password_hash('different-password')}):
                self.assertEqual(client.get('/',headers=header).status_code,401)
    def test_proxy_headers_cannot_break_basic_login(self):
        client=web.app.test_client();headers=self.header()
        headers.update({'Origin':'https://sec-checker.pawelkrzywicki.com','X-Forwarded-Proto':'https','X-Forwarded-Host':'sec-checker.pawelkrzywicki.com'})
        self.assertEqual(client.get('/',base_url='http://internal-container:8787',headers=headers).status_code,200)
        with client.session_transaction(base_url='http://internal-container:8787') as sess:token=sess['csrf']
        headers['X-CSRF-Token']=token
        self.assertEqual(client.post('/api/clear',base_url='http://internal-container:8787',headers=headers,json={}).status_code,200)
    def test_username_can_be_configured(self):
        client=web.app.test_client()
        with patch.dict(web.os.environ,{'SEC_CHECKER_USERNAME':'owner'}):
            self.assertEqual(client.get('/',headers=self.header()).status_code,401)
            self.assertEqual(client.get('/',headers=self.header('owner')).status_code,200)
    def test_failed_attempts_are_limited(self):
        client=web.app.test_client()
        for _ in range(10):self.assertEqual(client.get('/',headers=self.header(password='wrong')).status_code,401)
        response=client.get('/',headers=self.header(password='wrong'))
        self.assertEqual(response.status_code,429);self.assertIn('Retry-After',response.headers)
    def test_csrf_still_blocks_workspace_mutations(self):
        client=web.app.test_client();client.get('/',headers=self.header())
        self.assertEqual(client.post('/api/clear',headers=self.header(),json={}).status_code,403)
        with client.session_transaction() as sess:token=sess['csrf']
        headers={**self.header(),'X-CSRF-Token':token,'Sec-Fetch-Site':'cross-site'}
        self.assertEqual(client.post('/api/clear',headers=headers,json={}).status_code,403)
    def test_close_workspace_removes_data_without_claiming_browser_logout(self):
        client=web.app.test_client();client.get('/',headers=self.header())
        with client.session_transaction() as sess:sid=sess['sid'];token=sess['csrf']
        response=client.post('/logout',headers={**self.header(),'X-CSRF-Token':token},json={})
        self.assertEqual(response.json,{'workspace_closed':True})
        self.assertEqual(web.STORE.inventory(sid),[])
        self.assertEqual(client.get('/',headers=self.header()).status_code,200)
    def test_health_confirms_authentication_release_without_secrets(self):
        response=web.app.test_client().get('/health')
        self.assertEqual(response.status_code,200)
        self.assertEqual(response.json['release'],'basic-auth-1')
        self.assertNotIn('fixture-password-only',response.text)
