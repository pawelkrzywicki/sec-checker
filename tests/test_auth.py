import unittest
import io
from unittest.mock import patch
from werkzeug.security import generate_password_hash
import test_app as fixtures
import app as web

class AuthenticationTests(unittest.TestCase):
    setUp=fixtures.CheckerTests.setUp
    tearDown=fixtures.CheckerTests.tearDown
    authorize=fixtures.CheckerTests.authorize
    # Temporary shared-store setup is reused; authentication is exercised through HTTP.
    def login(self,client,password):
        client.get('/login')
        with client.session_transaction() as sess:token=sess['csrf']
        return client.post('/login',data={'password':password,'csrf':token},headers={'Origin':'http://localhost'})
    def test_hash_login_logout_and_stolen_old_cookie_revocation(self):
        hashed=generate_password_hash('correct-password-fixture')
        with patch.dict(web.os.environ,{'SEC_CHECKER_PASSWORD_HASH':hashed,'SEC_CHECKER_PASSWORD':''}):
            client=web.app.test_client()
            self.assertEqual(self.login(client,'wrong').status_code,401)
            self.assertEqual(client.get('/api/status').status_code,401)
            self.assertEqual(self.login(client,'correct-password-fixture').status_code,302)
            self.assertEqual(client.get('/').status_code,200)
            cookie=client.get_cookie(web.app.config['SESSION_COOKIE_NAME']).value
            with client.session_transaction() as sess:token=sess['csrf']
            self.assertEqual(client.post('/logout',json={},headers={'Origin':'http://localhost','X-CSRF-Token':token}).status_code,200)
            client.set_cookie(web.app.config['SESSION_COOKIE_NAME'],cookie)
            self.assertEqual(client.get('/api/status').status_code,401)
            self.assertNotIn('correct-password-fixture',cookie)
    def test_all_data_endpoints_require_authentication(self):
        client=web.app.test_client()
        for path in ['/api/status','/api/inventory','/api/report/html','/api/report/json','/api/report/csv']:
            self.assertEqual(client.get(path).status_code,401)
        for path in ['/api/upload','/api/scan','/api/clear','/api/cancel','/logout']:
            self.assertEqual(client.post(path,json={}).status_code,401)
    def test_login_csrf_and_rate_limit(self):
        client=web.app.test_client();client.get('/login')
        self.assertEqual(client.post('/login',data={'password':'fixture-password-only'},headers={'Origin':'http://localhost'}).status_code,403)
        for _ in range(10):self.assertEqual(self.login(client,'wrong').status_code,401)
        response=self.login(client,'wrong')
        self.assertEqual(response.status_code,429)
        self.assertIn('Retry-After',response.headers)
    def test_password_rotation_and_expired_session_require_login(self):
        client=web.app.test_client()
        self.assertEqual(self.login(client,'fixture-password-only').status_code,302)
        with patch.dict(web.os.environ,{'SEC_CHECKER_PASSWORD':'different-password'}):
            self.assertEqual(client.get('/api/status').status_code,401)
        self.assertEqual(self.login(client,'fixture-password-only').status_code,302)
        with client.session_transaction() as sess:sid=sess['sid']
        with web.STORE.transaction() as db:db.execute('UPDATE sessions SET expires=0 WHERE sid=?',(sid,))
        self.assertEqual(client.get('/api/status').status_code,401)

    def test_login_request_size_is_bounded_before_file_parsing(self):
        client=web.app.test_client();client.get('/login')
        with client.session_transaction() as sess:token=sess['csrf']
        response=client.post('/login',data={'csrf':token,'password':'x'*9000},headers={'Origin':'http://localhost'})
        self.assertEqual(response.status_code,413)

    def test_stale_cookie_gets_refreshed_login_form(self):
        client=web.app.test_client();client.get('/login')
        with client.session_transaction() as sess:old=sess['csrf']
        client.delete_cookie(web.app.config['SESSION_COOKIE_NAME'])
        response=client.post('/login',data={'csrf':old,'password':'fixture-password-only'},headers={'Origin':'http://localhost'})
        self.assertEqual(response.status_code,403)
        self.assertIn('This page has been refreshed',response.text)
        self.assertIn('name="csrf"',response.text)
        self.assertNotEqual(response.mimetype,'application/json')
        with client.session_transaction() as sess:token=sess['csrf']
        response=client.post('/login',data={'csrf':token,'password':'fixture-password-only'},headers={'Origin':'http://localhost'})
        self.assertEqual(response.status_code,302)
    def test_form_post_without_origin_still_requires_valid_token(self):
        client=web.app.test_client();client.get('/login')
        with client.session_transaction() as sess:token=sess['csrf']
        response=client.post('/login',data={'csrf':token,'password':'fixture-password-only'})
        self.assertEqual(response.status_code,302)
    def test_proxy_external_origin_and_cross_site_rejection(self):
        client=web.app.test_client();client.get('/login')
        with client.session_transaction() as sess:token=sess['csrf']
        response=client.post('/login',data={'csrf':token,'password':'fixture-password-only'},headers={'Origin':'https://checker.example','Sec-Fetch-Site':'same-origin'})
        self.assertEqual(response.status_code,302)
        client=web.app.test_client();client.get('/login')
        with client.session_transaction() as sess:token=sess['csrf']
        response=client.post('/login',data={'csrf':token,'password':'fixture-password-only'},headers={'Origin':'https://attacker.example','Sec-Fetch-Site':'cross-site'})
        self.assertEqual(response.status_code,403)
        self.assertIn('address does not match',response.text)
    def test_explicit_public_url_for_clients_without_fetch_metadata(self):
        client=web.app.test_client();client.get('/login')
        with client.session_transaction() as sess:token=sess['csrf']
        with patch.dict(web.os.environ,{'SEC_CHECKER_PUBLIC_URL':'https://checker.example/'}):
            response=client.post('/login',data={'csrf':token,'password':'fixture-password-only'},headers={'Origin':'https://checker.example'})
            self.assertEqual(response.status_code,302)
    def test_other_apps_generic_session_cookie_does_not_replace_app_cookie(self):
        client=web.app.test_client();client.get('/login')
        with client.session_transaction() as sess:token=sess['csrf']
        self.assertNotEqual(web.app.config['SESSION_COOKIE_NAME'],'session')
        client.set_cookie('session','another-apps-cookie')
        response=client.post('/login',data={'csrf':token,'password':'fixture-password-only'},headers={'Origin':'http://localhost'})
        self.assertEqual(response.status_code,302)

    def test_health_reports_only_nonsecret_public_configuration(self):
        with patch.dict(web.os.environ,{'SEC_CHECKER_PUBLIC_URL':'https://sec-checker.pawelkrzywicki.com'}):
            client=web.app.test_client();response=client.get('/health')
            self.assertEqual(response.status_code,200)
            self.assertEqual(response.json['public_url'],'https://sec-checker.pawelkrzywicki.com')
            self.assertEqual(set(response.json),{'status','release','public_url'})
            self.assertNotIn('fixture-password-only',response.text)
