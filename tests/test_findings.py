import unittest
from findings import analyze,select

class FindingsTests(unittest.TestCase):
    def row(self,**kwargs):
        return {'host':'example.org','tls':'TLS identity/date/trust validation passed','php':{'status':'Unknown','evidence':''},**kwargs}
    def test_unknown_does_not_become_vulnerability(self):
        result=analyze(self.row())
        self.assertFalse(result['needs_investigation']);self.assertTrue(result['php_unknown'])
    def test_multiple_reasons_keep_one_flagged_site(self):
        result=analyze(self.row(tls='TLS validation failed — requires investigation',error='Certificate expired',php={'status':'Potentially affected PHP','evidence':'PHP/8.1.33'}))
        self.assertTrue(result['needs_investigation']);self.assertEqual(len(result['findings']),2)
        self.assertTrue(all(x['reason'] and x['action'] for x in result['findings']))
    def test_compromised_key_is_critical(self):
        result=analyze(self.row(tls='Affected eMudhra key present — stop using this connection'))
        self.assertEqual(result['findings'][0]['severity'],'Critical')
    def test_incomplete_is_separate_from_issue(self):
        result=analyze(self.row(error='DNS lookup failed',tls='Not checked'))
        self.assertTrue(result['incomplete']);self.assertFalse(result['needs_investigation'])
        self.assertEqual(select([result],'investigation'),[])
        self.assertEqual(len(select([result],'incomplete')),1)
