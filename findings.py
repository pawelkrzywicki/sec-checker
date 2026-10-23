"""Explain exposure evidence consistently in the UI and exported reports."""
PHP_ADVISORY='https://www.php.net/archive/2026.php'
CERT_ADVISORY='https://emudhra.we-have-a-problem.com/'

def analyze(result):
    row=dict(result)
    findings=[]
    php=row.get('php',{}).get('status','Unknown')
    tls=row.get('tls','Not checked')
    if 'Potentially affected' in php:
        findings.append({'severity':'High','title':'PHP version may lack the October 21 fixes',
            'reason':row.get('php',{}).get('evidence','Advertised PHP version predates the upstream fixes.'),
            'action':'Ask the site operator to verify the installed package and any vendor backports for CVE-2026-109618 and CVE-2026-109619 before deciding it is patched.',
            'advisory':PHP_ADVISORY})
    if 'Affected eMudhra' in tls or row.get('certificate',{}).get('affected_matches'):
        findings.append({'severity':'Critical','title':'Affected eMudhra certificate key detected',
            'reason':'The presented chain matches a compromised intermediate certificate or public key.',
            'action':'Avoid submitting credentials on this connection. Ask the operator to replace the affected chain and verify your browser updates.',
            'advisory':CERT_ADVISORY})
    elif tls.startswith('TLS validation failed'):
        findings.append({'severity':'High','title':'TLS certificate validation failed',
            'reason':row.get('error') or 'The certificate failed hostname, trust or validity verification.',
            'action':'Check the certificate, hostname and chain with the site operator. Do not bypass the warning or assume this proves compromise.',
            'advisory':None})
    incomplete=bool(not findings and (row.get('error') or tls in ('Not checked','Unknown') or row.get('certificate',{}).get('chain_available') is False))
    row.update(needs_investigation=bool(findings),findings=findings,incomplete=incomplete,
        review_status='Needs investigation' if findings else 'Check incomplete' if incomplete else 'No flagged evidence',
        php_unknown=php.startswith('Unknown'))
    return row

def select(results,mode='all'):
    if mode not in ('all','investigation','incomplete'):
        raise ValueError('Unknown result filter.')
    rows=[analyze(row) for row in results]
    if mode=='investigation':return [row for row in rows if row['needs_investigation']]
    if mode=='incomplete':return [row for row in rows if row['incomplete']]
    return rows
