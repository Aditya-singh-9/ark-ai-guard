import urllib.request
import urllib.error
import urllib.parse
import json

login_req = urllib.request.Request(
    'https://ark-ai-guard.onrender.com/api/v1/auth/login',
    method='POST',
    headers={'Content-Type': 'application/json', 'Origin': 'https://www.devscops.xyz'},
    data=b'{"email":"Singhark94@gmail.com","password":"Aditya#99"}'
)

try:
    login_res = urllib.request.urlopen(login_req)
    token_data = json.loads(login_res.read().decode())
    token = token_data['access_token']
    
    report_req = urllib.request.Request(
        'https://ark-ai-guard.onrender.com/api/v1/vulnerability-report/2',
        method='GET',
        headers={'Authorization': f'Bearer {token}', 'Origin': 'https://www.devscops.xyz'}
    )
    report_res = urllib.request.urlopen(report_req)
    print(report_res.getcode(), report_res.read().decode())
except urllib.error.HTTPError as e:
    print('ERROR:', e.code, e.reason)
    print('BODY:', e.read().decode())
