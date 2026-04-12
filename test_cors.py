import urllib.request
import urllib.error
import json

req = urllib.request.Request(
    'https://ark-ai-guard.onrender.com/api/v1/auth/github',
    method='POST',
    headers={'Content-Type': 'application/json', 'Origin': 'https://www.devscops.xyz'},
    data=b'{"code": "fake"}'
)

try:
    res = urllib.request.urlopen(req)
    print(res.getcode(), res.headers.get('Access-Control-Allow-Origin'))
except urllib.error.HTTPError as e:
    print('ERROR:', e.code, e.reason)
    print('CORS:', e.headers.get('Access-Control-Allow-Origin'))
