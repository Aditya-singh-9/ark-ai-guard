import urllib.request
import urllib.error
import json

req = urllib.request.Request(
    'https://ark-ai-guard.onrender.com/api/v1/vulnerability-report/2',
    method='GET',
    headers={'Origin': 'https://www.devscops.xyz'}
)

try:
    res = urllib.request.urlopen(req)
    print(res.getcode(), res.read().decode())
except urllib.error.HTTPError as e:
    print('ERROR:', e.code, e.reason)
    print('BODY:', e.read().decode())
