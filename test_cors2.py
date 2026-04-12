import urllib.request
import urllib.error
import json

req = urllib.request.Request(
    'https://ark-ai-guard.onrender.com/api/v1/auth/register',
    method='POST',
    headers={'Content-Type': 'application/json', 'Origin': 'https://www.devscops.xyz'},
    data=b'{"email":"test3@example.com","username":"testuser3","password":"password123","display_name":"Test User"}'
)

try:
    res = urllib.request.urlopen(req)
    print(res.getcode(), res.read().decode())
except urllib.error.HTTPError as e:
    print('ERROR:', e.code, e.reason)
    print('BODY:', e.read().decode())
