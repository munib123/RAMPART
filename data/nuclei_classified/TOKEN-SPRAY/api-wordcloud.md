# Vulnerability: Word Cloud API Test
**Classification:** TOKEN-SPRAY
**Source:** Nuclei Template (`api-wordcloud.yaml`)

## Description
Easily create word clouds

## Vulnerable Code Pattern / Exploit Payload
```http
POST https://textvis-word-cloud-v1.p.rapidapi.com/v1/textToCloud HTTP/1.1
Host: textvis-word-cloud-v1.p.rapidapi.com
content-type: application/json
x-rapidapi-host: textvis-word-cloud-v1.p.rapidapi.com
x-rapidapi-key: {{token}}
Content-Length: 349

{
  "text": "This is a test. I repeat, this is a test. We are only testing the functionality of this api, nothing else. End of test.",
  "scale": 0.5,
  "width": 400,
  "height": 400,
  "colors": [
    "#375E97",
    "#FB6542",
    "#FFBB00",
    "#3F681C"
  ],
  "font": "Tahoma",
  "use_stopwords": true,
  "language": "en",
  "uppercase": false
}
```

