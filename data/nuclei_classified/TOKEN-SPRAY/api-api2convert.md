# Vulnerability: Api2Convert API Test
**Classification:** TOKEN-SPRAY
**Source:** Nuclei Template (`api-api2convert.yaml`)

## Description
Online File Conversion API

## Vulnerable Code Pattern / Exploit Payload
```http
POST https://api.api2convert.com/v2/jobs HTTP/1.1
Host: api.api2convert.com
X-Oc-Api-Key: {{token}}
Content-Type: application/json

{
    "input": [{
        "type": "remote",
        "source": "https://example-files.online-convert.com/raster%20image/jpg/example_small.jpg"
    }],
    "conversion": [{
        "target": "png"
    }]
}
```

