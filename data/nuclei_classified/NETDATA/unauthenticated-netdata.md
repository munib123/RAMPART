# Vulnerability: Unauthenticated Netdata
**Classification:** NETDATA
**Source:** Nuclei Template (`unauthenticated-netdata.yaml`)

## Description
Netdata is exposed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/api/v1/data?chart=system.cpu&format=json&points=125&group=average&gtime=0&options=ms%7Cflip%7Cjsonwrap%7Cnonzero&after=-120&dimensions=iowait
```

