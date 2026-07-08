# Vulnerability: Symfony Profiler - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`symfony-profiler.yaml`)

## Description
Symfony profiler was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/_profiler/empty/search/results?limit=10
GET {{BaseURL}}/app_dev.php/_profiler/empty/search/results?limit=10
GET {{BaseURL}}/index.php/_profiler/empty/search/results?limit=10
GET {{BaseURL}}/index_dev.php/_profiler/empty/search/results?limit=10
GET {{BaseURL}}/dev.php/_profiler/empty/search/results?limit=10
GET {{BaseURL}}/debug.php/_profiler/empty/search/results?limit=10
GET {{BaseURL}}/_debug/_profiler/empty/search/results?limit=10
GET {{BaseURL}}/web/_profiler/empty/search/results?limit=10
GET {{BaseURL}}/public/_profiler/empty/search/results?limit=10
GET {{BaseURL}}/frontend_dev.php/_profiler/empty/search/results?limit=10
GET {{BaseURL}}/backend_dev.php/_profiler/empty/search/results?limit=10
GET {{BaseURL}}/api_dev.php/_profiler/empty/search/results?limit=10
GET {{BaseURL}}/app.php/_profiler/empty/search/results?limit=10
GET {{BaseURL}}/app_test.php/_profiler/empty/search/results?limit=10
GET {{BaseURL}}/test.php/_profiler/empty/search/results?limit=10
GET {{BaseURL}}/symfony/_profiler/empty/search/results?limit=10
GET {{BaseURL}}/debug/_profiler/empty/search/results?limit=10
GET {{BaseURL}}/dev/_profiler/empty/search/results?limit=10
GET {{BaseURL}}/profiler/empty/search/results?limit=10
```

