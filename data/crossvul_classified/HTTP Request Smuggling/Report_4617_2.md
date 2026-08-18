# CrossVul Fix Pair: Inconsistent Interpretation of HTTP Requests ('HTTP Request/Response Smuggling') in c
**Pair ID:** 4617_2
**Vulnerability Class:** HTTP Request Smuggling
**CWE:** CWE-444
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4617_2`)

## Vulnerability Information & PoC

## Description
Inconsistent Interpretation of HTTP Requests ('HTTP Request/Response Smuggling') - HTTP requests or responses (messages) can be malformed or unexpected in ways that cause web servers or clients to interpret the messages in different ways than intermediary HTTP agents such as load...

## Vulnerable Code
```c
Lines 1-26 of the vulnerable file.

// Copyright (c) 2018, Peter Ohler, All rights reserved.

#ifndef AGOO_CON_H
#define AGOO_CON_H

#include <poll.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#ifdef HAVE_OPENSSL_SSL_H
#include <openssl/ssl.h>
#endif

#include "err.h"
#include "req.h"
#include "response.h"
#include "server.h"
#include "kinds.h"

#define MAX_HEADER_SIZE	8192

struct _agooUpgraded;
struct _agooReq;
struct _agooRes;
struct _agooBind;
struct _agooQueue;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -3,6 +3,7 @@
 #ifndef AGOO_CON_H
 #define AGOO_CON_H
 
+#include <arpa/inet.h>
 #include <poll.h>
 #include <pthread.h>
 #include <stdbool.h>
@@ -45,6 +46,7 @@
     struct _agooBind		*bind;
     struct pollfd		*pp;
     uint64_t			id;
+    char			remote[INET6_ADDRSTRLEN];
     char			buf[MAX_HEADER_SIZE];
     size_t			bcnt;
 
```
