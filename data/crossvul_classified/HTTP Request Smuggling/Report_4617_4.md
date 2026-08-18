# CrossVul Fix Pair: Inconsistent Interpretation of HTTP Requests ('HTTP Request/Response Smuggling') in c
**Pair ID:** 4617_4
**Vulnerability Class:** HTTP Request Smuggling
**CWE:** CWE-444
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4617_4`)

## Vulnerability Information & PoC

## Description
Inconsistent Interpretation of HTTP Requests ('HTTP Request/Response Smuggling') - HTTP requests or responses (messages) can be malformed or unexpected in ways that cause web servers or clients to interpret the messages in different ways than intermediary HTTP agents such as load...

## Vulnerable Code
```c
Lines 1-26 of the vulnerable file.

// Copyright (c) 2018, Peter Ohler, All rights reserved.

#ifndef AGOO_REQ_H
#define AGOO_REQ_H

#include <stdint.h>

#include "hook.h"
#include "kinds.h"

struct _agooUpgraded;
struct _agooRes;

typedef enum {
    AGOO_UP_NONE	= '\0',
    AGOO_UP_WS		= 'W',
    AGOO_UP_SSE		= 'S',
} agooUpgrade;

typedef struct _agooStr {
    char		*start;
    unsigned int	len;
} *agooStr;

typedef struct _agooReq {
    agooMethod			method;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -3,6 +3,7 @@
 #ifndef AGOO_REQ_H
 #define AGOO_REQ_H
 
+#include <arpa/inet.h>
 #include <stdint.h>
 
 #include "hook.h"
@@ -32,6 +33,7 @@
     struct _agooStr		query;
     struct _agooStr		header;
     struct _agooStr		body;
+    char			remote[INET6_ADDRSTRLEN];
     void			*env;
     agooHook			hook;
     size_t			mlen;   // allocated msg length
```
