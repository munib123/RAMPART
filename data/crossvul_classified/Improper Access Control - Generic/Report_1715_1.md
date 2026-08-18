# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in c
**Pair ID:** 1715_1
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1715_1`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```c
Lines 1-40 of the vulnerable file.

/* Copyright (C) 2014 Daniel Dressler and contributors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License. */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

#include "options.h"
#include "logging.h"
#include "tcp.h"


struct tcp_sock_t *tcp_open(uint16_t port)
{
	struct tcp_sock_t *this = calloc(1, sizeof *this);
	if (this == NULL) {
		ERR("callocing this failed");
		goto error;
	}

	// Open [S]ocket [D]escriptor
	this->sd = -1;
	this->sd = socket(AF_INET6, SOCK_STREAM, 0);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -17,6 +17,9 @@
 #include <stdlib.h>
 #include <string.h>
 #include <ctype.h>
+#include <sys/time.h>
+#include <sys/types.h>
+#include <unistd.h>
 
 #include <fcntl.h>
 #include <unistd.h>
@@ -31,7 +34,58 @@
 {
 	struct tcp_sock_t *this = calloc(1, sizeof *this);
 	if (this == NULL) {
-		ERR("callocing this failed");
+		ERR("IPv4: callocing this failed");
+		goto error;
+	}
+
+	// Open [S]ocket [D]escriptor
+	this->sd = -1;
+	this->sd = socket(AF_INET, SOCK_STREAM, 0);
+	if (this->sd < 0) {
+		ERR("IPv4 socket open failed");
+		goto error;
+	}
+
+	// Configure socket params
+	struct sockaddr_in addr;
+	memset(&addr, 0, sizeof addr);
+	addr.sin_family = AF_INET;
+	addr.sin_port = htons(port);
+	addr.sin_addr.s_addr = htonl(0x7F000001);
+
+	// Bind to localhost
+	if (bind(this->sd,
+	        (struct sockaddr *)&addr,
+	        sizeof addr) < 0) {
+		if (g_options.only_desired_port == 1)
+			ERR("IPv4 bind on port failed. "
+			    "Requested port may be taken or require root permissions.");
+		goto error;
+	}
+
+	// Let kernel over-accept max number of connections
+	if (listen(this->sd, HTTP_MAX_PENDING_CONNS) < 0) {
+		ERR("IPv4 listen failed on socket");
+		goto error;
+	}
+
+	return this;
+
+error:
+	if (this != NULL) {
+		if (this->sd != -1) {
+			close(this->sd);
+		}
+		free(this);
+	}
+	return NULL;
+}
+
+struct tcp_sock_t *tcp6_open(uint16_t port)
+{
+	struct tcp_sock_t *this = calloc(1, sizeof *this);
+	if (this == NULL) {
+		ERR("IPv6: callocing this failed");
 		goto error;
 	}
 
@@ -39,7 +93,7 @@
 	this->sd = -1;
 	this->sd = socket(AF_INET6, SOCK_STREAM, 0);
 	if (this->sd < 0) {
-		ERR("sockect open failed");
+		ERR("Ipv6 socket open failed");
 		goto error;
 	}
 
@@ -48,21 +102,21 @@
 	memset(&addr, 0, sizeof addr);
 	addr.sin6_family = AF_INET6;
 	addr.sin6_port = htons(port);
-	addr.sin6_addr = in6addr_any;
+	addr.sin6_addr = in6addr_loopback;
 
 	// Bind to localhost
 	if (bind(this->sd,
 	        (struct sockaddr *)&addr,
 	        sizeof addr) < 0) {
 		if (g_options.only_desired_port == 1)
-			ERR("Bind on port failed. "
+			ERR("IPv6 bind on port failed. "
 			    "Requested port may be taken or require root permissions.");
 		goto error;
 	}
 
 	// Let kernel over-accept max number of connections
 	if (listen(this->sd, HTTP_MAX_PENDING_CONNS) < 0) {
-		ERR("listen failed on socket");
+		ERR("IPv6 listen failed on socket");
 		goto error;
 	}
 
@@ -179,20 +233,58 @@
 }
 
 
-struct tcp_conn_t *tcp_conn_accept(struct tcp_sock_t *sock)
+struct tcp_conn_t *tcp_conn_select(struct tcp_sock_t *sock,
+				   struct tcp_sock_t *sock6)
 {
 	struct tcp_conn_t *conn = calloc(1, sizeof *conn);
 	if (conn == NULL) {
 		ERR("Calloc for connection struct failed");
 		goto error;
 	}
-
-	conn->sd = accept(sock->sd, NULL, NULL);
+	fd_set rfds;
+	struct timeval tv;
+	int retval = 0;
+	int nfds = 0;
+	while (retval == 0) {
+		FD_ZERO(&rfds);
+		if (sock) {
+			FD_SET(sock->sd, &rfds);
+			nfds = sock->sd;
+		}
+		if (sock6) {
+			FD_SET(sock6->sd, &rfds);
+			if (sock6->sd > nfds)
+				nfds = sock6->sd;
+		}
+		if (nfds == 0) {
+			ERR("No valid TCP socket supplied.");
+			goto error;
+		}
+		nfds += 1;
+		/* Wait up to five seconds. */
+		tv.tv_sec = 5;
+		tv.tv_usec = 0;
+		retval = select(nfds, &rfds, NULL, NULL, &tv);
+		if (retval == -1) {
+			ERR("Failed to open tcp connection");
+			goto error;
+		}
+	}
+
+	if (sock && FD_ISSET(sock->sd, &rfds)) {
+		conn->sd = accept(sock->sd, NULL, NULL);
+		NOTE ("Using IPv4");
+	} else if (sock6 && FD_ISSET(sock6->sd, &rfds)) {
+		conn->sd = accept(sock6->sd, NULL, NULL);
+		NOTE ("Using IPv6");
+	} else {
+		ERR("select failed");
+		goto error;
+	}
 	if (conn->sd < 0) {
 		ERR("accept failed");
 		goto error;
 	}
-
 	return conn;
 
 error:
```
