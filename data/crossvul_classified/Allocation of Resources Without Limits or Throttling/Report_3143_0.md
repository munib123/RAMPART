# CrossVul Fix Pair: Allocation of Resources Without Limits or Throttling in c
**Pair ID:** 3143_0
**Vulnerability Class:** Allocation of Resources Without Limits or Throttling
**CWE:** CWE-770
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3143_0`)

## Vulnerability Information & PoC

## Description
Allocation of Resources Without Limits or Throttling - Code frequently has to work with limited resources, so programmers must be careful to ensure that resources are not consumed too quickly, or too easily.

## Vulnerable Code
```c
Lines 1-21 of the vulnerable file.

/*	$OpenBSD: httpd.h,v 1.126 2017/01/31 12:21:27 reyk Exp $	*/

/*
 * Copyright (c) 2006 - 2015 Reyk Floeter <reyk@openbsd.org>
 * Copyright (c) 2006, 2007 Pierre-Yves Ritschard <pyr@openbsd.org>
 * Copyright (c) 2003, 2004 Henning Brauer <henning@openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ifndef _HTTPD_H
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,4 +1,4 @@
-/*	$OpenBSD: httpd.h,v 1.126 2017/01/31 12:21:27 reyk Exp $	*/
+/*	$OpenBSD: httpd.h,v 1.127 2017/01/31 14:39:47 reyk Exp $	*/
 
 /*
  * Copyright (c) 2006 - 2015 Reyk Floeter <reyk@openbsd.org>
@@ -73,6 +73,7 @@
 #define SERVER_MAX_PREFETCH	256
 #define SERVER_MIN_PREFETCHED	32
 #define SERVER_HSTS_DEFAULT_AGE	31536000
+#define SERVER_MAX_RANGES	4
 
 #define MEDIATYPE_NAMEMAX	128	/* file name extension */
 #define MEDIATYPE_TYPEMAX	64	/* length of type/subtype */
@@ -93,7 +94,8 @@
 	TOREAD_HTTP_HEADER		= -2,
 	TOREAD_HTTP_CHUNK_LENGTH	= -3,
 	TOREAD_HTTP_CHUNK_TRAILER	= -4,
-	TOREAD_HTTP_NONE		= -5
+	TOREAD_HTTP_NONE		= -5,
+	TOREAD_HTTP_RANGE		= TOREAD_HTTP_CHUNK_LENGTH
 };
 
 #if DEBUG
@@ -295,6 +297,22 @@
 	int			 headersdone;
 };
 
+struct range {
+	off_t	start;
+	off_t	end;
+};
+
+struct range_data {
+	struct range		 range[SERVER_MAX_RANGES];
+	int			 range_count;
+	int			 range_index;
+	off_t			 range_toread;
+
+	/* For the Content headers in each part */
+	struct media_type	*range_media;
+	size_t			 range_total;
+};
+
 struct client {
 	uint32_t		 clt_id;
 	pid_t			 clt_pid;
@@ -313,6 +331,7 @@
 	void			*clt_descreq;
 	void			*clt_descresp;
 	int			 clt_sndbufsiz;
+	uint64_t		 clt_boundary;
 
 	int			 clt_fd;
 	struct tls		*clt_tls_ctx;
@@ -327,6 +346,7 @@
 	int			 clt_done;
 	int			 clt_chunk;
 	int			 clt_inflight;
+	struct range_data	 clt_ranges;
 	struct fcgi_data	 clt_fcgi;
 	char			*clt_remote_user;
 	struct evbuffer		*clt_srvevb;
@@ -601,6 +621,7 @@
 	*server_httperror_byid(unsigned int);
 void	 server_read_httpcontent(struct bufferevent *, void *);
 void	 server_read_httpchunks(struct bufferevent *, void *);
+void	 server_read_httprange(struct bufferevent *, void *);
 int	 server_writeheader_http(struct client *clt, struct kv *, void *);
 int	 server_headers(struct client *, void *,
 	    int (*)(struct client *, struct kv *, void *), void *);
```
