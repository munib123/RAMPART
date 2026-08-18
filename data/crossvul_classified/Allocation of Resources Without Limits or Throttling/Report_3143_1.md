# CrossVul Fix Pair: Allocation of Resources Without Limits or Throttling in c
**Pair ID:** 3143_1
**Vulnerability Class:** Allocation of Resources Without Limits or Throttling
**CWE:** CWE-770
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3143_1`)

## Vulnerability Information & PoC

## Description
Allocation of Resources Without Limits or Throttling - Code frequently has to work with limited resources, so programmers must be careful to ensure that resources are not consumed too quickly, or too easily.

## Vulnerable Code
```c
Lines 1-21 of the vulnerable file.

/*	$OpenBSD: server_file.c,v 1.63 2017/01/30 09:54:41 reyk Exp $	*/

/*
 * Copyright (c) 2006 - 2015 Reyk Floeter <reyk@openbsd.org>
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

#include <sys/types.h>
#include <sys/time.h>
#include <sys/stat.h>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,7 +1,7 @@
-/*	$OpenBSD: server_file.c,v 1.63 2017/01/30 09:54:41 reyk Exp $	*/
+/*	$OpenBSD: server_file.c,v 1.64 2017/01/31 14:39:47 reyk Exp $	*/
 
 /*
- * Copyright (c) 2006 - 2015 Reyk Floeter <reyk@openbsd.org>
+ * Copyright (c) 2006 - 2017 Reyk Floeter <reyk@openbsd.org>
  *
  * Permission to use, copy, modify, and distribute this software for any
  * purpose with or without fee is hereby granted, provided that the above
@@ -36,12 +36,6 @@
 
 #define MINIMUM(a, b)	(((a) < (b)) ? (a) : (b))
 #define MAXIMUM(a, b)	(((a) > (b)) ? (a) : (b))
-#define MAX_RANGES	4
-
-struct range {
-	off_t	start;
-	off_t	end;
-};
 
 int		 server_file_access(struct httpd *, struct client *,
 		    char *, size_t);
@@ -55,8 +49,7 @@
 		    struct stat *);
 int		 server_file_method(struct client *);
 int		 parse_range_spec(char *, size_t, struct range *);
-struct range	*parse_range(char *, size_t, int *);
-int		 buffer_add_range(int, struct evbuffer *, struct range *);
+int		 parse_ranges(struct client *, char *, size_t);
 
 int
 server_file_access(struct httpd *env, struct client *clt,
@@ -303,11 +296,10 @@
 	struct http_descriptor	*resp = clt->clt_descresp;
 	struct http_descriptor	*desc = clt->clt_descreq;
 	struct media_type	*media, multipart_media;
+	struct range_data	*r = &clt->clt_ranges;
 	struct range		*range;
-	struct evbuffer		*evb = NULL;
-	size_t			 content_length;
+	size_t			 content_length = 0;
 	int			 code = 500, fd = -1, i, nranges, ret;
-	uint32_t		 boundary;
 	char			 content_range[64];
 	const char		*errstr = NULL;
 
@@ -315,7 +307,7 @@
 	if (desc->http_method != HTTP_METHOD_GET)
 		return server_file_request(env, clt, path, st);
 
-	if ((range = parse_range(range_str, st->st_size, &nranges)) == NULL) {
+	if ((nranges = parse_ranges(clt, range_str, st->st_size)) < 1) {
 		code = 416;
 		(void)snprintf(content_range, sizeof(content_range),
 		    "bytes */%lld", st->st_size);
@@ -328,12 +320,10 @@
 		goto abort;
 
 	media = media_find_config(env, srv_conf, path);
-	if ((evb = evbuffer_new()) == NULL) {
-		errstr = "failed to allocate file buffer";
-		goto abort;
-	}
+	r->range_media = media;
 
 	if (nranges == 1) {
+		range = &r->range[0];
 		(void)snprintf(content_range, sizeof(content_range),
 		    "bytes %lld-%lld/%lld", range->start, range->end,
 		    st->st_size);
@@ -341,56 +331,46 @@
 		    content_range) == NULL)
 			goto abort;
 
-		content_length = range->end - range->start + 1;
-		if (buffer_add_range(fd, evb, range) == 0)
+		range = &r->range[0];
+		content_length += range->end - range->start + 1;
+	} else {
+		/* Add boundary, all parts will be handled by the callback */
+		arc4random_buf(&clt->clt_boundary, sizeof(clt->clt_boundary));
+
+		/* Calculate Content-Length of the complete multipart body */
+		for (i = 0; i < nranges; i++) {
+			range = &r->range[i];
+
+			/* calculate Content-Length of the complete body */
+			if ((ret = snprintf(NULL, 0,
+			    "\r\n--%llu\r\n"
+			    "Content-Type: %s/%s\r\n"
+			    "Content-Range: bytes %lld-%lld/%lld\r\n\r\n",
+			    clt->clt_boundary,
+			    media->media_type, media->media_subtype,
+			    range->start, range->end, st->st_size)) < 0)
+				goto abort;
+
+			/* Add data length */
+			content_length += ret + range->end - range->start + 1;
+
+		}
+		if ((ret = snprintf(NULL, 0, "\r\n--%llu--\r\n",
+		    clt->clt_boundary)) < 0)
 			goto abort;
-
-	} else {
-		content_length = 0;
-		boundary = arc4random();
-		/* Generate a multipart payload of byteranges */
-		while (nranges--) {
-			if ((i = evbuffer_add_printf(evb, "\r\n--%ud\r\n",
-			    boundary)) == -1)
-				goto abort;
-
-			content_length += i;
-			if ((i = evbuffer_add_printf(evb,
-			    "Content-Type: %s/%s\r\n",
-			    media->media_type, media->media_subtype)) == -1)
-				goto abort;
-
-			content_length += i;
-			if ((i = evbuffer_add_printf(evb,
-			    "Content-Range: bytes %lld-%lld/%lld\r\n\r\n",
-			    range->start, range->end, st->st_size)) == -1)
-				goto abort;
-
-			content_length += i;
-			if (buffer_add_range(fd, evb, range) == 0)
-				goto abort;
-
-			content_length += range->end - range->start + 1;
-			range++;
-		}
-
-		if ((i = evbuffer_add_printf(evb, "\r\n--%ud--\r\n",
-		    boundary)) == -1)
-			goto abort;
-
-		content_length += i;
+		content_length += ret;
 
 		/* prepare multipart/byteranges media type */
 		(void)strlcpy(multipart_media.media_type, "multipart",
 		    sizeof(multipart_media.media_type));
 		(void)snprintf(multipart_media.media_subtype,
 		    sizeof(multipart_media.media_subtype),
-		    "byteranges; boundary=%ud", boundary);
+		    "byteranges; boundary=%llu", clt->clt_boundary);
 		media = &multipart_media;
 	}
 
-	close(fd);
-	fd = -1;
+	/* Start with first range */
+	r->range_toread = TOREAD_HTTP_RANGE;
 
 	ret = server_response_http(clt, 206, media, content_length,
 	    MINIMUM(time(NULL), st->st_mtim.tv_sec));
@@ -399,23 +379,34 @@
 		goto fail;
 	case 0:
 		/* Connection is already finished */
+		close(fd);
 		goto done;
 	default:
 		break;
 	}
 
-	if (server_bufferevent_write_buffer(clt, evb) == -1)
-		goto fail;
-
-	bufferevent_enable(clt->clt_bev, EV_READ|EV_WRITE);
-	if (clt->clt_persist)
-		clt->clt_toread = TOREAD_HTTP_HEADER;
-	else
-		clt->clt_toread = TOREAD_HTTP_NONE;
-	clt->clt_done = 0;
+	clt->clt_fd = fd;
+	if (clt->clt_srvbev != NULL)
+		bufferevent_free(clt->clt_srvbev);
+
+	clt->clt_srvbev_throttled = 0;
+	clt->clt_srvbev = bufferevent_new(clt->clt_fd, server_read_httprange,
+	    server_write, server_file_error, clt);
+	if (clt->clt_srvbev == NULL) {
+		errstr = "failed to allocate file buffer event";
+		goto fail;
+	}
+
+	/* Adjust read watermark to the socket output buffer size */
+	bufferevent_setwatermark(clt->clt_srvbev, EV_READ, 0,
+	    clt->clt_sndbufsiz);
+
+	bufferevent_settimeout(clt->clt_srvbev,
+	    srv_conf->timeout.tv_sec, srv_conf->timeout.tv_sec);
+	bufferevent_enable(clt->clt_srvbev, EV_READ);
+	bufferevent_disable(clt->clt_bev, EV_READ);
 
  done:
-	evbuffer_free(evb);
 	server_reset_http(clt);
 	return (0);
  fail:
@@ -423,8 +414,6 @@
 	bufferevent_free(clt->clt_bev);
 	clt->clt_bev = NULL;
  abort:
-	if (evb != NULL)
-		evbuffer_free(evb);
 	if (fd != -1)
 		close(fd);
 	if (errstr == NULL)
@@ -668,41 +657,44 @@
 	return (-1);
 }
 
-struct range *
-parse_range(char *str, size_t file_sz, int *nranges)
-{
-	static struct range	 ranges[MAX_RANGES];
+int
+parse_ranges(struct client *clt, char *str, size_t file_sz)
+{
 	int			 i = 0;
 	char			*p, *q;
+	struct range_data	*r = &clt->clt_ranges;
+
+	memset(r, 0, sizeof(*r));
 
 	/* Extract range unit */
 	if ((p = strchr(str, '=')) == NULL)
-		return (NULL);
+		return (-1);
 
 	*p++ = '\0';
 	/* Check if it's a bytes range spec */
 	if (strcmp(str, "bytes") != 0)
-		return (NULL);
+		return (-1);
 
 	while ((q = strchr(p, ',')) != NULL) {
 		*q++ = '\0';
 
 		/* Extract start and end positions */
-		if (parse_range_spec(p, file_sz, &ranges[i]) == 0)
+		if (parse_range_spec(p, file_sz, &r->range[i]) == 0)
 			continue;
 
 		i++;
-		if (i == MAX_RANGES)
-			return (NULL);
+		if (i == SERVER_MAX_RANGES)
+			return (-1);
 
 		p = q;
 	}
 
-	if (parse_range_spec(p, file_sz, &ranges[i]) != 0)
+	if (parse_range_spec(p, file_sz, &r->range[i]) != 0)
 		i++;
 
-	*nranges = i;
-	return (i ? ranges : NULL);
+	r->range_total = file_sz;
+	r->range_count = i;
+	return (i);
 }
 
 int
@@ -752,26 +744,3 @@
 
 	return (1);
 }
-
-int
-buffer_add_range(int fd, struct evbuffer *evb, struct range *range)
-{
-	char	buf[BUFSIZ];
-	size_t	n, range_sz;
-	ssize_t	nread;
-
-	if (lseek(fd, range->start, SEEK_SET) == -1)
-		return (0);
-
-	range_sz = range->end - range->start + 1;
-	while (range_sz) {
-		n = MINIMUM(range_sz, sizeof(buf));
-		if ((nread = read(fd, buf, n)) == -1)
-			return (0);
-
-		evbuffer_add(evb, buf, nread);
-		range_sz -= nread;
-	}
-
-	return (1);
-}
```
