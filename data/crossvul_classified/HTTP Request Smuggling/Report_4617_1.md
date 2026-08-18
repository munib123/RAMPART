# CrossVul Fix Pair: Inconsistent Interpretation of HTTP Requests ('HTTP Request/Response Smuggling') in c
**Pair ID:** 4617_1
**Vulnerability Class:** HTTP Request Smuggling
**CWE:** CWE-444
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4617_1`)

## Vulnerability Information & PoC

## Description
Inconsistent Interpretation of HTTP Requests ('HTTP Request/Response Smuggling') - HTTP requests or responses (messages) can be malformed or unexpected in ways that cause web servers or clients to interpret the messages in different ways than intermediary HTTP agents such as load...

## Vulnerable Code
```c
Lines 46-86 of the vulnerable file.

    .kind = AGOO_CON_WS,
    .read = con_ws_read,
    .write = con_ws_write,
    .events = con_ws_events,
};

static struct _agooBind	sse_bind = {
    .kind = AGOO_CON_SSE,
    .read = NULL,
    .write = con_sse_write,
    .events = con_sse_events,
};

agooCon
agoo_con_create(agooErr err, int sock, uint64_t id, agooBind b) {
    agooCon	c;

    if (NULL == (c = (agooCon)AGOO_CALLOC(1, sizeof(struct _agooCon)))) {
	AGOO_ERR_MEM(err, "Connection");
    } else {
	c->sock = sock;
	c->id = id;
	c->timeout = dtime() + CON_TIMEOUT;
	c->bind = b;
	c->loop = NULL;
	pthread_mutex_init(&c->res_lock, 0);
    }
    return c;
}

void
agoo_con_destroy(agooCon c) {
    atomic_fetch_sub(&agoo_server.con_cnt, 1);
    if (AGOO_CON_WS == c->bind->kind || AGOO_CON_SSE == c->bind->kind) {
	agoo_ws_req_close(c);
    }
    if (0 < c->sock) {
#ifdef HAVE_OPENSSL_SSL_H
	if (NULL != c->ssl) {
	    SSL_free(c->ssl);
	    c->ssl = NULL;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -63,6 +63,22 @@
     if (NULL == (c = (agooCon)AGOO_CALLOC(1, sizeof(struct _agooCon)))) {
 	AGOO_ERR_MEM(err, "Connection");
     } else {
+	// It would be better to get this information in server.c after
+	// accept() but that does not work on macOS so instead a call to
+	// getpeername() is used instead.
+	struct sockaddr_storage	addr;
+	socklen_t		len = sizeof(addr);
+
+	getpeername(sock, (struct sockaddr*)&addr, &len);
+	if (addr.ss_family == AF_INET) {
+	    struct sockaddr_in	*s = (struct sockaddr_in*)&addr;
+
+	    inet_ntop(AF_INET, &s->sin_addr, c->remote, sizeof(c->remote));
+	} else {
+	    struct sockaddr_in6	*s = (struct sockaddr_in6*)&addr;
+
+	    inet_ntop(AF_INET6, &s->sin6_addr, c->remote, sizeof(c->remote));
+	}
 	c->sock = sock;
 	c->id = id;
 	c->timeout = dtime() + CON_TIMEOUT;
@@ -437,6 +453,7 @@
     c->req->method = method;
     c->req->upgrade = AGOO_UP_NONE;
     c->req->up = NULL;
+    memcpy(c->req->remote, c->remote, sizeof(c->remote));
     c->req->path.start = c->req->msg + (path.start - c->buf);
     c->req->path.len = (int)(path.end - path.start);
     c->req->query.start = c->req->msg + (query - c->buf);
```
