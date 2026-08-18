# CrossVul Fix Pair: Use After Free in c
**Pair ID:** 3242_0
**Vulnerability Class:** Use After Free
**CWE:** CWE-416
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3242_0`)

## Vulnerability Information & PoC

## Description
Use After Free - The use of previously-freed memory can have any number of adverse consequences, ranging from the corruption of valid data to the execution of arbitrary code, depending on the instantiation and timi...

## Vulnerable Code
```c
Lines 5943-5983 of the vulnerable file.


static int mg_http_multipart_finalize(struct mg_connection *c) {
  struct mg_http_proto_data *pd = mg_http_get_proto_data(c);

  mg_http_multipart_call_handler(c, MG_EV_HTTP_PART_END, NULL, 0);
  MG_FREE((void *) pd->mp_stream.file_name);
  pd->mp_stream.file_name = NULL;
  MG_FREE((void *) pd->mp_stream.var_name);
  pd->mp_stream.var_name = NULL;
  mg_http_multipart_call_handler(c, MG_EV_HTTP_MULTIPART_REQUEST_END, NULL, 0);
  mg_http_free_proto_data_mp_stream(&pd->mp_stream);
  pd->mp_stream.state = MPS_FINISHED;

  return 1;
}

static int mg_http_multipart_wait_for_boundary(struct mg_connection *c) {
  const char *boundary;
  struct mbuf *io = &c->recv_mbuf;
  struct mg_http_proto_data *pd = mg_http_get_proto_data(c);

  if ((int) io->len < pd->mp_stream.boundary_len + 2) {
    return 0;
  }

  boundary = c_strnstr(io->buf, pd->mp_stream.boundary, io->len);
  if (boundary != NULL) {
    const char *boundary_end = (boundary + pd->mp_stream.boundary_len);
    if (io->len - (boundary_end - io->buf) < 4) {
      return 0;
    }
    if (strncmp(boundary_end, "--\r\n", 4) == 0) {
      pd->mp_stream.state = MPS_FINALIZE;
      mbuf_remove(io, (boundary_end - io->buf) + 4);
    } else {
      pd->mp_stream.state = MPS_GOT_BOUNDARY;
    }
  } else {
    return 0;
  }

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -5961,6 +5961,12 @@
   struct mbuf *io = &c->recv_mbuf;
   struct mg_http_proto_data *pd = mg_http_get_proto_data(c);
 
+  if (pd->mp_stream.boundary == NULL) {
+    pd->mp_stream.state = MPS_FINALIZE;
+    DBG(("Invalid request: boundary not initilaized"));
+    return 0;
+  }
+
   if ((int) io->len < pd->mp_stream.boundary_len + 2) {
     return 0;
   }
```
