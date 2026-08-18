# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 252_1
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `252_1`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 186-226 of the vulnerable file.

  mutt_debug(2, "Sending credentials\n");
  mutt_b64_encode(buf1, send_token.value, send_token.length, sizeof(buf1) - 2);
  gss_release_buffer(&min_stat, &send_token);
  mutt_str_strcat(buf1, sizeof(buf1), "\r\n");
  mutt_socket_send(idata->conn, buf1);

  while (maj_stat == GSS_S_CONTINUE_NEEDED)
  {
    /* Read server data */
    do
      rc = imap_cmd_step(idata);
    while (rc == IMAP_CMD_CONTINUE);

    if (rc != IMAP_CMD_RESPOND)
    {
      mutt_debug(1, "#1 Error receiving server response.\n");
      gss_release_name(&min_stat, &target_name);
      goto bail;
    }

    request_buf.length = mutt_b64_decode(buf2, idata->buf + 2);
    request_buf.value = buf2;
    sec_token = &request_buf;

    /* Write client data */
    maj_stat = gss_init_sec_context(
        &min_stat, GSS_C_NO_CREDENTIAL, &context, target_name, GSS_C_NO_OID,
        GSS_C_MUTUAL_FLAG | GSS_C_SEQUENCE_FLAG, 0, GSS_C_NO_CHANNEL_BINDINGS,
        sec_token, NULL, &send_token, (unsigned int *) &cflags, NULL);
    if (maj_stat != GSS_S_COMPLETE && maj_stat != GSS_S_CONTINUE_NEEDED)
    {
      print_gss_error(maj_stat, min_stat);
      mutt_debug(1, "Error exchanging credentials\n");
      gss_release_name(&min_stat, &target_name);

      goto err_abort_cmd;
    }
    mutt_b64_encode(buf1, send_token.value, send_token.length, sizeof(buf1) - 2);
    gss_release_buffer(&min_stat, &send_token);
    mutt_str_strcat(buf1, sizeof(buf1), "\r\n");
    mutt_socket_send(idata->conn, buf1);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -203,7 +203,7 @@
       goto bail;
     }
 
-    request_buf.length = mutt_b64_decode(buf2, idata->buf + 2);
+    request_buf.length = mutt_b64_decode(buf2, idata->buf + 2, sizeof(buf2));
     request_buf.value = buf2;
     sec_token = &request_buf;
 
@@ -238,7 +238,7 @@
     mutt_debug(1, "#2 Error receiving server response.\n");
     goto bail;
   }
-  request_buf.length = mutt_b64_decode(buf2, idata->buf + 2);
+  request_buf.length = mutt_b64_decode(buf2, idata->buf + 2, sizeof(buf2));
   request_buf.value = buf2;
 
   maj_stat = gss_unwrap(&min_stat, context, &request_buf, &send_token, &cflags, &quality);
```
