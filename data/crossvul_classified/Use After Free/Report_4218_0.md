# CrossVul Fix Pair: Use After Free in c
**Pair ID:** 4218_0
**Vulnerability Class:** Use After Free
**CWE:** CWE-416
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4218_0`)

## Vulnerability Information & PoC

## Description
Use After Free - The use of previously-freed memory can have any number of adverse consequences, ranging from the corruption of valid data to the execution of arbitrary code, depending on the instantiation and timi...

## Vulnerable Code
```c
Lines 4319-4359 of the vulnerable file.


      if(rc == 0) {
	flow->category = ret->category = (ndpi_protocol_category_t) id;
	return;
      }
    }
  }

  flow->category = ret->category = ndpi_get_proto_category(ndpi_str, *ret);
}

/* ********************************************************************************* */

static void ndpi_reset_packet_line_info(struct ndpi_packet_struct *packet) {
  packet->parsed_lines = 0, packet->empty_line_position_set = 0, packet->host_line.ptr = NULL,
    packet->host_line.len = 0, packet->referer_line.ptr = NULL, packet->referer_line.len = 0,
    packet->content_line.ptr = NULL, packet->content_line.len = 0, packet->accept_line.ptr = NULL,
    packet->accept_line.len = 0, packet->user_agent_line.ptr = NULL, packet->user_agent_line.len = 0,
    packet->http_url_name.ptr = NULL, packet->http_url_name.len = 0, packet->http_encoding.ptr = NULL,
    packet->http_encoding.len = 0, packet->http_transfer_encoding.ptr = NULL, packet->http_transfer_encoding.len = 0,
    packet->http_contentlen.ptr = NULL, packet->http_contentlen.len = 0, packet->http_cookie.ptr = NULL,
    packet->http_cookie.len = 0, packet->http_origin.len = 0, packet->http_origin.ptr = NULL,
    packet->http_x_session_type.ptr = NULL, packet->http_x_session_type.len = 0, packet->server_line.ptr = NULL,
    packet->server_line.len = 0, packet->http_method.ptr = NULL, packet->http_method.len = 0,
    packet->http_response.ptr = NULL, packet->http_response.len = 0, packet->http_num_headers = 0;
}

/* ********************************************************************************* */

static int ndpi_check_protocol_port_mismatch_exceptions(struct ndpi_detection_module_struct *ndpi_str,
							struct ndpi_flow_struct *flow,
							ndpi_default_ports_tree_node_t *expected_proto,
							ndpi_protocol *returned_proto) {
  /*
    For TLS (and other protocols) it is not simple to guess the exact protocol so before
    triggering an alert we need to make sure what we have exhausted all the possible
    options available
  */

  if(returned_proto->master_protocol == NDPI_PROTOCOL_TLS) {
    switch(expected_proto->proto->protoId) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -4336,7 +4336,8 @@
     packet->accept_line.len = 0, packet->user_agent_line.ptr = NULL, packet->user_agent_line.len = 0,
     packet->http_url_name.ptr = NULL, packet->http_url_name.len = 0, packet->http_encoding.ptr = NULL,
     packet->http_encoding.len = 0, packet->http_transfer_encoding.ptr = NULL, packet->http_transfer_encoding.len = 0,
-    packet->http_contentlen.ptr = NULL, packet->http_contentlen.len = 0, packet->http_cookie.ptr = NULL,
+    packet->http_contentlen.ptr = NULL, packet->http_contentlen.len = 0, packet->content_disposition_line.ptr = NULL,
+    packet->content_disposition_line.len = 0, packet->http_cookie.ptr = NULL,
     packet->http_cookie.len = 0, packet->http_origin.len = 0, packet->http_origin.ptr = NULL,
     packet->http_x_session_type.ptr = NULL, packet->http_x_session_type.len = 0, packet->server_line.ptr = NULL,
     packet->server_line.len = 0, packet->http_method.ptr = NULL, packet->http_method.len = 0,
```
