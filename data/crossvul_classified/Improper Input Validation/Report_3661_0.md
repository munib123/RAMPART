# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 3661_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3661_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 684-724 of the vulnerable file.

	 */
	message = (struct cn_msg *)kvp_send_buffer;
	message->id.idx = CN_KVP_IDX;
	message->id.val = CN_KVP_VAL;

	hv_msg = (struct hv_kvp_msg *)message->data;
	hv_msg->kvp_hdr.operation = KVP_OP_REGISTER;
	message->ack = 0;
	message->len = sizeof(struct hv_kvp_msg);

	len = netlink_send(fd, message);
	if (len < 0) {
		syslog(LOG_ERR, "netlink_send failed; error:%d", len);
		close(fd);
		exit(-1);
	}

	pfd.fd = fd;

	while (1) {
		pfd.events = POLLIN;
		pfd.revents = 0;
		poll(&pfd, 1, -1);

		len = recv(fd, kvp_recv_buffer, sizeof(kvp_recv_buffer), 0);

		if (len < 0) {
			syslog(LOG_ERR, "recv failed; error:%d", len);
			close(fd);
			return -1;
		}

		incoming_msg = (struct nlmsghdr *)kvp_recv_buffer;
		incoming_cn_msg = (struct cn_msg *)NLMSG_DATA(incoming_msg);
		hv_msg = (struct hv_kvp_msg *)incoming_cn_msg->data;

		switch (hv_msg->kvp_hdr.operation) {
		case KVP_OP_REGISTER:
			/*
			 * Driver is registering with us; stash away the version
			 * information.
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -701,14 +701,18 @@
 	pfd.fd = fd;
 
 	while (1) {
+		struct sockaddr *addr_p = (struct sockaddr *) &addr;
+		socklen_t addr_l = sizeof(addr);
 		pfd.events = POLLIN;
 		pfd.revents = 0;
 		poll(&pfd, 1, -1);
 
-		len = recv(fd, kvp_recv_buffer, sizeof(kvp_recv_buffer), 0);
-
-		if (len < 0) {
-			syslog(LOG_ERR, "recv failed; error:%d", len);
+		len = recvfrom(fd, kvp_recv_buffer, sizeof(kvp_recv_buffer), 0,
+				addr_p, &addr_l);
+
+		if (len < 0 || addr.nl_pid) {
+			syslog(LOG_ERR, "recvfrom failed; pid:%u error:%d %s",
+					addr.nl_pid, errno, strerror(errno));
 			close(fd);
 			return -1;
 		}
```
