# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in c
**Pair ID:** 1715_0
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1715_0`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```c
Lines 154-196 of the vulnerable file.



	tcp_conn_close(arg->tcp);
	free(arg);
	return NULL;
}

static void start_daemon()
{
	// Capture USB device if not in no-printer mode
	struct usb_sock_t *usb_sock;
	if (g_options.noprinter_mode == 0) {
		usb_sock = usb_open();
		if (usb_sock == NULL)
			goto cleanup_usb;
	} else
		usb_sock = NULL;

	// Capture a socket
	uint16_t desired_port = g_options.desired_port;
	struct tcp_sock_t *tcp_socket;
	while ((tcp_socket = tcp_open(desired_port)) == NULL &&
	       g_options.only_desired_port == 0) {
		// Search for a free port
		desired_port ++;
		// We failed with 0 as port number or we reached the max
		// port number
		if (desired_port == 1 || desired_port == 0)
			// IANA recommendation of 49152 to 65535 for ephemeral
			// ports
			// https://en.wikipedia.org/wiki/Ephemeral_port
			desired_port = 49152;
	}
	if (tcp_socket == NULL)
		goto cleanup_tcp;

	uint16_t real_port = tcp_port_number_get(tcp_socket);
	if (desired_port != 0 && g_options.only_desired_port == 1 &&
	    desired_port != real_port) {
		ERR("Received port number did not match requested port number."
		    " The requested port number may be too high.");
		goto cleanup_tcp;
	}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -171,9 +171,12 @@
 
 	// Capture a socket
 	uint16_t desired_port = g_options.desired_port;
-	struct tcp_sock_t *tcp_socket;
-	while ((tcp_socket = tcp_open(desired_port)) == NULL &&
-	       g_options.only_desired_port == 0) {
+	struct tcp_sock_t *tcp_socket = NULL, *tcp6_socket = NULL;
+	for (;;) {
+		tcp_socket = tcp_open(desired_port);
+		tcp6_socket = tcp6_open(desired_port);
+		if (tcp_socket || tcp6_socket || g_options.only_desired_port)
+			break;
 		// Search for a free port
 		desired_port ++;
 		// We failed with 0 as port number or we reached the max
@@ -183,11 +186,16 @@
 			// ports
 			// https://en.wikipedia.org/wiki/Ephemeral_port
 			desired_port = 49152;
-	}
-	if (tcp_socket == NULL)
+		NOTE("Access to desired port failed, trying alternative port %d", desired_port);
+	}
+	if (tcp_socket == NULL && tcp6_socket == NULL)
 		goto cleanup_tcp;
 
-	uint16_t real_port = tcp_port_number_get(tcp_socket);
+	uint16_t real_port;
+	if (tcp_socket)
+	  real_port = tcp_port_number_get(tcp_socket);
+	else
+	  real_port = tcp_port_number_get(tcp6_socket);
 	if (desired_port != 0 && g_options.only_desired_port == 1 &&
 	    desired_port != real_port) {
 		ERR("Received port number did not match requested port number."
@@ -197,6 +205,9 @@
 	printf("%u|", real_port);
 	fflush(stdout);
 
+	NOTE("Port: %d, IPv4 %savailable, IPv6 %savailable",
+	     real_port, tcp_socket ? "" : "not ", tcp6_socket ? "" : "not ");
+
 	// Lose connection to caller
 	uint16_t pid;
 	if (!g_options.nofork_mode && (pid = fork()) > 0) {
@@ -216,7 +227,10 @@
 		}
 
 		args->usb_sock = usb_sock;
-		args->tcp = tcp_conn_accept(tcp_socket);
+
+		// For each request/response round we use the socket (IPv4 or
+		// IPv6) which receives data first
+		args->tcp = tcp_conn_select(tcp_socket, tcp6_socket);
 		if (args->tcp == NULL) {
 			ERR("Failed to open tcp connection");
 			goto cleanup_thread;
@@ -243,6 +257,8 @@
 cleanup_tcp:
 	if (tcp_socket!= NULL)
 		tcp_close(tcp_socket);
+	if (tcp6_socket!= NULL)
+		tcp_close(tcp6_socket);
 cleanup_usb:
 	if (usb_sock != NULL)
 		usb_close(usb_sock);
```
