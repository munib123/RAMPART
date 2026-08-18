# CrossVul Fix Pair: Out-of-bounds Write in c
**Pair ID:** 4260_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-787
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4260_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Write - Typically, this can result in corruption of data, a crash, or code execution.

## Vulnerable Code
```c
Lines 424-464 of the vulnerable file.


static void handle_CDUP(ctrl_t *ctrl, char *path)
{
	handle_CWD(ctrl, "..");
}

static void handle_PORT(ctrl_t *ctrl, char *str)
{
	int a, b, c, d, e, f;
	char addr[INET_ADDRSTRLEN];
	struct sockaddr_in sin;

	if (ctrl->data_sd > 0) {
		uev_io_stop(&ctrl->data_watcher);
		close(ctrl->data_sd);
		ctrl->data_sd = -1;
	}

	/* Convert PORT command's argument to IP address + port */
	sscanf(str, "%d,%d,%d,%d,%d,%d", &a, &b, &c, &d, &e, &f);
	sprintf(addr, "%d.%d.%d.%d", a, b, c, d);

	/* Check IPv4 address using inet_aton(), throw away converted result */
	if (!inet_aton(addr, &(sin.sin_addr))) {
		ERR(0, "Invalid address '%s' given to PORT command", addr);
		send_msg(ctrl->sd, "500 Illegal PORT command.\r\n");
		return;
	}

	strlcpy(ctrl->data_address, addr, sizeof(ctrl->data_address));
	ctrl->data_port = e * 256 + f;

	DBG("Client PORT command accepted for %s:%d", ctrl->data_address, ctrl->data_port);
	send_msg(ctrl->sd, "200 PORT command successful.\r\n");
}

static void handle_EPRT(ctrl_t *ctrl, char *str)
{
	send_msg(ctrl->sd, "502 Command not implemented.\r\n");
}

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -441,7 +441,7 @@
 
 	/* Convert PORT command's argument to IP address + port */
 	sscanf(str, "%d,%d,%d,%d,%d,%d", &a, &b, &c, &d, &e, &f);
-	sprintf(addr, "%d.%d.%d.%d", a, b, c, d);
+	snprintf(addr, sizeof(addr), "%d.%d.%d.%d", a, b, c, d);
 
 	/* Check IPv4 address using inet_aton(), throw away converted result */
 	if (!inet_aton(addr, &(sin.sin_addr))) {
```
