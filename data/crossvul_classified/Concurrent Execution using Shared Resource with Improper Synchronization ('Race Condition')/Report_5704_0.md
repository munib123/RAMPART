# CrossVul Fix Pair: Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') in c
**Pair ID:** 5704_0
**Vulnerability Class:** Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')
**CWE:** CWE-362
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5704_0`)

## Vulnerability Information & PoC

## Description
Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') - This can have security implications when the expected synchronization is in security-critical code, such as recording whether a user is authenticated or modifying important state information that s...

## Vulnerable Code
```c
Lines 127-169 of the vulnerable file.

 * @iov:	Pointer to array of kvecs
 * @n_vec:	length of kvec array
 * @sent:	amount of data sent on socket is stored here
 *
 * Our basic "send data to server" function. Should be called with srv_mutex
 * held. The caller is responsible for handling the results.
 */
static int
smb_send_kvec(struct TCP_Server_Info *server, struct kvec *iov, size_t n_vec,
		size_t *sent)
{
	int rc = 0;
	int i = 0;
	struct msghdr smb_msg;
	unsigned int remaining;
	size_t first_vec = 0;
	struct socket *ssocket = server->ssocket;

	*sent = 0;

	if (ssocket == NULL)
		return -ENOTSOCK; /* BB eventually add reconnect code here */

	smb_msg.msg_name = (struct sockaddr *) &server->dstaddr;
	smb_msg.msg_namelen = sizeof(struct sockaddr);
	smb_msg.msg_control = NULL;
	smb_msg.msg_controllen = 0;
	if (server->noblocksnd)
		smb_msg.msg_flags = MSG_DONTWAIT + MSG_NOSIGNAL;
	else
		smb_msg.msg_flags = MSG_NOSIGNAL;

	remaining = 0;
	for (i = 0; i < n_vec; i++)
		remaining += iov[i].iov_len;

	i = 0;
	while (remaining) {
		/*
		 * If blocking send, we try 3 times, since each can block
		 * for 5 seconds. For nonblocking  we have to try more
		 * but wait increasing amounts of time allowing time for
		 * socket to clear.  The overall time we wait in either
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -143,9 +143,6 @@
 	struct socket *ssocket = server->ssocket;
 
 	*sent = 0;
-
-	if (ssocket == NULL)
-		return -ENOTSOCK; /* BB eventually add reconnect code here */
 
 	smb_msg.msg_name = (struct sockaddr *) &server->dstaddr;
 	smb_msg.msg_namelen = sizeof(struct sockaddr);
@@ -291,6 +288,9 @@
 	struct socket *ssocket = server->ssocket;
 	int val = 1;
 
+	if (ssocket == NULL)
+		return -ENOTSOCK;
+
 	cFYI(1, "Sending smb: smb_len=%u", smb_buf_length);
 	dump_smb(iov[0].iov_base, iov[0].iov_len);
 
```
