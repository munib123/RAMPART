# CrossVul Fix Pair: Improper Access Control in c
**Pair ID:** 5092_0
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-284
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5092_0`)

## Vulnerability Information & PoC

## Description
Improper Access Control - Access control involves the use of several protection mechanisms such as: Authentication (proving the identity of an actor) Authorization (ensuring that a given actor can access a resource), and Ac...

## Vulnerable Code
```c
Lines 155-195 of the vulnerable file.

			ExitProcess(-1);
		}
		wsa_init = 1;
	}
#endif
	struct sockaddr_in saddr;

	if (0 > (sfd = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP))) {
		perror("socket()");
		return -1;
	}

	if (setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, (void*)&yes, sizeof(int)) == -1) {
		perror("setsockopt()");
		socket_close(sfd);
		return -1;
	}

	memset((void *) &saddr, 0, sizeof(saddr));
	saddr.sin_family = AF_INET;
	saddr.sin_addr.s_addr = htonl(INADDR_ANY);
	saddr.sin_port = htons(port);

	if (0 > bind(sfd, (struct sockaddr *) &saddr, sizeof(saddr))) {
		perror("bind()");
		socket_close(sfd);
		return -1;
	}

	if (listen(sfd, 1) == -1) {
		perror("listen()");
		socket_close(sfd);
		return -1;
	}

	return sfd;
}

int socket_connect(const char *addr, uint16_t port)
{
	int sfd = -1;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -172,7 +172,7 @@
 
 	memset((void *) &saddr, 0, sizeof(saddr));
 	saddr.sin_family = AF_INET;
-	saddr.sin_addr.s_addr = htonl(INADDR_ANY);
+	saddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
 	saddr.sin_port = htons(port);
 
 	if (0 > bind(sfd, (struct sockaddr *) &saddr, sizeof(saddr))) {
@@ -329,7 +329,7 @@
 
 	memset(&addr, 0, sizeof(addr));
 	addr.sin_family = AF_INET;
-	addr.sin_addr.s_addr = htonl(INADDR_ANY);
+	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
 	addr.sin_port = htons(port);
 
 	addr_len = sizeof(addr);
```
