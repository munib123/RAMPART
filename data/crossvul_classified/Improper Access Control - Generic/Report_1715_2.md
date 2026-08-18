# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in c
**Pair ID:** 1715_2
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1715_2`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```c
Lines 23-51 of the vulnerable file.

#include "http.h"

#define HTTP_MAX_PENDING_CONNS 0
#define BUFFER_STEP (1 << 13)
#define BUFFER_STEP_RATIO (2)
#define BUFFER_INIT_RATIO (1)
#define BUFFER_MAX (1 << 20)

struct tcp_sock_t {
	int sd;
	struct sockaddr_in6 info;
	socklen_t info_size;
};

struct tcp_conn_t {
	int sd;
	int is_closed;
};

struct tcp_sock_t *tcp_open(uint16_t);
void tcp_close(struct tcp_sock_t *);
uint16_t tcp_port_number_get(struct tcp_sock_t *);

struct tcp_conn_t *tcp_conn_accept(struct tcp_sock_t *);
void tcp_conn_close(struct tcp_conn_t *);

struct http_packet_t *tcp_packet_get(struct tcp_conn_t *,
                                     struct http_message_t *);
void tcp_packet_send(struct tcp_conn_t *, struct http_packet_t *);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -40,10 +40,12 @@
 };
 
 struct tcp_sock_t *tcp_open(uint16_t);
+struct tcp_sock_t *tcp6_open(uint16_t);
 void tcp_close(struct tcp_sock_t *);
 uint16_t tcp_port_number_get(struct tcp_sock_t *);
 
-struct tcp_conn_t *tcp_conn_accept(struct tcp_sock_t *);
+struct tcp_conn_t *tcp_conn_select(struct tcp_sock_t *sock,
+				   struct tcp_sock_t *sock6);
 void tcp_conn_close(struct tcp_conn_t *);
 
 struct http_packet_t *tcp_packet_get(struct tcp_conn_t *,
```
