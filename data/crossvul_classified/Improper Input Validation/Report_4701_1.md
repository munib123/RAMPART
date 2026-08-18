# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 4701_1
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4701_1`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 30-70 of the vulnerable file.

#endif
};

/* maxmimum string length of IP address */
#ifdef HAVE_IPV6
#  define MAX_IP_LEN INET6_ADDRSTRLEN
#else
#  define MAX_IP_LEN 20
#endif

#define IPADDR_IS_V6(ip) ((ip)->family != AF_INET)

extern IPADDR ip4_any;

/* returns 1 if IPADDRs are the same */
int net_ip_compare(IPADDR *ip1, IPADDR *ip2);

/* Connect to socket */
GIOChannel *net_connect(const char *addr, int port, IPADDR *my_ip);
/* Connect to socket with ip address and SSL*/
GIOChannel *net_connect_ip_ssl(IPADDR *ip, int port, IPADDR *my_ip, const char *cert, const char *pkey, const char *cafile, const char *capath, gboolean verify);
int irssi_ssl_handshake(GIOChannel *handle);
/* Connect to socket with ip address */
GIOChannel *net_connect_ip(IPADDR *ip, int port, IPADDR *my_ip);
/* Connect to named UNIX socket */
GIOChannel *net_connect_unix(const char *path);
/* Disconnect socket */
void net_disconnect(GIOChannel *handle);

/* Listen for connections on a socket */
GIOChannel *net_listen(IPADDR *my_ip, int *port);
/* Accept a connection on a socket */
GIOChannel *net_accept(GIOChannel *handle, IPADDR *addr, int *port);

/* Read data from socket, return number of bytes read, -1 = error */
int net_receive(GIOChannel *handle, char *buf, int len);
/* Transmit data, return number of bytes sent, -1 = error */
int net_transmit(GIOChannel *handle, const char *data, int len);

/* Get IP addresses for host, both IPv4 and IPv6 if possible.
   If ip->family is 0, the address wasn't found.
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -47,7 +47,7 @@
 /* Connect to socket */
 GIOChannel *net_connect(const char *addr, int port, IPADDR *my_ip);
 /* Connect to socket with ip address and SSL*/
-GIOChannel *net_connect_ip_ssl(IPADDR *ip, int port, IPADDR *my_ip, const char *cert, const char *pkey, const char *cafile, const char *capath, gboolean verify);
+GIOChannel *net_connect_ip_ssl(IPADDR *ip, int port, const char* hostname, IPADDR *my_ip, const char *cert, const char *pkey, const char *cafile, const char *capath, gboolean verify);
 int irssi_ssl_handshake(GIOChannel *handle);
 /* Connect to socket with ip address */
 GIOChannel *net_connect_ip(IPADDR *ip, int port, IPADDR *my_ip);
```
