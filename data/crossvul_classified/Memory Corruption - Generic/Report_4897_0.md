# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 4897_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4897_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 465-505 of the vulnerable file.

  return;
}

static int
rtadv_read (struct thread *thread)
{
  int sock;
  int len;
  u_char buf[RTADV_MSG_SIZE];
  struct sockaddr_in6 from;
  ifindex_t ifindex = 0;
  int hoplimit = -1;
  struct zebra_vrf *zvrf = THREAD_ARG (thread);

  sock = THREAD_FD (thread);
  zvrf->rtadv.ra_read = NULL;

  /* Register myself. */
  rtadv_event (zvrf, RTADV_READ, sock);

  len = rtadv_recv_packet (sock, buf, BUFSIZ, &from, &ifindex, &hoplimit);

  if (len < 0) 
    {
      zlog_warn ("router solicitation recv failed: %s.", safe_strerror (errno));
      return len;
    }

  rtadv_process_packet (buf, (unsigned)len, ifindex, hoplimit, zvrf->vrf_id);

  return 0;
}

static int
rtadv_make_socket (vrf_id_t vrf_id)
{
  int sock;
  int ret;
  struct icmp6_filter filter;

  if ( zserv_privs.change (ZPRIVS_RAISE) )
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -482,7 +482,7 @@
   /* Register myself. */
   rtadv_event (zvrf, RTADV_READ, sock);
 
-  len = rtadv_recv_packet (sock, buf, BUFSIZ, &from, &ifindex, &hoplimit);
+  len = rtadv_recv_packet (sock, buf, sizeof (buf), &from, &ifindex, &hoplimit);
 
   if (len < 0) 
     {
```
