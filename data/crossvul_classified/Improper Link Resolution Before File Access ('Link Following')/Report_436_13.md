# CrossVul Fix Pair: Improper Link Resolution Before File Access ('Link Following') in c
**Pair ID:** 436_13
**Vulnerability Class:** Improper Link Resolution Before File Access ('Link Following')
**CWE:** CWE-59
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `436_13`)

## Vulnerability Information & PoC

## Description
Improper Link Resolution Before File Access ('Link Following') - The product attempts to access a file based on the filename, but it does not properly prevent that filename from identifying a link or shortcut that resolves to an unintended resource.

## Vulnerable Code
```c
Lines 165-194 of the vulnerable file.

#ifdef _WITH_PERF_
extern void run_perf(const char *, const char *, const char *);
#endif
extern uint16_t in_csum(const uint16_t *, size_t, uint32_t, uint32_t *);
extern char *inet_ntop2(uint32_t);
extern bool inet_stor(const char *, uint32_t *);
extern int domain_stosockaddr(const char *, const char *, struct sockaddr_storage *);
extern int inet_stosockaddr(char *, const char *, struct sockaddr_storage *);
extern void inet_ip4tosockaddr(struct in_addr *, struct sockaddr_storage *);
extern void inet_ip6tosockaddr(struct in6_addr *, struct sockaddr_storage *);
extern char *inet_sockaddrtos(struct sockaddr_storage *);
extern char *inet_sockaddrtopair(struct sockaddr_storage *);
extern char *inet_sockaddrtotrio(struct sockaddr_storage *, uint16_t);
extern uint16_t inet_sockaddrport(struct sockaddr_storage *);
extern uint32_t inet_sockaddrip4(struct sockaddr_storage *);
extern int inet_sockaddrip6(struct sockaddr_storage *, struct in6_addr *);
extern int inet_inaddrcmp(int, const void *, const void *);
extern int inet_sockaddrcmp(const struct sockaddr_storage *, const struct sockaddr_storage *);
extern char *get_local_name(void);
extern bool string_equal(const char *, const char *);
extern void set_std_fd(bool);
extern void close_std_fd(void);
#if !defined _HAVE_LIBIPTC_ || defined _LIBIPTC_DYNAMIC_
extern int fork_exec(char **argv);
#endif
#if defined _WITH_VRRP_ || defined _WITH_BFD_
extern int open_pipe(int [2]);
#endif

#endif
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -182,6 +182,7 @@
 extern int inet_sockaddrcmp(const struct sockaddr_storage *, const struct sockaddr_storage *);
 extern char *get_local_name(void);
 extern bool string_equal(const char *, const char *);
+extern FILE *fopen_safe(const char *, const char *);
 extern void set_std_fd(bool);
 extern void close_std_fd(void);
 #if !defined _HAVE_LIBIPTC_ || defined _LIBIPTC_DYNAMIC_
```
