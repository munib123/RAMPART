# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in c
**Pair ID:** 2286_0
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2286_0`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```c
Lines 231-277 of the vulnerable file.

#define net_emerg_ratelimited(fmt, ...)				\
	net_ratelimited_function(pr_emerg, fmt, ##__VA_ARGS__)
#define net_alert_ratelimited(fmt, ...)				\
	net_ratelimited_function(pr_alert, fmt, ##__VA_ARGS__)
#define net_crit_ratelimited(fmt, ...)				\
	net_ratelimited_function(pr_crit, fmt, ##__VA_ARGS__)
#define net_err_ratelimited(fmt, ...)				\
	net_ratelimited_function(pr_err, fmt, ##__VA_ARGS__)
#define net_notice_ratelimited(fmt, ...)			\
	net_ratelimited_function(pr_notice, fmt, ##__VA_ARGS__)
#define net_warn_ratelimited(fmt, ...)				\
	net_ratelimited_function(pr_warn, fmt, ##__VA_ARGS__)
#define net_info_ratelimited(fmt, ...)				\
	net_ratelimited_function(pr_info, fmt, ##__VA_ARGS__)
#define net_dbg_ratelimited(fmt, ...)				\
	net_ratelimited_function(pr_debug, fmt, ##__VA_ARGS__)

bool __net_get_random_once(void *buf, int nbytes, bool *done,
			   struct static_key *done_key);

#ifdef HAVE_JUMP_LABEL
#define ___NET_RANDOM_STATIC_KEY_INIT ((struct static_key) \
		{ .enabled = ATOMIC_INIT(0), .entries = (void *)1 })
#else /* !HAVE_JUMP_LABEL */
#define ___NET_RANDOM_STATIC_KEY_INIT STATIC_KEY_INIT_FALSE
#endif /* HAVE_JUMP_LABEL */

#define net_get_random_once(buf, nbytes)				\
	({								\
		bool ___ret = false;					\
		static bool ___done = false;				\
		static struct static_key ___done_key =			\
			___NET_RANDOM_STATIC_KEY_INIT;			\
		if (!static_key_true(&___done_key))			\
			___ret = __net_get_random_once(buf,		\
						       nbytes,		\
						       &___done,	\
						       &___done_key);	\
		___ret;							\
	})

int kernel_sendmsg(struct socket *sock, struct msghdr *msg, struct kvec *vec,
		   size_t num, size_t len);
int kernel_recvmsg(struct socket *sock, struct msghdr *msg, struct kvec *vec,
		   size_t num, size_t len, int flags);

int kernel_bind(struct socket *sock, struct sockaddr *addr, int addrlen);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -248,24 +248,17 @@
 bool __net_get_random_once(void *buf, int nbytes, bool *done,
 			   struct static_key *done_key);
 
-#ifdef HAVE_JUMP_LABEL
-#define ___NET_RANDOM_STATIC_KEY_INIT ((struct static_key) \
-		{ .enabled = ATOMIC_INIT(0), .entries = (void *)1 })
-#else /* !HAVE_JUMP_LABEL */
-#define ___NET_RANDOM_STATIC_KEY_INIT STATIC_KEY_INIT_FALSE
-#endif /* HAVE_JUMP_LABEL */
-
 #define net_get_random_once(buf, nbytes)				\
 	({								\
 		bool ___ret = false;					\
 		static bool ___done = false;				\
-		static struct static_key ___done_key =			\
-			___NET_RANDOM_STATIC_KEY_INIT;			\
-		if (!static_key_true(&___done_key))			\
+		static struct static_key ___once_key =			\
+			STATIC_KEY_INIT_TRUE;				\
+		if (static_key_true(&___once_key))			\
 			___ret = __net_get_random_once(buf,		\
 						       nbytes,		\
 						       &___done,	\
-						       &___done_key);	\
+						       &___once_key);	\
 		___ret;							\
 	})
 
```
