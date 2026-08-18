# CrossVul Fix Pair: Resource Management Errors in c
**Pair ID:** 4966_0
**Vulnerability Class:** Resource Management Errors
**CWE:** CWE-399
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4966_0`)

## Vulnerability Information & PoC

## Description
Resource Management Errors

## Vulnerable Code
```c
Lines 1-30 of the vulnerable file.

#ifndef __LINUX_NET_AFUNIX_H
#define __LINUX_NET_AFUNIX_H

#include <linux/socket.h>
#include <linux/un.h>
#include <linux/mutex.h>
#include <net/sock.h>

void unix_inflight(struct file *fp);
void unix_notinflight(struct file *fp);
void unix_gc(void);
void wait_for_unix_gc(void);
struct sock *unix_get_socket(struct file *filp);
struct sock *unix_peer_get(struct sock *);

#define UNIX_HASH_SIZE	256
#define UNIX_HASH_BITS	8

extern unsigned int unix_tot_inflight;
extern spinlock_t unix_table_lock;
extern struct hlist_head unix_socket_table[2 * UNIX_HASH_SIZE];

struct unix_address {
	atomic_t	refcnt;
	int		len;
	unsigned int	hash;
	struct sockaddr_un name[0];
};

struct unix_skb_parms {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -6,8 +6,8 @@
 #include <linux/mutex.h>
 #include <net/sock.h>
 
-void unix_inflight(struct file *fp);
-void unix_notinflight(struct file *fp);
+void unix_inflight(struct user_struct *user, struct file *fp);
+void unix_notinflight(struct user_struct *user, struct file *fp);
 void unix_gc(void);
 void wait_for_unix_gc(void);
 struct sock *unix_get_socket(struct file *filp);
```
