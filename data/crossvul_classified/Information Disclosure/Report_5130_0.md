# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in c
**Pair ID:** 5130_0
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5130_0`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```c
Lines 70-110 of the vulnerable file.

#include <linux/kernel.h>
#include <linux/prefetch.h>
#include <net/dst.h>
#include <net/tcp.h>
#include <net/inet_common.h>
#include <linux/ipsec.h>
#include <asm/unaligned.h>
#include <linux/errqueue.h>

int sysctl_tcp_timestamps __read_mostly = 1;
int sysctl_tcp_window_scaling __read_mostly = 1;
int sysctl_tcp_sack __read_mostly = 1;
int sysctl_tcp_fack __read_mostly = 1;
int sysctl_tcp_max_reordering __read_mostly = 300;
int sysctl_tcp_dsack __read_mostly = 1;
int sysctl_tcp_app_win __read_mostly = 31;
int sysctl_tcp_adv_win_scale __read_mostly = 1;
EXPORT_SYMBOL(sysctl_tcp_adv_win_scale);

/* rfc5961 challenge ack rate limiting */
int sysctl_tcp_challenge_ack_limit = 100;

int sysctl_tcp_stdurg __read_mostly;
int sysctl_tcp_rfc1337 __read_mostly;
int sysctl_tcp_max_orphans __read_mostly = NR_FILE;
int sysctl_tcp_frto __read_mostly = 2;
int sysctl_tcp_min_rtt_wlen __read_mostly = 300;

int sysctl_tcp_thin_dupack __read_mostly;

int sysctl_tcp_moderate_rcvbuf __read_mostly = 1;
int sysctl_tcp_early_retrans __read_mostly = 3;
int sysctl_tcp_invalid_ratelimit __read_mostly = HZ/2;

#define FLAG_DATA		0x01 /* Incoming frame contained data.		*/
#define FLAG_WIN_UPDATE		0x02 /* Incoming ACK was a window update.	*/
#define FLAG_DATA_ACKED		0x04 /* This ACK acknowledged new data.		*/
#define FLAG_RETRANS_DATA_ACKED	0x08 /* "" "" some of which was retransmitted.	*/
#define FLAG_SYN_ACKED		0x10 /* This ACK acknowledged SYN.		*/
#define FLAG_DATA_SACKED	0x20 /* New SACK.				*/
#define FLAG_ECE		0x40 /* ECE in this ACK				*/
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -87,7 +87,7 @@
 EXPORT_SYMBOL(sysctl_tcp_adv_win_scale);
 
 /* rfc5961 challenge ack rate limiting */
-int sysctl_tcp_challenge_ack_limit = 100;
+int sysctl_tcp_challenge_ack_limit = 1000;
 
 int sysctl_tcp_stdurg __read_mostly;
 int sysctl_tcp_rfc1337 __read_mostly;
@@ -3458,7 +3458,7 @@
 	static u32 challenge_timestamp;
 	static unsigned int challenge_count;
 	struct tcp_sock *tp = tcp_sk(sk);
-	u32 now;
+	u32 count, now;
 
 	/* First check our per-socket dupack rate limit. */
 	if (tcp_oow_rate_limited(sock_net(sk), skb,
@@ -3466,13 +3466,18 @@
 				 &tp->last_oow_ack_time))
 		return;
 
-	/* Then check the check host-wide RFC 5961 rate limit. */
+	/* Then check host-wide RFC 5961 rate limit. */
 	now = jiffies / HZ;
 	if (now != challenge_timestamp) {
+		u32 half = (sysctl_tcp_challenge_ack_limit + 1) >> 1;
+
 		challenge_timestamp = now;
-		challenge_count = 0;
-	}
-	if (++challenge_count <= sysctl_tcp_challenge_ack_limit) {
+		WRITE_ONCE(challenge_count, half +
+			   prandom_u32_max(sysctl_tcp_challenge_ack_limit));
+	}
+	count = READ_ONCE(challenge_count);
+	if (count > 0) {
+		WRITE_ONCE(challenge_count, count - 1);
 		NET_INC_STATS(sock_net(sk), LINUX_MIB_TCPCHALLENGEACK);
 		tcp_send_ack(sk);
 	}
```
