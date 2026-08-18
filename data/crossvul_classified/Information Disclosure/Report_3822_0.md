# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in c
**Pair ID:** 3822_0
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3822_0`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```c
Lines 66-106 of the vulnerable file.

	__u64	soft_packet_limit;
	__u64	hard_packet_limit;
	__u64	soft_add_expires_seconds;
	__u64	hard_add_expires_seconds;
	__u64	soft_use_expires_seconds;
	__u64	hard_use_expires_seconds;
};

struct xfrm_lifetime_cur {
	__u64	bytes;
	__u64	packets;
	__u64	add_time;
	__u64	use_time;
};

struct xfrm_replay_state {
	__u32	oseq;
	__u32	seq;
	__u32	bitmap;
};

struct xfrm_replay_state_esn {
	unsigned int	bmp_len;
	__u32		oseq;
	__u32		seq;
	__u32		oseq_hi;
	__u32		seq_hi;
	__u32		replay_window;
	__u32		bmp[0];
};

struct xfrm_algo {
	char		alg_name[64];
	unsigned int	alg_key_len;    /* in bits */
	char		alg_key[0];
};

struct xfrm_algo_auth {
	char		alg_name[64];
	unsigned int	alg_key_len;    /* in bits */
	unsigned int	alg_trunc_len;  /* in bits */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -83,6 +83,8 @@
 	__u32	seq;
 	__u32	bitmap;
 };
+
+#define XFRMA_REPLAY_ESN_MAX	4096
 
 struct xfrm_replay_state_esn {
 	unsigned int	bmp_len;
```
