# CrossVul Fix Pair: Uncontrolled Resource Consumption in c
**Pair ID:** 5872_0
**Vulnerability Class:** Uncontrolled Resource Consumption
**CWE:** CWE-400
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5872_0`)

## Vulnerability Information & PoC

## Description
Uncontrolled Resource Consumption - Limited resources include memory, file system storage, database connection pool entries, and CPU.

## Vulnerable Code
```c
Lines 273-313 of the vulnerable file.

}

static inline int cipso_v4_skbuff_delattr(struct sk_buff *skb)
{
	return -ENOSYS;
}

static inline int cipso_v4_skbuff_getattr(const struct sk_buff *skb,
					  struct netlbl_lsm_secattr *secattr)
{
	return -ENOSYS;
}

static inline int cipso_v4_validate(const struct sk_buff *skb,
				    unsigned char **option)
{
	unsigned char *opt = *option;
	unsigned char err_offset = 0;
	u8 opt_len = opt[1];
	u8 opt_iter;

	if (opt_len < 8) {
		err_offset = 1;
		goto out;
	}

	if (get_unaligned_be32(&opt[2]) == 0) {
		err_offset = 2;
		goto out;
	}

	for (opt_iter = 6; opt_iter < opt_len;) {
		if (opt[opt_iter + 1] > (opt_len - opt_iter)) {
			err_offset = opt_iter + 1;
			goto out;
		}
		opt_iter += opt[opt_iter + 1];
	}

out:
	*option = opt + err_offset;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -290,6 +290,7 @@
 	unsigned char err_offset = 0;
 	u8 opt_len = opt[1];
 	u8 opt_iter;
+	u8 tag_len;
 
 	if (opt_len < 8) {
 		err_offset = 1;
@@ -302,11 +303,12 @@
 	}
 
 	for (opt_iter = 6; opt_iter < opt_len;) {
-		if (opt[opt_iter + 1] > (opt_len - opt_iter)) {
+		tag_len = opt[opt_iter + 1];
+		if ((tag_len == 0) || (opt[opt_iter + 1] > (opt_len - opt_iter))) {
 			err_offset = opt_iter + 1;
 			goto out;
 		}
-		opt_iter += opt[opt_iter + 1];
+		opt_iter += tag_len;
 	}
 
 out:
```
