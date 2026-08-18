# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 5766_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5766_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 2060-2100 of the vulnerable file.

	udest->conn_flags	= udest_compat->conn_flags;
	udest->weight		= udest_compat->weight;
	udest->u_threshold	= udest_compat->u_threshold;
	udest->l_threshold	= udest_compat->l_threshold;
}

static int
do_ip_vs_set_ctl(struct sock *sk, int cmd, void __user *user, unsigned int len)
{
	int ret;
	unsigned char arg[MAX_ARG_LEN];
	struct ip_vs_service_user *usvc_compat;
	struct ip_vs_service_user_kern usvc;
	struct ip_vs_service *svc;
	struct ip_vs_dest_user *udest_compat;
	struct ip_vs_dest_user_kern udest;

	if (!capable(CAP_NET_ADMIN))
		return -EPERM;

	if (len != set_arglen[SET_CMDID(cmd)]) {
		pr_err("set_ctl: len %u != %u\n",
		       len, set_arglen[SET_CMDID(cmd)]);
		return -EINVAL;
	}

	if (copy_from_user(arg, user, len) != 0)
		return -EFAULT;

	/* increase the module use count */
	ip_vs_use_count_inc();

	if (mutex_lock_interruptible(&__ip_vs_mutex)) {
		ret = -ERESTARTSYS;
		goto out_dec;
	}

	if (cmd == IP_VS_SO_SET_FLUSH) {
		/* Flush the virtual service */
		ret = ip_vs_flush();
		goto out_unlock;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2077,6 +2077,10 @@
 	if (!capable(CAP_NET_ADMIN))
 		return -EPERM;
 
+	if (cmd < IP_VS_BASE_CTL || cmd > IP_VS_SO_SET_MAX)
+		return -EINVAL;
+	if (len < 0 || len >  MAX_ARG_LEN)
+		return -EINVAL;
 	if (len != set_arglen[SET_CMDID(cmd)]) {
 		pr_err("set_ctl: len %u != %u\n",
 		       len, set_arglen[SET_CMDID(cmd)]);
@@ -2352,9 +2356,13 @@
 {
 	unsigned char arg[128];
 	int ret = 0;
+	unsigned int copylen;
 
 	if (!capable(CAP_NET_ADMIN))
 		return -EPERM;
+
+	if (cmd < IP_VS_BASE_CTL || cmd > IP_VS_SO_GET_MAX)
+		return -EINVAL;
 
 	if (*len < get_arglen[GET_CMDID(cmd)]) {
 		pr_err("get_ctl: len %u < %u\n",
@@ -2362,7 +2370,11 @@
 		return -EINVAL;
 	}
 
-	if (copy_from_user(arg, user, get_arglen[GET_CMDID(cmd)]) != 0)
+	copylen = get_arglen[GET_CMDID(cmd)];
+	if (copylen > 128)
+		return -EINVAL;
+
+	if (copy_from_user(arg, user, copylen) != 0)
 		return -EFAULT;
 
 	if (mutex_lock_interruptible(&__ip_vs_mutex))
```
