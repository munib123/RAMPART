# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 4999_1
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4999_1`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 151-191 of the vulnerable file.

	return true;
}

static unsigned int
ipt_error(struct sk_buff *skb, const struct xt_action_param *par)
{
	net_info_ratelimited("error: `%s'\n", (const char *)par->targinfo);

	return NF_DROP;
}

/* Performance critical */
static inline struct ipt_entry *
get_entry(const void *base, unsigned int offset)
{
	return (struct ipt_entry *)(base + offset);
}

/* All zeroes == unconditional rule. */
/* Mildly perf critical (only if packet tracing is on) */
static inline bool unconditional(const struct ipt_ip *ip)
{
	static const struct ipt_ip uncond;

	return memcmp(ip, &uncond, sizeof(uncond)) == 0;
#undef FWINV
}

/* for const-correctness */
static inline const struct xt_entry_target *
ipt_get_target_c(const struct ipt_entry *e)
{
	return ipt_get_target((struct ipt_entry *)e);
}

#if IS_ENABLED(CONFIG_NETFILTER_XT_TARGET_TRACE)
static const char *const hooknames[] = {
	[NF_INET_PRE_ROUTING]		= "PREROUTING",
	[NF_INET_LOCAL_IN]		= "INPUT",
	[NF_INET_FORWARD]		= "FORWARD",
	[NF_INET_LOCAL_OUT]		= "OUTPUT",
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -168,11 +168,12 @@
 
 /* All zeroes == unconditional rule. */
 /* Mildly perf critical (only if packet tracing is on) */
-static inline bool unconditional(const struct ipt_ip *ip)
+static inline bool unconditional(const struct ipt_entry *e)
 {
 	static const struct ipt_ip uncond;
 
-	return memcmp(ip, &uncond, sizeof(uncond)) == 0;
+	return e->target_offset == sizeof(struct ipt_entry) &&
+	       memcmp(&e->ip, &uncond, sizeof(uncond)) == 0;
 #undef FWINV
 }
 
@@ -229,11 +230,10 @@
 	} else if (s == e) {
 		(*rulenum)++;
 
-		if (s->target_offset == sizeof(struct ipt_entry) &&
+		if (unconditional(s) &&
 		    strcmp(t->target.u.kernel.target->name,
 			   XT_STANDARD_TARGET) == 0 &&
-		   t->verdict < 0 &&
-		   unconditional(&s->ip)) {
+		   t->verdict < 0) {
 			/* Tail of chains: STANDARD target (return/policy) */
 			*comment = *chainname == hookname
 				? comments[NF_IP_TRACE_COMMENT_POLICY]
@@ -476,11 +476,10 @@
 			e->comefrom |= ((1 << hook) | (1 << NF_INET_NUMHOOKS));
 
 			/* Unconditional return/END. */
-			if ((e->target_offset == sizeof(struct ipt_entry) &&
+			if ((unconditional(e) &&
 			     (strcmp(t->target.u.user.name,
 				     XT_STANDARD_TARGET) == 0) &&
-			     t->verdict < 0 && unconditional(&e->ip)) ||
-			    visited) {
+			     t->verdict < 0) || visited) {
 				unsigned int oldpos, size;
 
 				if ((strcmp(t->target.u.user.name,
@@ -715,7 +714,7 @@
 	const struct xt_entry_target *t;
 	unsigned int verdict;
 
-	if (!unconditional(&e->ip))
+	if (!unconditional(e))
 		return false;
 	t = ipt_get_target_c(e);
 	if (strcmp(t->u.user.name, XT_STANDARD_TARGET) != 0)
@@ -763,9 +762,9 @@
 			newinfo->hook_entry[h] = hook_entries[h];
 		if ((unsigned char *)e - base == underflows[h]) {
 			if (!check_underflow(e)) {
-				pr_err("Underflows must be unconditional and "
-				       "use the STANDARD target with "
-				       "ACCEPT/DROP\n");
+				pr_debug("Underflows must be unconditional and "
+					 "use the STANDARD target with "
+					 "ACCEPT/DROP\n");
 				return -EINVAL;
 			}
 			newinfo->underflow[h] = underflows[h];
```
