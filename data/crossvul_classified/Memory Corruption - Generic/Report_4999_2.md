# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 4999_2
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4999_2`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 181-221 of the vulnerable file.

	}
	return true;
}

static unsigned int
ip6t_error(struct sk_buff *skb, const struct xt_action_param *par)
{
	net_info_ratelimited("error: `%s'\n", (const char *)par->targinfo);

	return NF_DROP;
}

static inline struct ip6t_entry *
get_entry(const void *base, unsigned int offset)
{
	return (struct ip6t_entry *)(base + offset);
}

/* All zeroes == unconditional rule. */
/* Mildly perf critical (only if packet tracing is on) */
static inline bool unconditional(const struct ip6t_ip6 *ipv6)
{
	static const struct ip6t_ip6 uncond;

	return memcmp(ipv6, &uncond, sizeof(uncond)) == 0;
}

static inline const struct xt_entry_target *
ip6t_get_target_c(const struct ip6t_entry *e)
{
	return ip6t_get_target((struct ip6t_entry *)e);
}

#if IS_ENABLED(CONFIG_NETFILTER_XT_TARGET_TRACE)
/* This cries for unification! */
static const char *const hooknames[] = {
	[NF_INET_PRE_ROUTING]		= "PREROUTING",
	[NF_INET_LOCAL_IN]		= "INPUT",
	[NF_INET_FORWARD]		= "FORWARD",
	[NF_INET_LOCAL_OUT]		= "OUTPUT",
	[NF_INET_POST_ROUTING]		= "POSTROUTING",
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -198,11 +198,12 @@
 
 /* All zeroes == unconditional rule. */
 /* Mildly perf critical (only if packet tracing is on) */
-static inline bool unconditional(const struct ip6t_ip6 *ipv6)
+static inline bool unconditional(const struct ip6t_entry *e)
 {
 	static const struct ip6t_ip6 uncond;
 
-	return memcmp(ipv6, &uncond, sizeof(uncond)) == 0;
+	return e->target_offset == sizeof(struct ip6t_entry) &&
+	       memcmp(&e->ipv6, &uncond, sizeof(uncond)) == 0;
 }
 
 static inline const struct xt_entry_target *
@@ -258,11 +259,10 @@
 	} else if (s == e) {
 		(*rulenum)++;
 
-		if (s->target_offset == sizeof(struct ip6t_entry) &&
+		if (unconditional(s) &&
 		    strcmp(t->target.u.kernel.target->name,
 			   XT_STANDARD_TARGET) == 0 &&
-		    t->verdict < 0 &&
-		    unconditional(&s->ipv6)) {
+		    t->verdict < 0) {
 			/* Tail of chains: STANDARD target (return/policy) */
 			*comment = *chainname == hookname
 				? comments[NF_IP6_TRACE_COMMENT_POLICY]
@@ -488,11 +488,10 @@
 			e->comefrom |= ((1 << hook) | (1 << NF_INET_NUMHOOKS));
 
 			/* Unconditional return/END. */
-			if ((e->target_offset == sizeof(struct ip6t_entry) &&
+			if ((unconditional(e) &&
 			     (strcmp(t->target.u.user.name,
 				     XT_STANDARD_TARGET) == 0) &&
-			     t->verdict < 0 &&
-			     unconditional(&e->ipv6)) || visited) {
+			     t->verdict < 0) || visited) {
 				unsigned int oldpos, size;
 
 				if ((strcmp(t->target.u.user.name,
@@ -727,7 +726,7 @@
 	const struct xt_entry_target *t;
 	unsigned int verdict;
 
-	if (!unconditional(&e->ipv6))
+	if (!unconditional(e))
 		return false;
 	t = ip6t_get_target_c(e);
 	if (strcmp(t->u.user.name, XT_STANDARD_TARGET) != 0)
@@ -775,9 +774,9 @@
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
