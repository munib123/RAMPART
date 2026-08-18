# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in c
**Pair ID:** 5806_0
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5806_0`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```c
Lines 808-848 of the vulnerable file.


int fib6_add(struct fib6_node *root, struct rt6_info *rt, struct nl_info *info)
{
	struct fib6_node *fn, *pn = NULL;
	int err = -ENOMEM;
	int allow_create = 1;
	int replace_required = 0;

	if (info->nlh) {
		if (!(info->nlh->nlmsg_flags & NLM_F_CREATE))
			allow_create = 0;
		if (info->nlh->nlmsg_flags & NLM_F_REPLACE)
			replace_required = 1;
	}
	if (!allow_create && !replace_required)
		pr_warn("RTM_NEWROUTE with no NLM_F_CREATE or NLM_F_REPLACE\n");

	fn = fib6_add_1(root, &rt->rt6i_dst.addr, rt->rt6i_dst.plen,
			offsetof(struct rt6_info, rt6i_dst), allow_create,
			replace_required);

	if (IS_ERR(fn)) {
		err = PTR_ERR(fn);
		goto out;
	}

	pn = fn;

#ifdef CONFIG_IPV6_SUBTREES
	if (rt->rt6i_src.plen) {
		struct fib6_node *sn;

		if (!fn->subtree) {
			struct fib6_node *sfn;

			/*
			 * Create subtree.
			 *
			 *		fn[main tree]
			 *		|
			 *		sfn[subtree root]
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -825,9 +825,9 @@
 	fn = fib6_add_1(root, &rt->rt6i_dst.addr, rt->rt6i_dst.plen,
 			offsetof(struct rt6_info, rt6i_dst), allow_create,
 			replace_required);
-
 	if (IS_ERR(fn)) {
 		err = PTR_ERR(fn);
+		fn = NULL;
 		goto out;
 	}
 
```
