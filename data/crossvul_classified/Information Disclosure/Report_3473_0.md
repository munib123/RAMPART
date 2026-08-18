# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in c
**Pair ID:** 3473_0
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3473_0`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```c
Lines 638-678 of the vulnerable file.

	if (!is_thread_group || !group_dead)
		goto send;

	stats = mk_reply(rep_skb, TASKSTATS_TYPE_TGID, tsk->tgid);
	if (!stats)
		goto err;

	memcpy(stats, tsk->signal->stats, sizeof(*stats));

send:
	send_cpu_listeners(rep_skb, listeners);
	return;
err:
	nlmsg_free(rep_skb);
}

static struct genl_ops taskstats_ops = {
	.cmd		= TASKSTATS_CMD_GET,
	.doit		= taskstats_user_cmd,
	.policy		= taskstats_cmd_get_policy,
};

static struct genl_ops cgroupstats_ops = {
	.cmd		= CGROUPSTATS_CMD_GET,
	.doit		= cgroupstats_user_cmd,
	.policy		= cgroupstats_cmd_get_policy,
};

/* Needed early in initialization */
void __init taskstats_init_early(void)
{
	unsigned int i;

	taskstats_cache = KMEM_CACHE(taskstats, SLAB_PANIC);
	for_each_possible_cpu(i) {
		INIT_LIST_HEAD(&(per_cpu(listener_array, i).list));
		init_rwsem(&(per_cpu(listener_array, i).sem));
	}
}

static int __init taskstats_init(void)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -655,6 +655,7 @@
 	.cmd		= TASKSTATS_CMD_GET,
 	.doit		= taskstats_user_cmd,
 	.policy		= taskstats_cmd_get_policy,
+	.flags		= GENL_ADMIN_PERM,
 };
 
 static struct genl_ops cgroupstats_ops = {
```
