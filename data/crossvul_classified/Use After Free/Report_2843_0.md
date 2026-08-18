# CrossVul Fix Pair: Use After Free in c
**Pair ID:** 2843_0
**Vulnerability Class:** Use After Free
**CWE:** CWE-416
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2843_0`)

## Vulnerability Information & PoC

## Description
Use After Free - The use of previously-freed memory can have any number of adverse consequences, ranging from the corruption of valid data to the execution of arbitrary code, depending on the instantiation and timi...

## Vulnerable Code
```c
Lines 250-290 of the vulnerable file.


/* This function returns true is the peer netns has an id assigned into the
 * current netns.
 */
bool peernet_has_id(struct net *net, struct net *peer)
{
	return peernet2id(net, peer) >= 0;
}

struct net *get_net_ns_by_id(struct net *net, int id)
{
	struct net *peer;

	if (id < 0)
		return NULL;

	rcu_read_lock();
	spin_lock_bh(&net->nsid_lock);
	peer = idr_find(&net->netns_ids, id);
	if (peer)
		get_net(peer);
	spin_unlock_bh(&net->nsid_lock);
	rcu_read_unlock();

	return peer;
}

/*
 * setup_net runs the initializers for the network namespace object.
 */
static __net_init int setup_net(struct net *net, struct user_namespace *user_ns)
{
	/* Must be called with net_mutex held */
	const struct pernet_operations *ops, *saved_ops;
	int error = 0;
	LIST_HEAD(net_exit_list);

	atomic_set(&net->count, 1);
	refcount_set(&net->passive, 1);
	net->dev_base_seq = 1;
	net->user_ns = user_ns;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -267,7 +267,7 @@
 	spin_lock_bh(&net->nsid_lock);
 	peer = idr_find(&net->netns_ids, id);
 	if (peer)
-		get_net(peer);
+		peer = maybe_get_net(peer);
 	spin_unlock_bh(&net->nsid_lock);
 	rcu_read_unlock();
 
```
