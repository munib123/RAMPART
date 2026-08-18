# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 5718_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5718_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 430-470 of the vulnerable file.


	mp = br_mdb_ip_get(mdb, &ip);
	if (!mp)
		goto unlock;

	for (pp = &mp->ports;
	     (p = mlock_dereference(*pp, br)) != NULL;
	     pp = &p->next) {
		if (!p->port || p->port->dev->ifindex != entry->ifindex)
			continue;

		if (p->port->state == BR_STATE_DISABLED)
			goto unlock;

		rcu_assign_pointer(*pp, p->next);
		hlist_del_init(&p->mglist);
		del_timer(&p->timer);
		call_rcu_bh(&p->rcu, br_multicast_free_pg);
		err = 0;

		if (!mp->ports && !mp->mglist &&
		    netif_running(br->dev))
			mod_timer(&mp->timer, jiffies);
		break;
	}

unlock:
	spin_unlock_bh(&br->multicast_lock);
	return err;
}

static int br_mdb_del(struct sk_buff *skb, struct nlmsghdr *nlh)
{
	struct net_device *dev;
	struct br_mdb_entry *entry;
	struct net_bridge *br;
	int err;

	err = br_mdb_parse(skb, nlh, &dev, &entry);
	if (err < 0)
		return err;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -447,7 +447,7 @@
 		call_rcu_bh(&p->rcu, br_multicast_free_pg);
 		err = 0;
 
-		if (!mp->ports && !mp->mglist &&
+		if (!mp->ports && !mp->mglist && mp->timer_armed &&
 		    netif_running(br->dev))
 			mod_timer(&mp->timer, jiffies);
 		break;
```
