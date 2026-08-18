# CrossVul Fix Pair: Resource Management Errors in c
**Pair ID:** 5672_0
**Vulnerability Class:** Resource Management Errors
**CWE:** CWE-399
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5672_0`)

## Vulnerability Information & PoC

## Description
Resource Management Errors

## Vulnerable Code
```c
Lines 63-103 of the vulnerable file.

		struct net_bridge_mdb_entry *mp;
		struct net_bridge_port_group *p, **pp;
		struct net_bridge_port *port;

		hlist_for_each_entry_rcu(mp, &mdb->mhash[i], hlist[mdb->ver]) {
			if (idx < s_idx)
				goto skip;

			nest2 = nla_nest_start(skb, MDBA_MDB_ENTRY);
			if (nest2 == NULL) {
				err = -EMSGSIZE;
				goto out;
			}

			for (pp = &mp->ports;
			     (p = rcu_dereference(*pp)) != NULL;
			      pp = &p->next) {
				port = p->port;
				if (port) {
					struct br_mdb_entry e;
					e.ifindex = port->dev->ifindex;
					e.state = p->state;
					if (p->addr.proto == htons(ETH_P_IP))
						e.addr.u.ip4 = p->addr.u.ip4;
#if IS_ENABLED(CONFIG_IPV6)
					if (p->addr.proto == htons(ETH_P_IPV6))
						e.addr.u.ip6 = p->addr.u.ip6;
#endif
					e.addr.proto = p->addr.proto;
					if (nla_put(skb, MDBA_MDB_ENTRY_INFO, sizeof(e), &e)) {
						nla_nest_cancel(skb, nest2);
						err = -EMSGSIZE;
						goto out;
					}
				}
			}
			nla_nest_end(skb, nest2);
		skip:
			idx++;
		}
	}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -80,6 +80,7 @@
 				port = p->port;
 				if (port) {
 					struct br_mdb_entry e;
+					memset(&e, 0, sizeof(e));
 					e.ifindex = port->dev->ifindex;
 					e.state = p->state;
 					if (p->addr.proto == htons(ETH_P_IP))
@@ -136,6 +137,7 @@
 				break;
 
 			bpm = nlmsg_data(nlh);
+			memset(bpm, 0, sizeof(*bpm));
 			bpm->ifindex = dev->ifindex;
 			if (br_mdb_fill_info(skb, cb, dev) < 0)
 				goto out;
@@ -171,6 +173,7 @@
 		return -EMSGSIZE;
 
 	bpm = nlmsg_data(nlh);
+	memset(bpm, 0, sizeof(*bpm));
 	bpm->family  = AF_BRIDGE;
 	bpm->ifindex = dev->ifindex;
 	nest = nla_nest_start(skb, MDBA_MDB);
@@ -228,6 +231,7 @@
 {
 	struct br_mdb_entry entry;
 
+	memset(&entry, 0, sizeof(entry));
 	entry.ifindex = port->dev->ifindex;
 	entry.addr.proto = group->proto;
 	entry.addr.u.ip4 = group->u.ip4;
```
