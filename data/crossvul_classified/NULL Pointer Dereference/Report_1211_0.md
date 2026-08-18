# CrossVul Fix Pair: NULL Pointer Dereference in c
**Pair ID:** 1211_0
**Vulnerability Class:** NULL Pointer Dereference
**CWE:** CWE-476
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1211_0`)

## Vulnerability Information & PoC

## Description
NULL Pointer Dereference - NULL pointer dereference issues can occur through a number of flaws, including race conditions, and simple programming omissions.

## Vulnerable Code
```c
Lines 335-377 of the vulnerable file.

static void rds_tcp_kill_sock(struct net *net)
{
	struct rds_tcp_connection *tc, *_tc;
	struct sock *sk;
	LIST_HEAD(tmp_list);
	struct rds_tcp_net *rtn = net_generic(net, rds_tcp_netid);

	rds_tcp_listen_stop(rtn->rds_tcp_listen_sock);
	rtn->rds_tcp_listen_sock = NULL;
	flush_work(&rtn->rds_tcp_accept_w);
	spin_lock_irq(&rds_tcp_conn_lock);
	list_for_each_entry_safe(tc, _tc, &rds_tcp_conn_list, t_tcp_node) {
		struct net *c_net = read_pnet(&tc->conn->c_net);

		if (net != c_net)
			continue;
		list_move_tail(&tc->t_tcp_node, &tmp_list);
	}
	spin_unlock_irq(&rds_tcp_conn_lock);
	list_for_each_entry_safe(tc, _tc, &tmp_list, t_tcp_node) {
		sk = tc->t_sock->sk;
		sk->sk_prot->disconnect(sk, 0);
		tcp_done(sk);
		if (tc->conn->c_passive)
			rds_conn_destroy(tc->conn->c_passive);
		rds_conn_destroy(tc->conn);
	}
}

static int rds_tcp_dev_event(struct notifier_block *this,
			     unsigned long event, void *ptr)
{
	struct net_device *dev = netdev_notifier_info_to_dev(ptr);

	/* rds-tcp registers as a pernet subys, so the ->exit will only
	 * get invoked after network acitivity has quiesced. We need to
	 * clean up all sockets  to quiesce network activity, and use
	 * the unregistration of the per-net loopback device as a trigger
	 * to start that cleanup.
	 */
	if (event == NETDEV_UNREGISTER_FINAL &&
	    dev->ifindex == LOOPBACK_IFINDEX)
		rds_tcp_kill_sock(dev_net(dev));
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -352,9 +352,11 @@
 	}
 	spin_unlock_irq(&rds_tcp_conn_lock);
 	list_for_each_entry_safe(tc, _tc, &tmp_list, t_tcp_node) {
-		sk = tc->t_sock->sk;
-		sk->sk_prot->disconnect(sk, 0);
-		tcp_done(sk);
+		if (tc->t_sock) {
+			sk = tc->t_sock->sk;
+			sk->sk_prot->disconnect(sk, 0);
+			tcp_done(sk);
+		}
 		if (tc->conn->c_passive)
 			rds_conn_destroy(tc->conn->c_passive);
 		rds_conn_destroy(tc->conn);
```
