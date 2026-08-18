# CrossVul Fix Pair: Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') in c
**Pair ID:** 836_0
**Vulnerability Class:** Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')
**CWE:** CWE-362
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `836_0`)

## Vulnerability Information & PoC

## Description
Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') - This can have security implications when the expected synchronization is in security-critical code, such as recording whether a user is authenticated or modifying important state information that s...

## Vulnerable Code
```c
Lines 591-631 of the vulnerable file.


fail:
	if (net != &init_net)
		kfree(tbl);
	return err;
}

static void rds_tcp_kill_sock(struct net *net)
{
	struct rds_tcp_connection *tc, *_tc;
	LIST_HEAD(tmp_list);
	struct rds_tcp_net *rtn = net_generic(net, rds_tcp_netid);
	struct socket *lsock = rtn->rds_tcp_listen_sock;

	rtn->rds_tcp_listen_sock = NULL;
	rds_tcp_listen_stop(lsock, &rtn->rds_tcp_accept_w);
	spin_lock_irq(&rds_tcp_conn_lock);
	list_for_each_entry_safe(tc, _tc, &rds_tcp_conn_list, t_tcp_node) {
		struct net *c_net = read_pnet(&tc->t_cpath->cp_conn->c_net);

		if (net != c_net || !tc->t_sock)
			continue;
		if (!list_has_conn(&tmp_list, tc->t_cpath->cp_conn)) {
			list_move_tail(&tc->t_tcp_node, &tmp_list);
		} else {
			list_del(&tc->t_tcp_node);
			tc->t_tcp_node_detached = true;
		}
	}
	spin_unlock_irq(&rds_tcp_conn_lock);
	list_for_each_entry_safe(tc, _tc, &tmp_list, t_tcp_node)
		rds_conn_destroy(tc->t_cpath->cp_conn);
}

static void __net_exit rds_tcp_exit_net(struct net *net)
{
	struct rds_tcp_net *rtn = net_generic(net, rds_tcp_netid);

	rds_tcp_kill_sock(net);

	if (rtn->rds_tcp_sysctl)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -608,7 +608,7 @@
 	list_for_each_entry_safe(tc, _tc, &rds_tcp_conn_list, t_tcp_node) {
 		struct net *c_net = read_pnet(&tc->t_cpath->cp_conn->c_net);
 
-		if (net != c_net || !tc->t_sock)
+		if (net != c_net)
 			continue;
 		if (!list_has_conn(&tmp_list, tc->t_cpath->cp_conn)) {
 			list_move_tail(&tc->t_tcp_node, &tmp_list);
```
