# CrossVul Fix Pair: Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') in c
**Pair ID:** 2116_0
**Vulnerability Class:** Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')
**CWE:** CWE-362
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2116_0`)

## Vulnerability Information & PoC

## Description
Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') - This can have security implications when the expected synchronization is in security-critical code, such as recording whether a user is authenticated or modifying important state information that s...

## Vulnerable Code
```c
Lines 313-353 of the vulnerable file.

		}

		if (tx_latency->n_ranges) {
			for (i = 0; i < IEEE80211_NUM_TIDS; i++) {
				/* size of bins is size of the ranges +1 */
				sta->tx_lat[i].bin_count =
					tx_latency->n_ranges + 1;
				sta->tx_lat[i].bins =
					kcalloc(sta->tx_lat[i].bin_count,
						sizeof(u32), GFP_ATOMIC);
				if (!sta->tx_lat[i].bins) {
					rcu_read_unlock();
					goto free;
				}
			}
		}
	}
	rcu_read_unlock();

	spin_lock_init(&sta->lock);
	INIT_WORK(&sta->drv_unblock_wk, sta_unblock);
	INIT_WORK(&sta->ampdu_mlme.work, ieee80211_ba_session_work);
	mutex_init(&sta->ampdu_mlme.mtx);
#ifdef CONFIG_MAC80211_MESH
	if (ieee80211_vif_is_mesh(&sdata->vif) &&
	    !sdata->u.mesh.user_mpm)
		init_timer(&sta->plink_timer);
	sta->nonpeer_pm = NL80211_MESH_POWER_ACTIVE;
#endif

	memcpy(sta->sta.addr, addr, ETH_ALEN);
	sta->local = local;
	sta->sdata = sdata;
	sta->last_rx = jiffies;

	sta->sta_state = IEEE80211_STA_NONE;

	do_posix_clock_monotonic_gettime(&uptime);
	sta->last_connected = uptime.tv_sec;
	ewma_init(&sta->avg_signal, 1024, 8);
	for (i = 0; i < ARRAY_SIZE(sta->chain_signal_avg); i++)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -330,6 +330,7 @@
 	rcu_read_unlock();
 
 	spin_lock_init(&sta->lock);
+	spin_lock_init(&sta->ps_lock);
 	INIT_WORK(&sta->drv_unblock_wk, sta_unblock);
 	INIT_WORK(&sta->ampdu_mlme.work, ieee80211_ba_session_work);
 	mutex_init(&sta->ampdu_mlme.mtx);
@@ -1109,6 +1110,8 @@
 
 	skb_queue_head_init(&pending);
 
+	/* sync with ieee80211_tx_h_unicast_ps_buf */
+	spin_lock(&sta->ps_lock);
 	/* Send all buffered frames to the station */
 	for (ac = 0; ac < IEEE80211_NUM_ACS; ac++) {
 		int count = skb_queue_len(&pending), tmp;
@@ -1128,6 +1131,7 @@
 	}
 
 	ieee80211_add_pending_skbs_fn(local, &pending, clear_sta_ps_flags, sta);
+	spin_unlock(&sta->ps_lock);
 
 	/* This station just woke up and isn't aware of our SMPS state */
 	if (!ieee80211_smps_is_restrictive(sta->known_smps_mode,
```
