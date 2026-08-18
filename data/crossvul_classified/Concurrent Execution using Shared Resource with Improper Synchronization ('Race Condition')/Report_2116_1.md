# CrossVul Fix Pair: Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') in c
**Pair ID:** 2116_1
**Vulnerability Class:** Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')
**CWE:** CWE-362
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2116_1`)

## Vulnerability Information & PoC

## Description
Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') - This can have security implications when the expected synchronization is in security-critical code, such as recording whether a user is authenticated or modifying important state information that s...

## Vulnerable Code
```c
Lines 250-290 of the vulnerable file.

 * @free_list: list entry for keeping track of stations to free
 * @hnext: hash table linked list pointer
 * @local: pointer to the global information
 * @sdata: virtual interface this station belongs to
 * @ptk: peer keys negotiated with this station, if any
 * @ptk_idx: last installed peer key index
 * @gtk: group keys negotiated with this station, if any
 * @gtk_idx: last installed group key index
 * @rate_ctrl: rate control algorithm reference
 * @rate_ctrl_priv: rate control private per-STA pointer
 * @last_tx_rate: rate used for last transmit, to report to userspace as
 *	"the" transmit rate
 * @last_rx_rate_idx: rx status rate index of the last data packet
 * @last_rx_rate_flag: rx status flag of the last data packet
 * @last_rx_rate_vht_nss: rx status nss of last data packet
 * @lock: used for locking all fields that require locking, see comments
 *	in the header file.
 * @drv_unblock_wk: used for driver PS unblocking
 * @listen_interval: listen interval of this station, when we're acting as AP
 * @_flags: STA flags, see &enum ieee80211_sta_info_flags, do not use directly
 * @ps_tx_buf: buffers (per AC) of frames to transmit to this station
 *	when it leaves power saving state or polls
 * @tx_filtered: buffers (per AC) of frames we already tried to
 *	transmit but were filtered by hardware due to STA having
 *	entered power saving state, these are also delivered to
 *	the station when it leaves powersave or polls for frames
 * @driver_buffered_tids: bitmap of TIDs the driver has data buffered on
 * @rx_packets: Number of MSDUs received from this STA
 * @rx_bytes: Number of bytes received from this STA
 * @wep_weak_iv_count: number of weak WEP IVs received from this station
 * @last_rx: time (in jiffies) when last frame was received from this STA
 * @last_connected: time (in seconds) when a station got connected
 * @num_duplicates: number of duplicate frames received from this STA
 * @rx_fragments: number of received MPDUs
 * @rx_dropped: number of dropped MPDUs from this STA
 * @last_signal: signal of last received frame from this STA
 * @avg_signal: moving average of signal of received frames from this STA
 * @last_ack_signal: signal of last received Ack frame from this STA
 * @last_seq_ctrl: last received seq/frag number from this STA (per RX queue)
 * @tx_filtered_count: number of frames the hardware filtered for this STA
 * @tx_retry_failed: number of frames that failed retry
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -267,6 +267,7 @@
  * @drv_unblock_wk: used for driver PS unblocking
  * @listen_interval: listen interval of this station, when we're acting as AP
  * @_flags: STA flags, see &enum ieee80211_sta_info_flags, do not use directly
+ * @ps_lock: used for powersave (when mac80211 is the AP) related locking
  * @ps_tx_buf: buffers (per AC) of frames to transmit to this station
  *	when it leaves power saving state or polls
  * @tx_filtered: buffers (per AC) of frames we already tried to
@@ -356,10 +357,8 @@
 	/* use the accessors defined below */
 	unsigned long _flags;
 
-	/*
-	 * STA powersave frame queues, no more than the internal
-	 * locking required.
-	 */
+	/* STA powersave lock and frame queues */
+	spinlock_t ps_lock;
 	struct sk_buff_head ps_tx_buf[IEEE80211_NUM_ACS];
 	struct sk_buff_head tx_filtered[IEEE80211_NUM_ACS];
 	unsigned long driver_buffered_tids;
```
