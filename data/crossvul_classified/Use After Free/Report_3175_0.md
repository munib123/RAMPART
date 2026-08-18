# CrossVul Fix Pair: Use After Free in c
**Pair ID:** 3175_0
**Vulnerability Class:** Use After Free
**CWE:** CWE-416
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3175_0`)

## Vulnerability Information & PoC

## Description
Use After Free - The use of previously-freed memory can have any number of adverse consequences, ranging from the corruption of valid data to the execution of arbitrary code, depending on the instantiation and timi...

## Vulnerable Code
```c
Lines 1602-1642 of the vulnerable file.

	case PACKET_FANOUT_CBPF:
		return fanout_set_data_cbpf(po, data, len);
	case PACKET_FANOUT_EBPF:
		return fanout_set_data_ebpf(po, data, len);
	default:
		return -EINVAL;
	};
}

static void fanout_release_data(struct packet_fanout *f)
{
	switch (f->type) {
	case PACKET_FANOUT_CBPF:
	case PACKET_FANOUT_EBPF:
		__fanout_set_data_bpf(f, NULL);
	};
}

static int fanout_add(struct sock *sk, u16 id, u16 type_flags)
{
	struct packet_sock *po = pkt_sk(sk);
	struct packet_fanout *f, *match;
	u8 type = type_flags & 0xff;
	u8 flags = type_flags >> 8;
	int err;

	switch (type) {
	case PACKET_FANOUT_ROLLOVER:
		if (type_flags & PACKET_FANOUT_FLAG_ROLLOVER)
			return -EINVAL;
	case PACKET_FANOUT_HASH:
	case PACKET_FANOUT_LB:
	case PACKET_FANOUT_CPU:
	case PACKET_FANOUT_RND:
	case PACKET_FANOUT_QM:
	case PACKET_FANOUT_CBPF:
	case PACKET_FANOUT_EBPF:
		break;
	default:
		return -EINVAL;
	}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1619,6 +1619,7 @@
 
 static int fanout_add(struct sock *sk, u16 id, u16 type_flags)
 {
+	struct packet_rollover *rollover = NULL;
 	struct packet_sock *po = pkt_sk(sk);
 	struct packet_fanout *f, *match;
 	u8 type = type_flags & 0xff;
@@ -1641,23 +1642,28 @@
 		return -EINVAL;
 	}
 
+	mutex_lock(&fanout_mutex);
+
+	err = -EINVAL;
 	if (!po->running)
-		return -EINVAL;
-
+		goto out;
+
+	err = -EALREADY;
 	if (po->fanout)
-		return -EALREADY;
+		goto out;
 
 	if (type == PACKET_FANOUT_ROLLOVER ||
 	    (type_flags & PACKET_FANOUT_FLAG_ROLLOVER)) {
-		po->rollover = kzalloc(sizeof(*po->rollover), GFP_KERNEL);
-		if (!po->rollover)
-			return -ENOMEM;
-		atomic_long_set(&po->rollover->num, 0);
-		atomic_long_set(&po->rollover->num_huge, 0);
-		atomic_long_set(&po->rollover->num_failed, 0);
-	}
-
-	mutex_lock(&fanout_mutex);
+		err = -ENOMEM;
+		rollover = kzalloc(sizeof(*rollover), GFP_KERNEL);
+		if (!rollover)
+			goto out;
+		atomic_long_set(&rollover->num, 0);
+		atomic_long_set(&rollover->num_huge, 0);
+		atomic_long_set(&rollover->num_failed, 0);
+		po->rollover = rollover;
+	}
+
 	match = NULL;
 	list_for_each_entry(f, &fanout_list, list) {
 		if (f->id == id &&
@@ -1704,11 +1710,11 @@
 		}
 	}
 out:
+	if (err && rollover) {
+		kfree(rollover);
+		po->rollover = NULL;
+	}
 	mutex_unlock(&fanout_mutex);
-	if (err) {
-		kfree(po->rollover);
-		po->rollover = NULL;
-	}
 	return err;
 }
 
@@ -1717,23 +1723,22 @@
 	struct packet_sock *po = pkt_sk(sk);
 	struct packet_fanout *f;
 
+	mutex_lock(&fanout_mutex);
 	f = po->fanout;
-	if (!f)
-		return;
-
-	mutex_lock(&fanout_mutex);
-	po->fanout = NULL;
-
-	if (atomic_dec_and_test(&f->sk_ref)) {
-		list_del(&f->list);
-		dev_remove_pack(&f->prot_hook);
-		fanout_release_data(f);
-		kfree(f);
+	if (f) {
+		po->fanout = NULL;
+
+		if (atomic_dec_and_test(&f->sk_ref)) {
+			list_del(&f->list);
+			dev_remove_pack(&f->prot_hook);
+			fanout_release_data(f);
+			kfree(f);
+		}
+
+		if (po->rollover)
+			kfree_rcu(po->rollover, rcu);
 	}
 	mutex_unlock(&fanout_mutex);
-
-	if (po->rollover)
-		kfree_rcu(po->rollover, rcu);
 }
 
 static bool packet_extra_vlan_len_allowed(const struct net_device *dev,
```
