# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 3540_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3540_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 119-160 of the vulnerable file.

		return -EINVAL;

	if (!access_ok(VERIFY_WRITE, buf, count))
		return -EFAULT;

	error = wait_event_interruptible(socket_client->queue_wait,
					 socket_client->queue_len);

	if (error)
		return error;

	spin_lock_bh(&socket_client->lock);

	socket_packet = list_first_entry(&socket_client->queue_list,
					 struct socket_packet, list);
	list_del(&socket_packet->list);
	socket_client->queue_len--;

	spin_unlock_bh(&socket_client->lock);

	error = copy_to_user(buf, &socket_packet->icmp_packet,
			     socket_packet->icmp_len);

	packet_len = socket_packet->icmp_len;
	kfree(socket_packet);

	if (error)
		return -EFAULT;

	return packet_len;
}

static ssize_t bat_socket_write(struct file *file, const char __user *buff,
				size_t len, loff_t *off)
{
	struct socket_client *socket_client = file->private_data;
	struct bat_priv *bat_priv = socket_client->bat_priv;
	struct hard_iface *primary_if = NULL;
	struct sk_buff *skb;
	struct icmp_packet_rr *icmp_packet;

	struct orig_node *orig_node = NULL;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -136,10 +136,9 @@
 
 	spin_unlock_bh(&socket_client->lock);
 
-	error = copy_to_user(buf, &socket_packet->icmp_packet,
-			     socket_packet->icmp_len);
-
-	packet_len = socket_packet->icmp_len;
+	packet_len = min(count, socket_packet->icmp_len);
+	error = copy_to_user(buf, &socket_packet->icmp_packet, packet_len);
+
 	kfree(socket_packet);
 
 	if (error)
```
