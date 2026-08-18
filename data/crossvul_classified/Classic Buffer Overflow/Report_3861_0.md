# CrossVul Fix Pair: Buffer Copy without Checking Size of Input ('Classic Buffer Overflow') in c
**Pair ID:** 3861_0
**Vulnerability Class:** Classic Buffer Overflow
**CWE:** CWE-120
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3861_0`)

## Vulnerability Information & PoC

## Description
Buffer Copy without Checking Size of Input ('Classic Buffer Overflow') - A buffer overflow condition exists when a product attempts to put more data in a buffer than it can hold, or when it attempts to put data in a memory area outside of the boundaries of a buffer.

## Vulnerable Code
```c
Lines 129-169 of the vulnerable file.


		evt.type = MQTT_EVT_PINGRESP;
		break;

	default:
		/* Nothing to notify. */
		notify_event = false;
		break;
	}

	if (notify_event == true) {
		event_notify(client, &evt);
	}

	return err_code;
}

static int mqtt_read_message_chunk(struct mqtt_client *client,
				   struct buf_ctx *buf, u32_t length)
{
	int remaining;
	int len;

	/* Calculate how much data we need to read from the transport,
	 * given the already buffered data.
	 */
	remaining = length - (buf->end - buf->cur);
	if (remaining <= 0) {
		return 0;
	}

	/* Check if read does not exceed the buffer. */
	if (buf->end + remaining > client->rx_buf + client->rx_buf_size) {
		MQTT_ERR("[CID %p]: Buffer too small to receive the message",
			 client);
		return -ENOMEM;
	}

	len = mqtt_transport_read(client, buf->end, remaining, false);
	if (len < 0) {
		MQTT_TRC("[CID %p]: Transport read error: %d", client, len);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -146,20 +146,23 @@
 static int mqtt_read_message_chunk(struct mqtt_client *client,
 				   struct buf_ctx *buf, u32_t length)
 {
-	int remaining;
+	u32_t remaining;
 	int len;
+
+	/* In case all data requested has already been buffered, return. */
+	if (length <= (buf->end - buf->cur)) {
+		return 0;
+	}
 
 	/* Calculate how much data we need to read from the transport,
 	 * given the already buffered data.
 	 */
 	remaining = length - (buf->end - buf->cur);
-	if (remaining <= 0) {
-		return 0;
-	}
 
 	/* Check if read does not exceed the buffer. */
-	if (buf->end + remaining > client->rx_buf + client->rx_buf_size) {
-		MQTT_ERR("[CID %p]: Buffer too small to receive the message",
+	if ((buf->end + remaining > client->rx_buf + client->rx_buf_size) ||
+	    (buf->end + remaining < client->rx_buf)) {
+		MQTT_ERR("[CID %p]: Read would exceed RX buffer bounds.",
 			 client);
 		return -ENOMEM;
 	}
```
