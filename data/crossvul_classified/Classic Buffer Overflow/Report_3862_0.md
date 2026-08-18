# CrossVul Fix Pair: Buffer Copy without Checking Size of Input ('Classic Buffer Overflow') in c
**Pair ID:** 3862_0
**Vulnerability Class:** Classic Buffer Overflow
**CWE:** CWE-120
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3862_0`)

## Vulnerability Information & PoC

## Description
Buffer Copy without Checking Size of Input ('Classic Buffer Overflow') - A buffer overflow condition exists when a product attempts to put more data in a buffer than it can hold, or when it attempts to put data in a memory area outside of the boundaries of a buffer.

## Vulnerable Code
```c
Lines 239-279 of the vulnerable file.

	param->dup_flag = flags & MQTT_HEADER_DUP_MASK;
	param->retain_flag = flags & MQTT_HEADER_RETAIN_MASK;
	param->message.topic.qos = ((flags & MQTT_HEADER_QOS_MASK) >> 1);

	err_code = unpack_utf8_str(buf, &param->message.topic.topic);
	if (err_code != 0) {
		return err_code;
	}

	var_header_length = param->message.topic.topic.size + sizeof(u16_t);

	if (param->message.topic.qos > MQTT_QOS_0_AT_MOST_ONCE) {
		err_code = unpack_uint16(buf, &param->message_id);
		if (err_code != 0) {
			return err_code;
		}

		var_header_length += sizeof(u16_t);
	}

	param->message.payload.data = NULL;
	param->message.payload.len = var_length - var_header_length;

	return 0;
}

int publish_ack_decode(struct buf_ctx *buf, struct mqtt_puback_param *param)
{
	return unpack_uint16(buf, &param->message_id);
}

int publish_receive_decode(struct buf_ctx *buf, struct mqtt_pubrec_param *param)
{
	return unpack_uint16(buf, &param->message_id);
}

int publish_release_decode(struct buf_ctx *buf, struct mqtt_pubrel_param *param)
{
	return unpack_uint16(buf, &param->message_id);
}

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -256,6 +256,13 @@
 		var_header_length += sizeof(u16_t);
 	}
 
+	if (var_length < var_header_length) {
+		MQTT_ERR("Corrupted PUBLISH message, header length (%u) larger "
+			 "than total length (%u)", var_header_length,
+			 var_length);
+		return -EINVAL;
+	}
+
 	param->message.payload.data = NULL;
 	param->message.payload.len = var_length - var_header_length;
 
```
