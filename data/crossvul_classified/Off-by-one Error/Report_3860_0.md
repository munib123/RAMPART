# CrossVul Fix Pair: Off-by-one Error in c
**Pair ID:** 3860_0
**Vulnerability Class:** Off-by-one Error
**CWE:** CWE-193
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3860_0`)

## Vulnerability Information & PoC

## Description
Off-by-one Error - A product calculates or uses an incorrect maximum or minimum value that is 1 more, or 1 less, than the correct value.

## Vulnerable Code
```c
Lines 141-181 of the vulnerable file.

	} else {
		str->data = NULL;
	}

	MQTT_TRC("<< bin len:%08x", GET_BINSTR_BUFFER_SIZE(str));

	return 0;
}

/**@brief Decode MQTT Packet Length in the MQTT fixed header.
 *
 * @param[inout] buf A pointer to the buf_ctx structure containing current
 *                   buffer position.
 * @param[out] length Length of variable header and payload in the
 *                              MQTT message.
 *
 * @retval 0 if the procedure is successful.
 * @retval -EINVAL if the length decoding would use more that 4 bytes.
 * @retval -EAGAIN if the buffer would be exceeded during the read.
 */
int packet_length_decode(struct buf_ctx *buf, u32_t *length)
{
	u8_t shift = 0U;
	u8_t bytes = 0U;

	*length = 0U;
	do {
		if (bytes > MQTT_MAX_LENGTH_BYTES) {
			return -EINVAL;
		}

		if (buf->cur >= buf->end) {
			return -EAGAIN;
		}

		*length += ((u32_t)*(buf->cur) & MQTT_LENGTH_VALUE_MASK)
								<< shift;
		shift += MQTT_LENGTH_SHIFT;
		bytes++;
	} while ((*(buf->cur++) & MQTT_LENGTH_CONTINUATION_BIT) != 0U);

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -158,14 +158,14 @@
  * @retval -EINVAL if the length decoding would use more that 4 bytes.
  * @retval -EAGAIN if the buffer would be exceeded during the read.
  */
-int packet_length_decode(struct buf_ctx *buf, u32_t *length)
+static int packet_length_decode(struct buf_ctx *buf, u32_t *length)
 {
 	u8_t shift = 0U;
 	u8_t bytes = 0U;
 
 	*length = 0U;
 	do {
-		if (bytes > MQTT_MAX_LENGTH_BYTES) {
+		if (bytes >= MQTT_MAX_LENGTH_BYTES) {
 			return -EINVAL;
 		}
 
@@ -179,6 +179,10 @@
 		bytes++;
 	} while ((*(buf->cur++) & MQTT_LENGTH_CONTINUATION_BIT) != 0U);
 
+	if (*length > MQTT_MAX_PAYLOAD_SIZE) {
+		return -EINVAL;
+	}
+
 	MQTT_TRC("length:0x%08x", *length);
 
 	return 0;
```
