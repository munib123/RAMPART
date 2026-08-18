# CrossVul Fix Pair: Buffer Copy without Checking Size of Input ('Classic Buffer Overflow') in c
**Pair ID:** 3862_1
**Vulnerability Class:** Classic Buffer Overflow
**CWE:** CWE-120
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3862_1`)

## Vulnerability Information & PoC

## Description
Buffer Copy without Checking Size of Input ('Classic Buffer Overflow') - A buffer overflow condition exists when a product attempts to put more data in a buffer than it can hold, or when it attempts to put data in a memory area outside of the boundaries of a buffer.

## Vulnerable Code
```c
Lines 71-111 of the vulnerable file.

	u16_t expected_len;
};

/**
 * @brief eval_msg_connect	Evaluate the given mqtt_test against the
 *				connect packing/unpacking routines.
 * @param [in] mqtt_test	MQTT test structure
 * @return			TC_PASS on success
 * @return			TC_FAIL on error
 */
static int eval_msg_connect(struct mqtt_test *mqtt_test);

/**
 * @brief eval_msg_publish	Evaluate the given mqtt_test against the
 *				publish packing/unpacking routines.
 * @param [in] mqtt_test	MQTT test structure
 * @return			TC_PASS on success
 * @return			TC_FAIL on error
 */
static int eval_msg_publish(struct mqtt_test *mqtt_test);

/**
 * @brief eval_msg_subscribe	Evaluate the given mqtt_test against the
 *				subscribe packing/unpacking routines.
 * @param [in] mqtt_test	MQTT test structure
 * @return			TC_PASS on success
 * @return			TC_FAIL on error
 */
static int eval_msg_subscribe(struct mqtt_test *mqtt_test);

/**
 * @brief eval_msg_suback	Evaluate the given mqtt_test against the
 *				suback packing/unpacking routines.
 * @param [in] mqtt_test	MQTT test structure
 * @return			TC_PASS on success
 * @return			TC_FAIL on error
 */
static int eval_msg_suback(struct mqtt_test *mqtt_test);

/**
 * @brief eval_msg_pingreq	Evaluate the given mqtt_test against the
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -88,6 +88,15 @@
  * @return			TC_FAIL on error
  */
 static int eval_msg_publish(struct mqtt_test *mqtt_test);
+
+/**
+ * @brief eval_msg_corrupted_publish Evaluate the given mqtt_test against the
+ *				     corrupted publish message.
+ * @param [in] mqtt_test	     MQTT test structure
+ * @return			     TC_PASS on success
+ * @return			     TC_FAIL on error
+ */
+static int eval_msg_corrupted_publish(struct mqtt_test *mqtt_test);
 
 /**
  * @brief eval_msg_subscribe	Evaluate the given mqtt_test against the
@@ -422,6 +431,14 @@
 	.message.payload.len = 2,
 };
 
+static ZTEST_DMEM
+u8_t publish_corrupted[] = {0x30, 0x07, 0x00, 0x07, 0x73, 0x65, 0x6e, 0x73,
+			    0x6f, 0x72, 0x73, 0x00, 0x01, 0x4f, 0x4b};
+static ZTEST_DMEM struct buf_ctx publish_corrupted_buf = {
+	.cur = publish_corrupted,
+	.end = publish_corrupted + sizeof(publish_corrupted)
+};
+
 /*
  * MQTT SUBSCRIBE msg:
  * pkt_id: 1, topic: sensors, qos: 0
@@ -591,6 +608,9 @@
 	{.test_name = "PUBLISH, qos = 2",
 	 .ctx = &msg_publish4, .eval_fcn = eval_msg_publish,
 	 .expected = publish4, .expected_len = sizeof(publish4)},
+
+	{.test_name = "PUBLISH, corrupted message length (smaller than topic)",
+	 .ctx = &publish_corrupted_buf, .eval_fcn = eval_msg_corrupted_publish},
 
 	{.test_name = "SUBSCRIBE, one topic, qos = 0",
 	 .ctx = &msg_subscribe1, .eval_fcn = eval_msg_subscribe,
@@ -799,6 +819,23 @@
 	return TC_PASS;
 }
 
+static int eval_msg_corrupted_publish(struct mqtt_test *mqtt_test)
+{
+	struct buf_ctx *buf = (struct buf_ctx *)mqtt_test->ctx;
+	int rc;
+	u8_t type_and_flags;
+	u32_t length;
+	struct mqtt_publish_param dec_param;
+
+	rc = fixed_header_decode(buf, &type_and_flags, &length);
+	zassert_equal(rc, 0, "fixed_header_decode failed");
+
+	rc = publish_decode(type_and_flags, length, buf, &dec_param);
+	zassert_equal(rc, -EINVAL, "publish_decode should fail");
+
+	return TC_PASS;
+}
+
 static int eval_msg_subscribe(struct mqtt_test *mqtt_test)
 {
 	struct mqtt_subscription_list *param =
```
