# CrossVul Fix Pair: Off-by-one Error in c
**Pair ID:** 3860_1
**Vulnerability Class:** Off-by-one Error
**CWE:** CWE-193
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3860_1`)

## Vulnerability Information & PoC

## Description
Off-by-one Error - A product calculates or uses an incorrect maximum or minimum value that is 1 more, or 1 less, than the correct value.

## Vulnerable Code
```c
Lines 154-194 of the vulnerable file.


/**
 * @brief eval_msg_unsuback	Evaluate the given mqtt_test against the
 *				unsuback routines.
 * @param [in] mqtt_test	MQTT test structure
 * @return			TC_PASS on success
 * @return			TC_FAIL on error
 */
static int eval_msg_unsuback(struct mqtt_test *mqtt_test);

/**
 * @brief eval_msg_disconnect	Evaluate the given mqtt_test against the
 *				disconnect routines.
 * @param [in] mqtt_test	MQTT test structure
 * @return			TC_PASS on success
 * @return			TC_FAIL on error
 */
static int eval_msg_disconnect(struct mqtt_test *mqtt_test);

/**
 * @brief eval_buffers		Evaluate if two given buffers are equal
 * @param [in] buf		Input buffer 1, mostly used as the 'computed'
 *				buffer
 * @param [in] expected		Expected buffer
 * @param [in] len		'expected' len
 * @return			TC_PASS on success
 * @return			TC_FAIL on error and prints both buffers
 */
static int eval_buffers(const struct buf_ctx *buf,
			const u8_t *expected, u16_t len);

/**
 * @brief print_array		Prints the array 'a' of 'size' elements
 * @param a			The array
 * @param size			Array's size
 */
static void print_array(const u8_t *a, u16_t size);

/*
 * MQTT CONNECT msg:
 * Clean session: 1	Client id: [6] 'zephyr'	Will flag: 0
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -171,6 +171,24 @@
 static int eval_msg_disconnect(struct mqtt_test *mqtt_test);
 
 /**
+ * @brief eval_max_pkt_len	Evaluate header with maximum allowed packet
+ *				length.
+ * @param [in] mqtt_test	MQTT test structure
+ * @return			TC_PASS on success
+ * @return			TC_FAIL on error
+ */
+static int eval_max_pkt_len(struct mqtt_test *mqtt_test);
+
+/**
+ * @brief eval_corrupted_pkt_len Evaluate header exceeding maximum
+ *				 allowed packet length.
+ * @param [in] mqtt_test	 MQTT test structure
+ * @return			 TC_PASS on success
+ * @return			 TC_FAIL on error
+ */
+static int eval_corrupted_pkt_len(struct mqtt_test *mqtt_test);
+
+/**
  * @brief eval_buffers		Evaluate if two given buffers are equal
  * @param [in] buf		Input buffer 1, mostly used as the 'computed'
  *				buffer
@@ -181,6 +199,7 @@
  */
 static int eval_buffers(const struct buf_ctx *buf,
 			const u8_t *expected, u16_t len);
+
 
 /**
  * @brief print_array		Prints the array 'a' of 'size' elements
@@ -514,6 +533,19 @@
 static ZTEST_DMEM struct mqtt_unsuback_param msg_unsuback1 = {.message_id = 1};
 
 static ZTEST_DMEM
+u8_t max_pkt_len[] = {0x30, 0xff, 0xff, 0xff, 0x7f};
+static ZTEST_DMEM struct buf_ctx max_pkt_len_buf = {
+	.cur = max_pkt_len, .end = max_pkt_len + sizeof(max_pkt_len)
+};
+
+static ZTEST_DMEM
+u8_t corrupted_pkt_len[] = {0x30, 0xff, 0xff, 0xff, 0xff, 0x01};
+static ZTEST_DMEM struct buf_ctx corrupted_pkt_len_buf = {
+	.cur = corrupted_pkt_len,
+	.end = corrupted_pkt_len + sizeof(corrupted_pkt_len)
+};
+
+static ZTEST_DMEM
 struct mqtt_test mqtt_tests[] = {
 
 	{.test_name = "CONNECT, new session, zeros",
@@ -607,6 +639,12 @@
 	{.test_name = "UNSUBACK",
 	 .ctx = &msg_unsuback1, .eval_fcn = eval_msg_unsuback,
 	 .expected = unsuback1, .expected_len = sizeof(unsuback1)},
+
+	{.test_name = "Maximum packet length",
+	 .ctx = &max_pkt_len_buf, .eval_fcn = eval_max_pkt_len},
+
+	{.test_name = "Corrupted packet length",
+	 .ctx = &corrupted_pkt_len_buf, .eval_fcn = eval_corrupted_pkt_len},
 
 	/* last test case, do not remove it */
 	{.test_name = NULL}
@@ -1018,6 +1056,36 @@
 	return TC_PASS;
 }
 
+static int eval_max_pkt_len(struct mqtt_test *mqtt_test)
+{
+	struct buf_ctx *buf = (struct buf_ctx *)mqtt_test->ctx;
+	int rc;
+	u8_t flags;
+	u32_t length;
+
+	rc = fixed_header_decode(buf, &flags, &length);
+
+	zassert_equal(rc, 0, "fixed_header_decode failed");
+	zassert_equal(length, MQTT_MAX_PAYLOAD_SIZE,
+		      "Invalid packet length decoded");
+
+	return TC_PASS;
+}
+
+static int eval_corrupted_pkt_len(struct mqtt_test *mqtt_test)
+{
+	struct buf_ctx *buf = (struct buf_ctx *)mqtt_test->ctx;
+	int rc;
+	u8_t flags;
+	u32_t length;
+
+	rc = fixed_header_decode(buf, &flags, &length);
+
+	zassert_equal(rc, -EINVAL, "fixed_header_decode should fail");
+
+	return TC_PASS;
+}
+
 void test_mqtt_packet(void)
 {
 	TC_START("MQTT Library test");
```
