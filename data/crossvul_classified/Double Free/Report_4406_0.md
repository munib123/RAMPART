# CrossVul Fix Pair: Double Free in c
**Pair ID:** 4406_0
**Vulnerability Class:** Double Free
**CWE:** CWE-415
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4406_0`)

## Vulnerability Information & PoC

## Description
Double Free - When a program calls free() twice with the same argument, the program's memory management data structures become corrupted.

## Vulnerable Code
```c
Lines 67-107 of the vulnerable file.

	uint8_t *buf;
	uint16_t mtu;
};

struct bt_att {
	int ref_count;
	bool close_on_unref;
	struct queue *chans;
	uint8_t enc_size;
	uint16_t mtu;			/* Biggest possible MTU */

	struct queue *notify_list;	/* List of registered callbacks */
	struct queue *disconn_list;	/* List of disconnect handlers */

	unsigned int next_send_id;	/* IDs for "send" ops */
	unsigned int next_reg_id;	/* IDs for registered callbacks */

	struct queue *req_queue;	/* Queued ATT protocol requests */
	struct queue *ind_queue;	/* Queued ATT protocol indications */
	struct queue *write_queue;	/* Queue of PDUs ready to send */

	bt_att_timeout_func_t timeout_callback;
	bt_att_destroy_func_t timeout_destroy;
	void *timeout_data;

	bt_att_debug_func_t debug_callback;
	bt_att_destroy_func_t debug_destroy;
	void *debug_data;

	struct bt_crypto *crypto;

	struct sign_info *local_sign;
	struct sign_info *remote_sign;
};

struct sign_info {
	uint8_t key[16];
	bt_att_counter_func_t counter;
	void *user_data;
};

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -84,6 +84,7 @@
 	struct queue *req_queue;	/* Queued ATT protocol requests */
 	struct queue *ind_queue;	/* Queued ATT protocol indications */
 	struct queue *write_queue;	/* Queue of PDUs ready to send */
+	bool in_disc;			/* Cleanup queues on disconnect_cb */
 
 	bt_att_timeout_func_t timeout_callback;
 	bt_att_destroy_func_t timeout_destroy;
@@ -222,8 +223,10 @@
 	free(op);
 }
 
-static void cancel_att_send_op(struct att_send_op *op)
-{
+static void cancel_att_send_op(void *data)
+{
+	struct att_send_op *op = data;
+
 	if (op->destroy)
 		op->destroy(op->user_data);
 
@@ -631,28 +634,32 @@
 	/* Dettach channel */
 	queue_remove(att->chans, chan);
 
+	if (chan->pending_req) {
+		disc_att_send_op(chan->pending_req);
+		chan->pending_req = NULL;
+	}
+
+	if (chan->pending_ind) {
+		disc_att_send_op(chan->pending_ind);
+		chan->pending_ind = NULL;
+	}
+
+	bt_att_chan_free(chan);
+
+	/* Don't run disconnect callback if there are channels left */
+	if (!queue_isempty(att->chans))
+		return false;
+
+	bt_att_ref(att);
+
+	att->in_disc = true;
+
 	/* Notify request callbacks */
 	queue_remove_all(att->req_queue, NULL, NULL, disc_att_send_op);
 	queue_remove_all(att->ind_queue, NULL, NULL, disc_att_send_op);
 	queue_remove_all(att->write_queue, NULL, NULL, disc_att_send_op);
 
-	if (chan->pending_req) {
-		disc_att_send_op(chan->pending_req);
-		chan->pending_req = NULL;
-	}
-
-	if (chan->pending_ind) {
-		disc_att_send_op(chan->pending_ind);
-		chan->pending_ind = NULL;
-	}
-
-	bt_att_chan_free(chan);
-
-	/* Don't run disconnect callback if there are channels left */
-	if (!queue_isempty(att->chans))
-		return false;
-
-	bt_att_ref(att);
+	att->in_disc = false;
 
 	queue_foreach(att->disconn_list, disconn_handler, INT_TO_PTR(err));
 
@@ -1574,6 +1581,30 @@
 	return true;
 }
 
+static bool bt_att_disc_cancel(struct bt_att *att, unsigned int id)
+{
+	struct att_send_op *op;
+
+	op = queue_find(att->req_queue, match_op_id, UINT_TO_PTR(id));
+	if (op)
+		goto done;
+
+	op = queue_find(att->ind_queue, match_op_id, UINT_TO_PTR(id));
+	if (op)
+		goto done;
+
+	op = queue_find(att->write_queue, match_op_id, UINT_TO_PTR(id));
+
+done:
+	if (!op)
+		return false;
+
+	/* Just cancel since disconnect_cb will be cleaning up */
+	cancel_att_send_op(op);
+
+	return true;
+}
+
 bool bt_att_cancel(struct bt_att *att, unsigned int id)
 {
 	const struct queue_entry *entry;
@@ -1590,6 +1621,9 @@
 		if (bt_att_chan_cancel(chan, id))
 			return true;
 	}
+
+	if (att->in_disc)
+		return bt_att_disc_cancel(att, id);
 
 	op = queue_remove_if(att->req_queue, match_op_id, UINT_TO_PTR(id));
 	if (op)
```
