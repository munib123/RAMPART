# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 2117_1
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2117_1`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 1267-1315 of the vulnerable file.

	event->param.conn.retry_count = req_data->retry_count;
	event->param.conn.rnr_retry_count = req_data->rnr_retry_count;
	event->param.conn.srq = req_data->srq;
	event->param.conn.qp_num = req_data->remote_qpn;
}

static int cma_check_req_qp_type(struct rdma_cm_id *id, struct ib_cm_event *ib_event)
{
	return (((ib_event->event == IB_CM_REQ_RECEIVED) &&
		 (ib_event->param.req_rcvd.qp_type == id->qp_type)) ||
		((ib_event->event == IB_CM_SIDR_REQ_RECEIVED) &&
		 (id->qp_type == IB_QPT_UD)) ||
		(!id->qp_type));
}

static int cma_req_handler(struct ib_cm_id *cm_id, struct ib_cm_event *ib_event)
{
	struct rdma_id_private *listen_id, *conn_id;
	struct rdma_cm_event event;
	int offset, ret;
	u8 smac[ETH_ALEN];
	u8 alt_smac[ETH_ALEN];
	u8 *psmac = smac;
	u8 *palt_smac = alt_smac;
	int is_iboe = ((rdma_node_get_transport(cm_id->device->node_type) ==
			RDMA_TRANSPORT_IB) &&
		       (rdma_port_get_link_layer(cm_id->device,
			ib_event->param.req_rcvd.port) ==
			IB_LINK_LAYER_ETHERNET));

	listen_id = cm_id->context;
	if (!cma_check_req_qp_type(&listen_id->id, ib_event))
		return -EINVAL;

	if (cma_disable_callback(listen_id, RDMA_CM_LISTEN))
		return -ECONNABORTED;

	memset(&event, 0, sizeof event);
	offset = cma_user_data_offset(listen_id);
	event.event = RDMA_CM_EVENT_CONNECT_REQUEST;
	if (ib_event->event == IB_CM_SIDR_REQ_RECEIVED) {
		conn_id = cma_new_udp_id(&listen_id->id, ib_event);
		event.param.ud.private_data = ib_event->private_data + offset;
		event.param.ud.private_data_len =
				IB_CM_SIDR_REQ_PRIVATE_DATA_SIZE - offset;
	} else {
		conn_id = cma_new_conn_id(&listen_id->id, ib_event);
		cma_set_req_event_data(&event, &ib_event->param.req_rcvd,
				       ib_event->private_data, offset);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1284,15 +1284,6 @@
 	struct rdma_id_private *listen_id, *conn_id;
 	struct rdma_cm_event event;
 	int offset, ret;
-	u8 smac[ETH_ALEN];
-	u8 alt_smac[ETH_ALEN];
-	u8 *psmac = smac;
-	u8 *palt_smac = alt_smac;
-	int is_iboe = ((rdma_node_get_transport(cm_id->device->node_type) ==
-			RDMA_TRANSPORT_IB) &&
-		       (rdma_port_get_link_layer(cm_id->device,
-			ib_event->param.req_rcvd.port) ==
-			IB_LINK_LAYER_ETHERNET));
 
 	listen_id = cm_id->context;
 	if (!cma_check_req_qp_type(&listen_id->id, ib_event))
@@ -1336,28 +1327,11 @@
 	ret = conn_id->id.event_handler(&conn_id->id, &event);
 	if (ret)
 		goto err3;
-
-	if (is_iboe) {
-		if (ib_event->param.req_rcvd.primary_path != NULL)
-			rdma_addr_find_smac_by_sgid(
-				&ib_event->param.req_rcvd.primary_path->sgid,
-				psmac, NULL);
-		else
-			psmac = NULL;
-		if (ib_event->param.req_rcvd.alternate_path != NULL)
-			rdma_addr_find_smac_by_sgid(
-				&ib_event->param.req_rcvd.alternate_path->sgid,
-				palt_smac, NULL);
-		else
-			palt_smac = NULL;
-	}
 	/*
 	 * Acquire mutex to prevent user executing rdma_destroy_id()
 	 * while we're accessing the cm_id.
 	 */
 	mutex_lock(&lock);
-	if (is_iboe)
-		ib_update_cm_av(cm_id, psmac, palt_smac);
 	if (cma_comp(conn_id, RDMA_CM_CONNECT) &&
 	    (conn_id->id.qp_type != IB_QPT_UD))
 		ib_send_cm_mra(cm_id, CMA_CM_MRA_SETTING, NULL, 0);
```
