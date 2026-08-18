# CrossVul Fix Pair: NULL Pointer Dereference in c
**Pair ID:** 887_0
**Vulnerability Class:** NULL Pointer Dereference
**CWE:** CWE-476
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `887_0`)

## Vulnerability Information & PoC

## Description
NULL Pointer Dereference - NULL pointer dereference issues can occur through a number of flaws, including race conditions, and simple programming omissions.

## Vulnerable Code
```c
Lines 402-442 of the vulnerable file.

	struct nfc_llcp_local *local;
	struct sk_buff *skb;
	u8 *service_name_tlv = NULL, service_name_tlv_length;
	u8 *miux_tlv = NULL, miux_tlv_length;
	u8 *rw_tlv = NULL, rw_tlv_length, rw;
	int err;
	u16 size = 0;
	__be16 miux;

	pr_debug("Sending CONNECT\n");

	local = sock->local;
	if (local == NULL)
		return -ENODEV;

	if (sock->service_name != NULL) {
		service_name_tlv = nfc_llcp_build_tlv(LLCP_TLV_SN,
						      sock->service_name,
						      sock->service_name_len,
						      &service_name_tlv_length);
		size += service_name_tlv_length;
	}

	/* If the socket parameters are not set, use the local ones */
	miux = be16_to_cpu(sock->miux) > LLCP_MAX_MIUX ?
		local->miux : sock->miux;
	rw = sock->rw > LLCP_MAX_RW ? local->rw : sock->rw;

	miux_tlv = nfc_llcp_build_tlv(LLCP_TLV_MIUX, (u8 *)&miux, 0,
				      &miux_tlv_length);
	size += miux_tlv_length;

	rw_tlv = nfc_llcp_build_tlv(LLCP_TLV_RW, &rw, 0, &rw_tlv_length);
	size += rw_tlv_length;

	pr_debug("SKB size %d SN length %zu\n", size, sock->service_name_len);

	skb = llcp_allocate_pdu(sock, LLCP_PDU_CONNECT, size);
	if (skb == NULL) {
		err = -ENOMEM;
		goto error_tlv;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -419,6 +419,10 @@
 						      sock->service_name,
 						      sock->service_name_len,
 						      &service_name_tlv_length);
+		if (!service_name_tlv) {
+			err = -ENOMEM;
+			goto error_tlv;
+		}
 		size += service_name_tlv_length;
 	}
 
@@ -429,9 +433,17 @@
 
 	miux_tlv = nfc_llcp_build_tlv(LLCP_TLV_MIUX, (u8 *)&miux, 0,
 				      &miux_tlv_length);
+	if (!miux_tlv) {
+		err = -ENOMEM;
+		goto error_tlv;
+	}
 	size += miux_tlv_length;
 
 	rw_tlv = nfc_llcp_build_tlv(LLCP_TLV_RW, &rw, 0, &rw_tlv_length);
+	if (!rw_tlv) {
+		err = -ENOMEM;
+		goto error_tlv;
+	}
 	size += rw_tlv_length;
 
 	pr_debug("SKB size %d SN length %zu\n", size, sock->service_name_len);
@@ -484,9 +496,17 @@
 
 	miux_tlv = nfc_llcp_build_tlv(LLCP_TLV_MIUX, (u8 *)&miux, 0,
 				      &miux_tlv_length);
+	if (!miux_tlv) {
+		err = -ENOMEM;
+		goto error_tlv;
+	}
 	size += miux_tlv_length;
 
 	rw_tlv = nfc_llcp_build_tlv(LLCP_TLV_RW, &rw, 0, &rw_tlv_length);
+	if (!rw_tlv) {
+		err = -ENOMEM;
+		goto error_tlv;
+	}
 	size += rw_tlv_length;
 
 	skb = llcp_allocate_pdu(sock, LLCP_PDU_CC, size);
```
