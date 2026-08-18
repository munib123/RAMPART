# CrossVul Fix Pair: Buffer Copy without Checking Size of Input ('Classic Buffer Overflow') in c
**Pair ID:** 1769_0
**Vulnerability Class:** Classic Buffer Overflow
**CWE:** CWE-120
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1769_0`)

## Vulnerability Information & PoC

## Description
Buffer Copy without Checking Size of Input ('Classic Buffer Overflow') - A buffer overflow condition exists when a product attempts to put more data in a buffer than it can hold, or when it attempts to put data in a memory area outside of the boundaries of a buffer.

## Vulnerable Code
```c
Lines 709-749 of the vulnerable file.

				log_warn("lldp", "unable to allocate memory for string tlv "
				    "received on %s",
				    hardware->h_ifname);
				goto malformed;
			}
			PEEK_BYTES(b, tlv_size);
			if (tlv_type == LLDP_TLV_PORT_DESCR)
				port->p_descr = b;
			else if (tlv_type == LLDP_TLV_SYSTEM_NAME)
				chassis->c_name = b;
			else chassis->c_descr = b;
			break;
		case LLDP_TLV_SYSTEM_CAP:
			CHECK_TLV_SIZE(4, "System capabilities");
			chassis->c_cap_available = PEEK_UINT16;
			chassis->c_cap_enabled = PEEK_UINT16;
			break;
		case LLDP_TLV_MGMT_ADDR:
			CHECK_TLV_SIZE(1, "Management address");
			addr_str_length = PEEK_UINT8;
			CHECK_TLV_SIZE(1 + addr_str_length, "Management address");
			PEEK_BYTES(addr_str_buffer, addr_str_length);
			addr_length = addr_str_length - 1;
			addr_family = addr_str_buffer[0];
			addr_ptr = &addr_str_buffer[1];
			CHECK_TLV_SIZE(1 + addr_str_length + 5, "Management address");
			iface_subtype = PEEK_UINT8;
			iface_number = PEEK_UINT32;
			
			af = lldpd_af_from_lldp_proto(addr_family);
			if (af == LLDPD_AF_UNSPEC)
				break;
			if (iface_subtype == LLDP_MGMT_IFACE_IFINDEX)
				iface = iface_number;
			else
				iface = 0;
			mgmt = lldpd_alloc_mgmt(af, addr_ptr, addr_length, iface);
			if (mgmt == NULL) {
				assert(errno == ENOMEM);
				log_warn("lldp", "unable to allocate memory "
							"for management address");
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -726,6 +726,11 @@
 		case LLDP_TLV_MGMT_ADDR:
 			CHECK_TLV_SIZE(1, "Management address");
 			addr_str_length = PEEK_UINT8;
+			if (addr_str_length > sizeof(addr_str_buffer)) {
+				log_warnx("lldp", "too large management address on %s",
+				    hardware->h_ifname);
+				goto malformed;
+			}
 			CHECK_TLV_SIZE(1 + addr_str_length, "Management address");
 			PEEK_BYTES(addr_str_buffer, addr_str_length);
 			addr_length = addr_str_length - 1;
@@ -734,7 +739,7 @@
 			CHECK_TLV_SIZE(1 + addr_str_length + 5, "Management address");
 			iface_subtype = PEEK_UINT8;
 			iface_number = PEEK_UINT32;
-			
+
 			af = lldpd_af_from_lldp_proto(addr_family);
 			if (af == LLDPD_AF_UNSPEC)
 				break;
@@ -752,7 +757,7 @@
 			TAILQ_INSERT_TAIL(&chassis->c_mgmt, mgmt, m_entries);
 			break;
 		case LLDP_TLV_ORG:
-			CHECK_TLV_SIZE(4, "Organisational");
+			CHECK_TLV_SIZE(1 + (int)sizeof(orgid), "Organisational");
 			PEEK_BYTES(orgid, sizeof(orgid));
 			tlv_subtype = PEEK_UINT8;
 			if (memcmp(dot1, orgid, sizeof(orgid)) == 0) {
```
