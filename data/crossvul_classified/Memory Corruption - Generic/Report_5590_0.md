# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 5590_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5590_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 195-236 of the vulnerable file.

			sizeof(struct icmsg_hdr)];
	kvp_data = &kvp_msg->kvp_data;
	key_name = key;

	/*
	 * If the error parameter is set, terminate the host's enumeration.
	 */
	if (error) {
		/*
		 * We don't support this index or the we have timedout;
		 * terminate the host-side iteration by returning an error.
		 */
		icmsghdrp->status = HV_E_FAIL;
		goto response_done;
	}

	/*
	 * The windows host expects the key/value pair to be encoded
	 * in utf16.
	 */
	keylen = utf8s_to_utf16s(key_name, strlen(key_name),
				(wchar_t *)kvp_data->data.key);
	kvp_data->data.key_size = 2*(keylen + 1); /* utf16 encoding */
	valuelen = utf8s_to_utf16s(value, strlen(value),
				(wchar_t *)kvp_data->data.value);
	kvp_data->data.value_size = 2*(valuelen + 1); /* utf16 encoding */

	kvp_data->data.value_type = REG_SZ; /* all our values are strings */
	icmsghdrp->status = HV_S_OK;

response_done:
	icmsghdrp->icflags = ICMSGHDRFLAG_TRANSACTION | ICMSGHDRFLAG_RESPONSE;

	vmbus_sendpacket(channel, recv_buffer, buf_len, req_id,
				VM_PKT_DATA_INBAND, 0);

}

/*
 * This callback is invoked when we get a KVP message from the host.
 * The host ensures that only one KVP transaction can be active at a time.
 * KVP implementation in Linux needs to forward the key to a user-mde
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -212,11 +212,13 @@
 	 * The windows host expects the key/value pair to be encoded
 	 * in utf16.
 	 */
-	keylen = utf8s_to_utf16s(key_name, strlen(key_name),
-				(wchar_t *)kvp_data->data.key);
+	keylen = utf8s_to_utf16s(key_name, strlen(key_name), UTF16_HOST_ENDIAN,
+				(wchar_t *) kvp_data->data.key,
+				HV_KVP_EXCHANGE_MAX_KEY_SIZE / 2);
 	kvp_data->data.key_size = 2*(keylen + 1); /* utf16 encoding */
-	valuelen = utf8s_to_utf16s(value, strlen(value),
-				(wchar_t *)kvp_data->data.value);
+	valuelen = utf8s_to_utf16s(value, strlen(value), UTF16_HOST_ENDIAN,
+				(wchar_t *) kvp_data->data.value,
+				HV_KVP_EXCHANGE_MAX_VALUE_SIZE / 2);
 	kvp_data->data.value_size = 2*(valuelen + 1); /* utf16 encoding */
 
 	kvp_data->data.value_type = REG_SZ; /* all our values are strings */
```
