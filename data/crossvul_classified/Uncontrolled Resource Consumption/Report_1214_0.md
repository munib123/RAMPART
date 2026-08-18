# CrossVul Fix Pair: Uncontrolled Resource Consumption in c
**Pair ID:** 1214_0
**Vulnerability Class:** Uncontrolled Resource Consumption
**CWE:** CWE-400
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1214_0`)

## Vulnerability Information & PoC

## Description
Uncontrolled Resource Consumption - Limited resources include memory, file system storage, database connection pool entries, and CPU.

## Vulnerable Code
```c
Lines 1760-1800 of the vulnerable file.

		scatterwalk_map_and_copy(hmac_buf, sha->opad, 0, block_size, 0);
		switch (sha->type) {
		case CCP_SHA_TYPE_1:
		case CCP_SHA_TYPE_224:
		case CCP_SHA_TYPE_256:
			memcpy(hmac_buf + block_size,
			       ctx.address + ooffset,
			       digest_size);
			break;
		case CCP_SHA_TYPE_384:
		case CCP_SHA_TYPE_512:
			memcpy(hmac_buf + block_size,
			       ctx.address + LSB_ITEM_SIZE + ooffset,
			       LSB_ITEM_SIZE);
			memcpy(hmac_buf + block_size +
			       (LSB_ITEM_SIZE - ooffset),
			       ctx.address,
			       LSB_ITEM_SIZE);
			break;
		default:
			ret = -EINVAL;
			goto e_ctx;
		}

		memset(&hmac_cmd, 0, sizeof(hmac_cmd));
		hmac_cmd.engine = CCP_ENGINE_SHA;
		hmac_cmd.u.sha.type = sha->type;
		hmac_cmd.u.sha.ctx = sha->ctx;
		hmac_cmd.u.sha.ctx_len = sha->ctx_len;
		hmac_cmd.u.sha.src = &sg;
		hmac_cmd.u.sha.src_len = block_size + digest_size;
		hmac_cmd.u.sha.opad = NULL;
		hmac_cmd.u.sha.opad_len = 0;
		hmac_cmd.u.sha.first = 1;
		hmac_cmd.u.sha.final = 1;
		hmac_cmd.u.sha.msg_bits = (block_size + digest_size) << 3;

		ret = ccp_run_sha_cmd(cmd_q, &hmac_cmd);
		if (ret)
			cmd->engine_error = hmac_cmd.engine_error;

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1777,8 +1777,9 @@
 			       LSB_ITEM_SIZE);
 			break;
 		default:
+			kfree(hmac_buf);
 			ret = -EINVAL;
-			goto e_ctx;
+			goto e_data;
 		}
 
 		memset(&hmac_cmd, 0, sizeof(hmac_cmd));
```
