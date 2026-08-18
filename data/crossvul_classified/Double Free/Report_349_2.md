# CrossVul Fix Pair: Double Free in c
**Pair ID:** 349_2
**Vulnerability Class:** Double Free
**CWE:** CWE-415
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `349_2`)

## Vulnerability Information & PoC

## Description
Double Free - When a program calls free() twice with the same argument, the program's memory management data structures become corrupted.

## Vulnerable Code
```c
Lines 501-541 of the vulnerable file.

		flags = SC_ALGORITHM_RSA_RAW;
		flags |= SC_ALGORITHM_RSA_HASH_NONE;
		flags |= SC_ALGORITHM_ONBOARD_KEY_GEN;

		_sc_card_add_rsa_alg(card, 1024, flags, 0);
		_sc_card_add_rsa_alg(card, 2048, flags, 0);
	}
	return SC_SUCCESS;
}

static int muscle_list_files(sc_card_t *card, u8 *buf, size_t bufLen)
{
	muscle_private_t* priv = MUSCLE_DATA(card);
	mscfs_t *fs = priv->fs;
	int x;
	int count = 0;

	mscfs_check_cache(priv->fs);

	for(x = 0; x < fs->cache.size; x++) {
		u8* oid= fs->cache.array[x].objectId.id;
		sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL,
			"FILE: %02X%02X%02X%02X\n",
			oid[0],oid[1],oid[2],oid[3]);
		if(0 == memcmp(fs->currentPath, oid, 2)) {
			buf[0] = oid[2];
			buf[1] = oid[3];
			if(buf[0] == 0x00 && buf[1] == 0x00) continue; /* No directories/null names outside of root */
			buf += 2;
			count+=2;
		}
	}
	return count;
}

static int muscle_pin_cmd(sc_card_t *card, struct sc_pin_cmd_data *cmd,
				int *tries_left)
{
	muscle_private_t* priv = MUSCLE_DATA(card);
	const int bufferLength = MSC_MAX_PIN_COMMAND_LENGTH;
	u8 buffer[MSC_MAX_PIN_COMMAND_LENGTH];
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -518,7 +518,9 @@
 	mscfs_check_cache(priv->fs);
 
 	for(x = 0; x < fs->cache.size; x++) {
-		u8* oid= fs->cache.array[x].objectId.id;
+		u8* oid = fs->cache.array[x].objectId.id;
+		if (bufLen < 2)
+			break;
 		sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL,
 			"FILE: %02X%02X%02X%02X\n",
 			oid[0],oid[1],oid[2],oid[3]);
@@ -527,7 +529,8 @@
 			buf[1] = oid[3];
 			if(buf[0] == 0x00 && buf[1] == 0x00) continue; /* No directories/null names outside of root */
 			buf += 2;
-			count+=2;
+			count += 2;
+			bufLen -= 2;
 		}
 	}
 	return count;
```
