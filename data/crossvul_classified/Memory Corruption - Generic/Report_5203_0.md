# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 5203_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5203_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 1418-1458 of the vulnerable file.

					&buffer, &buffer_size, flags);
			if (status != 0)
			{
				ERROR ("network plugin: Decrypting AES256 "
						"part failed "
						"with status %i.", status);
				break;
			}
		}
#if HAVE_LIBGCRYPT
		else if ((se->data.server.security_level == SECURITY_LEVEL_ENCRYPT)
				&& (packet_was_encrypted == 0))
		{
			if (printed_ignore_warning == 0)
			{
				INFO ("network plugin: Unencrypted packet or "
						"part has been ignored.");
				printed_ignore_warning = 1;
			}
			buffer = ((char *) buffer) + pkg_length;
			continue;
		}
#endif /* HAVE_LIBGCRYPT */
		else if (pkg_type == TYPE_SIGN_SHA256)
		{
			status = parse_part_sign_sha256 (se,
                                        &buffer, &buffer_size, flags);
			if (status != 0)
			{
				ERROR ("network plugin: Verifying HMAC-SHA-256 "
						"signature failed "
						"with status %i.", status);
				break;
			}
		}
#if HAVE_LIBGCRYPT
		else if ((se->data.server.security_level == SECURITY_LEVEL_SIGN)
				&& (packet_was_encrypted == 0)
				&& (packet_was_signed == 0))
		{
			if (printed_ignore_warning == 0)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1435,6 +1435,7 @@
 				printed_ignore_warning = 1;
 			}
 			buffer = ((char *) buffer) + pkg_length;
+			buffer_size -= (size_t) pkg_length;
 			continue;
 		}
 #endif /* HAVE_LIBGCRYPT */
@@ -1462,6 +1463,7 @@
 				printed_ignore_warning = 1;
 			}
 			buffer = ((char *) buffer) + pkg_length;
+			buffer_size -= (size_t) pkg_length;
 			continue;
 		}
 #endif /* HAVE_LIBGCRYPT */
@@ -1603,6 +1605,7 @@
 			DEBUG ("network plugin: parse_packet: Unknown part"
 					" type: 0x%04hx", pkg_type);
 			buffer = ((char *) buffer) + pkg_length;
+			buffer_size -= (size_t) pkg_length;
 		}
 	} /* while (buffer_size > sizeof (part_header_t)) */
 
```
