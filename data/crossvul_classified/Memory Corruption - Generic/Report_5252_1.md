# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 5252_1
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5252_1`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 390-430 of the vulnerable file.


static void abort_connection(struct mt_connection *curconn, struct mt_mactelnet_hdr *pkthdr, char *message) {
	struct mt_packet pdata;

	init_packet(&pdata, MT_PTYPE_DATA, pkthdr->dstaddr, pkthdr->srcaddr, pkthdr->seskey, curconn->outcounter);
	add_control_packet(&pdata, MT_CPTYPE_PLAINDATA, message, strlen(message));
	send_udp(curconn, &pdata);

	/* Make connection time out; lets the previous message get acked before disconnecting */
	curconn->state = STATE_CLOSED;
	init_packet(&pdata, MT_PTYPE_END, pkthdr->dstaddr, pkthdr->srcaddr, pkthdr->seskey, curconn->outcounter);
	send_udp(curconn, &pdata);
}

static void user_login(struct mt_connection *curconn, struct mt_mactelnet_hdr *pkthdr) {
	struct mt_packet pdata;
	unsigned char md5sum[17];
	char md5data[100];
	struct mt_credentials *user;
	char *slavename;

	/* Reparse user file before each login */
	read_userfile();

	if ((user = find_user(curconn->username)) != NULL) {
		md5_state_t state;
#if defined(__linux__) && defined(_POSIX_MEMLOCK_RANGE)
		mlock(md5data, sizeof(md5data));
		mlock(md5sum, sizeof(md5sum));
		if (user->password != NULL) {
			mlock(user->password, strlen(user->password));
		}
#endif

		/* Concat string of 0 + password + pass_salt */
		md5data[0] = 0;
		strncpy(md5data + 1, user->password, 82);
		memcpy(md5data + 1 + strlen(user->password), curconn->pass_salt, 16);

		/* Generate md5 sum of md5data with a leading 0 */
		md5_init(&state);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -407,6 +407,7 @@
 	char md5data[100];
 	struct mt_credentials *user;
 	char *slavename;
+	int act_pass_len;
 
 	/* Reparse user file before each login */
 	read_userfile();
@@ -421,14 +422,18 @@
 		}
 #endif
 
+		/* calculate the password's actual length */
+		act_pass_len = strlen(user->password);
+		act_pass_len = act_pass_len <= 82 ? act_pass_len : 82;
+
 		/* Concat string of 0 + password + pass_salt */
 		md5data[0] = 0;
-		strncpy(md5data + 1, user->password, 82);
-		memcpy(md5data + 1 + strlen(user->password), curconn->pass_salt, 16);
+		memcpy(md5data + 1, user->password, act_pass_len);
+		memcpy(md5data + 1 + act_pass_len, curconn->pass_salt, 16);
 
 		/* Generate md5 sum of md5data with a leading 0 */
 		md5_init(&state);
-		md5_append(&state, (const md5_byte_t *)md5data, strlen(user->password) + 17);
+		md5_append(&state, (const md5_byte_t *)md5data, 1 + act_pass_len + 16);
 		md5_finish(&state, (md5_byte_t *)md5sum + 1);
 		md5sum[0] = 0;
 
@@ -635,7 +640,7 @@
 			memcpy(curconn->terminal_type, cpkt.data, act_size = (cpkt.length > 30 - 1 ? 30 - 1 : cpkt.length));
 			curconn->terminal_type[act_size] = 0;
 
-		} else if (cpkt.cptype == MT_CPTYPE_PASSWORD) {
+		} else if (cpkt.cptype == MT_CPTYPE_PASSWORD && cpkt.length == 17) {
 
 #if defined(__linux__) && defined(_POSIX_MEMLOCK_RANGE)
 			mlock(curconn->trypassword, 17);
@@ -651,7 +656,7 @@
 			}
 
 		} else {
-			syslog(LOG_WARNING, _("(%d) Unhandeled control packet type: %d"), curconn->seskey, cpkt.cptype);
+			syslog(LOG_WARNING, _("(%d) Unhandeled control packet type: %d, length: %d"), curconn->seskey, cpkt.cptype, cpkt.length);
 		}
 
 		/* Parse next control packet */
```
