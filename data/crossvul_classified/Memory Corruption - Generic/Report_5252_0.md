# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 5252_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5252_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 79-119 of the vulnerable file.

static unsigned char srcmac[ETH_ALEN];
static unsigned char dstmac[ETH_ALEN];

static struct in_addr sourceip; 
static struct in_addr destip;
static int sourceport;

static int connect_timeout = CONNECT_TIMEOUT;
static char run_mndp = 0;
static int mndp_timeout = 0;

static int is_a_tty = 1;
static int quiet_mode = 0;
static int batch_mode = 0;
static int no_autologin = 0;

static char autologin_path[255];

static int keepalive_counter = 0;

static unsigned char pass_salt[17];
static char username[MT_MNDP_MAX_STRING_SIZE];
static char password[MT_MNDP_MAX_STRING_SIZE];
static char nonpriv_username[MT_MNDP_MAX_STRING_SIZE];

struct net_interface *interfaces=NULL;
struct net_interface *active_interface;

/* Protocol data direction */
unsigned char mt_direction_fromserver = 0;

static unsigned int send_socket;

static int handle_packet(unsigned char *data, int data_len);

static void print_version() {
	fprintf(stderr, PROGRAM_NAME " " PROGRAM_VERSION "\n");
}

void drop_privileges(char *username) {
	struct passwd *user = (struct passwd *) getpwnam(username);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -96,7 +96,7 @@
 
 static int keepalive_counter = 0;
 
-static unsigned char pass_salt[17];
+static unsigned char pass_salt[16];
 static char username[MT_MNDP_MAX_STRING_SIZE];
 static char password[MT_MNDP_MAX_STRING_SIZE];
 static char nonpriv_username[MT_MNDP_MAX_STRING_SIZE];
@@ -212,7 +212,7 @@
 	char *terminal = getenv("TERM");
 	char md5data[100];
 	unsigned char md5sum[17];
-	int plen;
+	int plen, act_pass_len;
 	md5_state_t state;
 
 #if defined(__linux__) && defined(_POSIX_MEMLOCK_RANGE)
@@ -220,15 +220,18 @@
 	mlock(md5sum, sizeof(md5data));
 #endif
 
+	/* calculate the actual password's length */
+	act_pass_len = strnlen(password, 82);
+
 	/* Concat string of 0 + password + pass_salt */
 	md5data[0] = 0;
-	strncpy(md5data + 1, password, 82);
-	md5data[83] = '\0';
-	memcpy(md5data + 1 + strlen(password), pass_salt, 16);
+	memcpy(md5data + 1, password, act_pass_len);
+	/* in case that password is long, calculate only using the used-up parts */
+	memcpy(md5data + 1 + act_pass_len, pass_salt, 16);
 
 	/* Generate md5 sum of md5data with a leading 0 */
 	md5_init(&state);
-	md5_append(&state, (const md5_byte_t *)md5data, strlen(password) + 17);
+	md5_append(&state, (const md5_byte_t *)md5data, 1 + act_pass_len + 16);
 	md5_finish(&state, (md5_byte_t *)md5sum + 1);
 	md5sum[0] = 0;
 
@@ -312,7 +315,11 @@
 
 			/* If we receive pass_salt, transmit auth data back */
 			if (cpkt.cptype == MT_CPTYPE_PASSSALT) {
-				memcpy(pass_salt, cpkt.data, cpkt.length);
+				/* check validity, server sends exactly 16 bytes */
+				if (cpkt.length != 16) {
+					fprintf(stderr, _("Invalid salt length: %d (instead of 16) received from server %s\n"), cpkt.length, ether_ntoa((struct ether_addr *)dstmac));
+				}
+				memcpy(pass_salt, cpkt.data, 16);
 				send_auth(username, password);
 			}
 
```
