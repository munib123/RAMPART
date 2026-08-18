# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 2522_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2522_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 10-50 of the vulnerable file.


   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
   OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
   FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT OF THIRD PARTY RIGHTS.
   IN NO EVENT SHALL THE COPYRIGHT HOLDER(S) AND AUTHOR(S) BE LIABLE FOR ANY
   CLAIM, OR ANY SPECIAL INDIRECT OR CONSEQUENTIAL DAMAGES, OR ANY DAMAGES 
   WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN 
   ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF 
   OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

   ALL LIABILITY, INCLUDING LIABILITY FOR INFRINGEMENT OF ANY PATENTS, 
   COPYRIGHTS, TRADEMARKS OR OTHER RIGHTS, RELATING TO USE OF THIS 
   SOFTWARE IS DISCLAIMED.
*/

#ifndef __L2CAP_H
#define __L2CAP_H

/* L2CAP defaults */
#define L2CAP_DEFAULT_MTU		672
#define L2CAP_DEFAULT_FLUSH_TO		0xffff
#define L2CAP_DEFAULT_RX_WINDOW		1
#define L2CAP_DEFAULT_MAX_RECEIVE	1
#define L2CAP_DEFAULT_RETRANS_TO	300    /* 300 milliseconds */
#define L2CAP_DEFAULT_MONITOR_TO	1000   /* 1 second */
#define L2CAP_DEFAULT_MAX_RX_APDU	0xfff7

#define L2CAP_CONN_TIMEOUT	(40000) /* 40 seconds */
#define L2CAP_INFO_TIMEOUT	(4000)  /*  4 seconds */

/* L2CAP socket address */
struct sockaddr_l2 {
	sa_family_t	l2_family;
	__le16		l2_psm;
	bdaddr_t	l2_bdaddr;
	__le16		l2_cid;
};

/* L2CAP socket options */
#define L2CAP_OPTIONS	0x01
struct l2cap_options {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -27,8 +27,9 @@
 
 /* L2CAP defaults */
 #define L2CAP_DEFAULT_MTU		672
+#define L2CAP_DEFAULT_MIN_MTU		48
 #define L2CAP_DEFAULT_FLUSH_TO		0xffff
-#define L2CAP_DEFAULT_RX_WINDOW		1
+#define L2CAP_DEFAULT_TX_WINDOW		1
 #define L2CAP_DEFAULT_MAX_RECEIVE	1
 #define L2CAP_DEFAULT_RETRANS_TO	300    /* 300 milliseconds */
 #define L2CAP_DEFAULT_MONITOR_TO	1000   /* 1 second */
@@ -272,6 +273,9 @@
 	__u16		omtu;
 	__u16		flush_to;
 	__u8		mode;
+	__u8		num_conf_req;
+	__u8		num_conf_rsp;
+
 	__u8		fcs;
 	__u8		sec_level;
 	__u8		role_switch;
@@ -280,9 +284,14 @@
 	__u8		conf_req[64];
 	__u8		conf_len;
 	__u8		conf_state;
-	__u8		conf_retry;
 
 	__u8		ident;
+
+	__u8		remote_tx_win;
+	__u8		remote_max_tx;
+	__u16		retrans_timeout;
+	__u16		monitor_timeout;
+	__u16		max_pdu_size;
 
 	__le16		sport;
 
@@ -291,12 +300,17 @@
 	struct sock		*prev_c;
 };
 
-#define L2CAP_CONF_REQ_SENT	0x01
-#define L2CAP_CONF_INPUT_DONE	0x02
-#define L2CAP_CONF_OUTPUT_DONE	0x04
-#define L2CAP_CONF_CONNECT_PEND	0x80
-
-#define L2CAP_CONF_MAX_RETRIES	2
+#define L2CAP_CONF_REQ_SENT       0x01
+#define L2CAP_CONF_INPUT_DONE     0x02
+#define L2CAP_CONF_OUTPUT_DONE    0x04
+#define L2CAP_CONF_MTU_DONE       0x08
+#define L2CAP_CONF_MODE_DONE      0x10
+#define L2CAP_CONF_CONNECT_PEND   0x20
+#define L2CAP_CONF_STATE2_DEVICE  0x80
+
+#define L2CAP_CONF_MAX_CONF_REQ 2
+#define L2CAP_CONF_MAX_CONF_RSP 2
+
 
 void l2cap_load(void);
 
```
