# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 3312_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3312_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 42-82 of the vulnerable file.

#include "dib0070.h"
#include "lgs8gxx.h"
#include "atbm8830.h"
#include "si2168.h"
#include "si2157.h"

/* debug */
static int dvb_usb_cxusb_debug;
module_param_named(debug, dvb_usb_cxusb_debug, int, 0644);
MODULE_PARM_DESC(debug, "set debugging level (1=rc (or-able))." DVB_USB_DEBUG_STATUS);

DVB_DEFINE_MOD_OPT_ADAPTER_NR(adapter_nr);

#define deb_info(args...)   dprintk(dvb_usb_cxusb_debug, 0x03, args)
#define deb_i2c(args...)    dprintk(dvb_usb_cxusb_debug, 0x02, args)

static int cxusb_ctrl_msg(struct dvb_usb_device *d,
			  u8 cmd, u8 *wbuf, int wlen, u8 *rbuf, int rlen)
{
	struct cxusb_state *st = d->priv;
	int ret, wo;

	if (1 + wlen > MAX_XFER_SIZE) {
		warn("i2c wr: len=%d is too big!\n", wlen);
		return -EOPNOTSUPP;
	}

	wo = (rbuf == NULL || rlen == 0); /* write-only */

	mutex_lock(&d->data_mutex);
	st->data[0] = cmd;
	memcpy(&st->data[1], wbuf, wlen);
	if (wo)
		ret = dvb_usb_generic_write(d, st->data, 1 + wlen);
	else
		ret = dvb_usb_generic_rw(d, st->data, 1 + wlen,
					 rbuf, rlen, 0);

	mutex_unlock(&d->data_mutex);
	return ret;
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -59,23 +59,24 @@
 			  u8 cmd, u8 *wbuf, int wlen, u8 *rbuf, int rlen)
 {
 	struct cxusb_state *st = d->priv;
-	int ret, wo;
+	int ret;
 
 	if (1 + wlen > MAX_XFER_SIZE) {
 		warn("i2c wr: len=%d is too big!\n", wlen);
 		return -EOPNOTSUPP;
 	}
 
-	wo = (rbuf == NULL || rlen == 0); /* write-only */
+	if (rlen > MAX_XFER_SIZE) {
+		warn("i2c rd: len=%d is too big!\n", rlen);
+		return -EOPNOTSUPP;
+	}
 
 	mutex_lock(&d->data_mutex);
 	st->data[0] = cmd;
 	memcpy(&st->data[1], wbuf, wlen);
-	if (wo)
-		ret = dvb_usb_generic_write(d, st->data, 1 + wlen);
-	else
-		ret = dvb_usb_generic_rw(d, st->data, 1 + wlen,
-					 rbuf, rlen, 0);
+	ret = dvb_usb_generic_rw(d, st->data, 1 + wlen, st->data, rlen, 0);
+	if (!ret && rbuf && rlen)
+		memcpy(rbuf, st->data, rlen);
 
 	mutex_unlock(&d->data_mutex);
 	return ret;
```
