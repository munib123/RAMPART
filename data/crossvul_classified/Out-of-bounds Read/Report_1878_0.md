# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 1878_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1878_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 946-986 of the vulnerable file.

	state->dsec_cmd.args[CX24116_DISEQC_ARG3_0] = 0x00;
	/* Continuation flag? */
	state->dsec_cmd.args[CX24116_DISEQC_ARG4_0] = 0x00;

	/* DiSEqC message length */
	state->dsec_cmd.args[CX24116_DISEQC_MSGLEN] = 0x00;

	/* Command length */
	state->dsec_cmd.len = CX24116_DISEQC_MSGOFS;

	return 0;
}

/* Send DiSEqC message with derived burst (hack) || previous burst */
static int cx24116_send_diseqc_msg(struct dvb_frontend *fe,
	struct dvb_diseqc_master_cmd *d)
{
	struct cx24116_state *state = fe->demodulator_priv;
	int i, ret;

	/* Dump DiSEqC message */
	if (debug) {
		printk(KERN_INFO "cx24116: %s(", __func__);
		for (i = 0 ; i < d->msg_len ;) {
			printk(KERN_INFO "0x%02x", d->msg[i]);
			if (++i < d->msg_len)
				printk(KERN_INFO ", ");
		}
		printk(") toneburst=%d\n", toneburst);
	}

	/* Validate length */
	if (d->msg_len > (CX24116_ARGLEN - CX24116_DISEQC_MSGOFS))
		return -EINVAL;

	/* DiSEqC message */
	for (i = 0; i < d->msg_len; i++)
		state->dsec_cmd.args[CX24116_DISEQC_MSGOFS + i] = d->msg[i];

	/* DiSEqC message length */
	state->dsec_cmd.args[CX24116_DISEQC_MSGLEN] = d->msg_len;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -963,6 +963,10 @@
 	struct cx24116_state *state = fe->demodulator_priv;
 	int i, ret;
 
+	/* Validate length */
+	if (d->msg_len > sizeof(d->msg))
+                return -EINVAL;
+
 	/* Dump DiSEqC message */
 	if (debug) {
 		printk(KERN_INFO "cx24116: %s(", __func__);
@@ -973,10 +977,6 @@
 		}
 		printk(") toneburst=%d\n", toneburst);
 	}
-
-	/* Validate length */
-	if (d->msg_len > (CX24116_ARGLEN - CX24116_DISEQC_MSGOFS))
-		return -EINVAL;
 
 	/* DiSEqC message */
 	for (i = 0; i < d->msg_len; i++)
```
