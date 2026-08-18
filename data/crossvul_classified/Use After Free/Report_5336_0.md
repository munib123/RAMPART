# CrossVul Fix Pair: Use After Free in c
**Pair ID:** 5336_0
**Vulnerability Class:** Use After Free
**CWE:** CWE-416
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5336_0`)

## Vulnerability Information & PoC

## Description
Use After Free - The use of previously-freed memory can have any number of adverse consequences, ranging from the corruption of valid data to the execution of arbitrary code, depending on the instantiation and timi...

## Vulnerable Code
```c
Lines 1386-1426 of the vulnerable file.

		return;
	priv->state = XC2028_ACTIVE;
}

static int xc2028_set_config(struct dvb_frontend *fe, void *priv_cfg)
{
	struct xc2028_data *priv = fe->tuner_priv;
	struct xc2028_ctrl *p    = priv_cfg;
	int                 rc   = 0;

	tuner_dbg("%s called\n", __func__);

	mutex_lock(&priv->lock);

	/*
	 * Copy the config data.
	 * For the firmware name, keep a local copy of the string,
	 * in order to avoid troubles during device release.
	 */
	kfree(priv->ctrl.fname);
	memcpy(&priv->ctrl, p, sizeof(priv->ctrl));
	if (p->fname) {
		priv->ctrl.fname = kstrdup(p->fname, GFP_KERNEL);
		if (priv->ctrl.fname == NULL)
			rc = -ENOMEM;
	}

	/*
	 * If firmware name changed, frees firmware. As free_firmware will
	 * reset the status to NO_FIRMWARE, this forces a new request_firmware
	 */
	if (!firmware_name[0] && p->fname &&
	    priv->fname && strcmp(p->fname, priv->fname))
		free_firmware(priv);

	if (priv->ctrl.max_len < 9)
		priv->ctrl.max_len = 13;

	if (priv->state == XC2028_NO_FIRMWARE) {
		if (!firmware_name[0])
			priv->fname = priv->ctrl.fname;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1403,11 +1403,12 @@
 	 * in order to avoid troubles during device release.
 	 */
 	kfree(priv->ctrl.fname);
+	priv->ctrl.fname = NULL;
 	memcpy(&priv->ctrl, p, sizeof(priv->ctrl));
 	if (p->fname) {
 		priv->ctrl.fname = kstrdup(p->fname, GFP_KERNEL);
 		if (priv->ctrl.fname == NULL)
-			rc = -ENOMEM;
+			return -ENOMEM;
 	}
 
 	/*
```
