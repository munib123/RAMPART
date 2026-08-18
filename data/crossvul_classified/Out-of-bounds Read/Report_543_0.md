# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 543_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `543_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 189-229 of the vulnerable file.

	return -EINVAL;
}

static const struct phy_ops serdes_ops = {
	.set_mode	= serdes_set_mode,
	.owner		= THIS_MODULE,
};

static struct phy *serdes_simple_xlate(struct device *dev,
				       struct of_phandle_args *args)
{
	struct serdes_ctrl *ctrl = dev_get_drvdata(dev);
	unsigned int port, idx, i;

	if (args->args_count != 2)
		return ERR_PTR(-EINVAL);

	port = args->args[0];
	idx = args->args[1];

	for (i = 0; i <= SERDES_MAX; i++) {
		struct serdes_macro *macro = phy_get_drvdata(ctrl->phys[i]);

		if (idx != macro->idx)
			continue;

		/* SERDES6G(0) is the only SerDes capable of QSGMII */
		if (idx != SERDES6G(0) && macro->port >= 0)
			return ERR_PTR(-EBUSY);

		macro->port = port;
		return ctrl->phys[i];
	}

	return ERR_PTR(-ENODEV);
}

static int serdes_phy_create(struct serdes_ctrl *ctrl, u8 idx, struct phy **phy)
{
	struct serdes_macro *macro;

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -206,7 +206,7 @@
 	port = args->args[0];
 	idx = args->args[1];
 
-	for (i = 0; i <= SERDES_MAX; i++) {
+	for (i = 0; i < SERDES_MAX; i++) {
 		struct serdes_macro *macro = phy_get_drvdata(ctrl->phys[i]);
 
 		if (idx != macro->idx)
@@ -260,7 +260,7 @@
 	if (IS_ERR(ctrl->regs))
 		return PTR_ERR(ctrl->regs);
 
-	for (i = 0; i <= SERDES_MAX; i++) {
+	for (i = 0; i < SERDES_MAX; i++) {
 		ret = serdes_phy_create(ctrl, i, &ctrl->phys[i]);
 		if (ret)
 			return ret;
```
