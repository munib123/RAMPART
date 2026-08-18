# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 4888_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4888_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 1065-1105 of the vulnerable file.

	cqspi_controller_enable(cqspi, 1);
}

static int cqspi_setup_flash(struct cqspi_st *cqspi, struct device_node *np)
{
	struct platform_device *pdev = cqspi->pdev;
	struct device *dev = &pdev->dev;
	struct cqspi_flash_pdata *f_pdata;
	struct spi_nor *nor;
	struct mtd_info *mtd;
	unsigned int cs;
	int i, ret;

	/* Get flash device data */
	for_each_available_child_of_node(dev->of_node, np) {
		if (of_property_read_u32(np, "reg", &cs)) {
			dev_err(dev, "Couldn't determine chip select.\n");
			goto err;
		}

		if (cs > CQSPI_MAX_CHIPSELECT) {
			dev_err(dev, "Chip select %d out of range.\n", cs);
			goto err;
		}

		f_pdata = &cqspi->f_pdata[cs];
		f_pdata->cqspi = cqspi;
		f_pdata->cs = cs;

		ret = cqspi_of_get_flash_pdata(pdev, f_pdata, np);
		if (ret)
			goto err;

		nor = &f_pdata->nor;
		mtd = &nor->mtd;

		mtd->priv = nor;

		nor->dev = dev;
		spi_nor_set_flash_node(nor, np);
		nor->priv = f_pdata;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1082,7 +1082,7 @@
 			goto err;
 		}
 
-		if (cs > CQSPI_MAX_CHIPSELECT) {
+		if (cs >= CQSPI_MAX_CHIPSELECT) {
 			dev_err(dev, "Chip select %d out of range.\n", cs);
 			goto err;
 		}
```
