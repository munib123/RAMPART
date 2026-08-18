# CrossVul Fix Pair: Uncontrolled Resource Consumption in c
**Pair ID:** 1260_0
**Vulnerability Class:** Uncontrolled Resource Consumption
**CWE:** CWE-400
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1260_0`)

## Vulnerability Information & PoC

## Description
Uncontrolled Resource Consumption - Limited resources include memory, file system storage, database connection pool entries, and CPU.

## Vulnerable Code
```c
Lines 354-394 of the vulnerable file.

{
	spi_master_put(data);
}

static int spi_gpio_probe(struct platform_device *pdev)
{
	int				status;
	struct spi_master		*master;
	struct spi_gpio			*spi_gpio;
	struct device			*dev = &pdev->dev;
	struct spi_bitbang		*bb;
	const struct of_device_id	*of_id;

	of_id = of_match_device(spi_gpio_dt_ids, &pdev->dev);

	master = spi_alloc_master(dev, sizeof(*spi_gpio));
	if (!master)
		return -ENOMEM;

	status = devm_add_action_or_reset(&pdev->dev, spi_gpio_put, master);
	if (status)
		return status;

	if (of_id)
		status = spi_gpio_probe_dt(pdev, master);
	else
		status = spi_gpio_probe_pdata(pdev, master);

	if (status)
		return status;

	spi_gpio = spi_master_get_devdata(master);

	status = spi_gpio_request(dev, spi_gpio);
	if (status)
		return status;

	master->bits_per_word_mask = SPI_BPW_RANGE_MASK(1, 32);
	master->mode_bits = SPI_3WIRE | SPI_3WIRE_HIZ | SPI_CPHA | SPI_CPOL |
			    SPI_CS_HIGH;
	if (!spi_gpio->mosi) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -371,8 +371,10 @@
 		return -ENOMEM;
 
 	status = devm_add_action_or_reset(&pdev->dev, spi_gpio_put, master);
-	if (status)
+	if (status) {
+		spi_master_put(master);
 		return status;
+	}
 
 	if (of_id)
 		status = spi_gpio_probe_dt(pdev, master);
```
