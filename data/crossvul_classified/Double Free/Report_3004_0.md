# CrossVul Fix Pair: Double Free in c
**Pair ID:** 3004_0
**Vulnerability Class:** Double Free
**CWE:** CWE-415
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3004_0`)

## Vulnerability Information & PoC

## Description
Double Free - When a program calls free() twice with the same argument, the program's memory management data structures become corrupted.

## Vulnerable Code
```c
Lines 819-859 of the vulnerable file.

				 irq_base,
				 amd_gpio_irq_handler);
	platform_set_drvdata(pdev, gpio_dev);

	dev_dbg(&pdev->dev, "amd gpio driver loaded\n");
	return ret;

out2:
	gpiochip_remove(&gpio_dev->gc);

	return ret;
}

static int amd_gpio_remove(struct platform_device *pdev)
{
	struct amd_gpio *gpio_dev;

	gpio_dev = platform_get_drvdata(pdev);

	gpiochip_remove(&gpio_dev->gc);
	pinctrl_unregister(gpio_dev->pctrl);

	return 0;
}

static const struct acpi_device_id amd_gpio_acpi_match[] = {
	{ "AMD0030", 0 },
	{ "AMDI0030", 0},
	{ },
};
MODULE_DEVICE_TABLE(acpi, amd_gpio_acpi_match);

static struct platform_driver amd_gpio_driver = {
	.driver		= {
		.name	= "amd_gpio",
		.acpi_match_table = ACPI_PTR(amd_gpio_acpi_match),
	},
	.probe		= amd_gpio_probe,
	.remove		= amd_gpio_remove,
};

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -836,7 +836,6 @@
 	gpio_dev = platform_get_drvdata(pdev);
 
 	gpiochip_remove(&gpio_dev->gc);
-	pinctrl_unregister(gpio_dev->pctrl);
 
 	return 0;
 }
```
