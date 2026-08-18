# CrossVul Fix Pair: Double Free in c
**Pair ID:** 3003_0
**Vulnerability Class:** Double Free
**CWE:** CWE-415
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3003_0`)

## Vulnerability Information & PoC

## Description
Double Free - When a program calls free() twice with the same argument, the program's memory management data structures become corrupted.

## Vulnerable Code
```c
Lines 766-807 of the vulnerable file.

	gpio_dev->gc.direction_input	= amd_gpio_direction_input;
	gpio_dev->gc.direction_output	= amd_gpio_direction_output;
	gpio_dev->gc.get			= amd_gpio_get_value;
	gpio_dev->gc.set			= amd_gpio_set_value;
	gpio_dev->gc.set_debounce	= amd_gpio_set_debounce;
	gpio_dev->gc.dbg_show		= amd_gpio_dbg_show;

	gpio_dev->gc.base			= 0;
	gpio_dev->gc.label			= pdev->name;
	gpio_dev->gc.owner			= THIS_MODULE;
	gpio_dev->gc.parent			= &pdev->dev;
	gpio_dev->gc.ngpio			= TOTAL_NUMBER_OF_PINS;
#if defined(CONFIG_OF_GPIO)
	gpio_dev->gc.of_node			= pdev->dev.of_node;
#endif

	gpio_dev->groups = kerncz_groups;
	gpio_dev->ngroups = ARRAY_SIZE(kerncz_groups);

	amd_pinctrl_desc.name = dev_name(&pdev->dev);
	gpio_dev->pctrl = pinctrl_register(&amd_pinctrl_desc,
					&pdev->dev, gpio_dev);
	if (IS_ERR(gpio_dev->pctrl)) {
		dev_err(&pdev->dev, "Couldn't register pinctrl driver\n");
		return PTR_ERR(gpio_dev->pctrl);
	}

	ret = gpiochip_add_data(&gpio_dev->gc, gpio_dev);
	if (ret)
		goto out1;

	ret = gpiochip_add_pin_range(&gpio_dev->gc, dev_name(&pdev->dev),
				0, 0, TOTAL_NUMBER_OF_PINS);
	if (ret) {
		dev_err(&pdev->dev, "Failed to add pin range\n");
		goto out2;
	}

	ret = gpiochip_irqchip_add(&gpio_dev->gc,
				&amd_gpio_irqchip,
				0,
				handle_simple_irq,
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -783,8 +783,8 @@
 	gpio_dev->ngroups = ARRAY_SIZE(kerncz_groups);
 
 	amd_pinctrl_desc.name = dev_name(&pdev->dev);
-	gpio_dev->pctrl = pinctrl_register(&amd_pinctrl_desc,
-					&pdev->dev, gpio_dev);
+	gpio_dev->pctrl = devm_pinctrl_register(&pdev->dev, &amd_pinctrl_desc,
+						gpio_dev);
 	if (IS_ERR(gpio_dev->pctrl)) {
 		dev_err(&pdev->dev, "Couldn't register pinctrl driver\n");
 		return PTR_ERR(gpio_dev->pctrl);
@@ -792,7 +792,7 @@
 
 	ret = gpiochip_add_data(&gpio_dev->gc, gpio_dev);
 	if (ret)
-		goto out1;
+		return ret;
 
 	ret = gpiochip_add_pin_range(&gpio_dev->gc, dev_name(&pdev->dev),
 				0, 0, TOTAL_NUMBER_OF_PINS);
@@ -825,8 +825,6 @@
 out2:
 	gpiochip_remove(&gpio_dev->gc);
 
-out1:
-	pinctrl_unregister(gpio_dev->pctrl);
 	return ret;
 }
 
@@ -837,7 +835,6 @@
 	gpio_dev = platform_get_drvdata(pdev);
 
 	gpiochip_remove(&gpio_dev->gc);
-	pinctrl_unregister(gpio_dev->pctrl);
 
 	return 0;
 }
```
