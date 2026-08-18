# CrossVul Fix Pair: Use After Free in c
**Pair ID:** 888_0
**Vulnerability Class:** Use After Free
**CWE:** CWE-416
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `888_0`)

## Vulnerability Information & PoC

## Description
Use After Free - The use of previously-freed memory can have any number of adverse consequences, ranging from the corruption of valid data to the execution of arbitrary code, depending on the instantiation and timi...

## Vulnerable Code
```c
Lines 362-402 of the vulnerable file.

	struct mdio_device *mdiodev;
	int i, err;
	struct gpio_desc *gpiod;

	if (NULL == bus || NULL == bus->name ||
	    NULL == bus->read || NULL == bus->write)
		return -EINVAL;

	BUG_ON(bus->state != MDIOBUS_ALLOCATED &&
	       bus->state != MDIOBUS_UNREGISTERED);

	bus->owner = owner;
	bus->dev.parent = bus->parent;
	bus->dev.class = &mdio_bus_class;
	bus->dev.groups = NULL;
	dev_set_name(&bus->dev, "%s", bus->id);

	err = device_register(&bus->dev);
	if (err) {
		pr_err("mii_bus %s failed to register\n", bus->id);
		put_device(&bus->dev);
		return -EINVAL;
	}

	mutex_init(&bus->mdio_lock);

	/* de-assert bus level PHY GPIO reset */
	gpiod = devm_gpiod_get_optional(&bus->dev, "reset", GPIOD_OUT_LOW);
	if (IS_ERR(gpiod)) {
		dev_err(&bus->dev, "mii_bus %s couldn't get reset GPIO\n",
			bus->id);
		device_del(&bus->dev);
		return PTR_ERR(gpiod);
	} else	if (gpiod) {
		bus->reset_gpiod = gpiod;

		gpiod_set_value_cansleep(gpiod, 1);
		udelay(bus->reset_delay_us);
		gpiod_set_value_cansleep(gpiod, 0);
	}

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -379,7 +379,6 @@
 	err = device_register(&bus->dev);
 	if (err) {
 		pr_err("mii_bus %s failed to register\n", bus->id);
-		put_device(&bus->dev);
 		return -EINVAL;
 	}
 
```
