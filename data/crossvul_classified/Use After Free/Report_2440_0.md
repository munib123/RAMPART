# CrossVul Fix Pair: Use After Free in c
**Pair ID:** 2440_0
**Vulnerability Class:** Use After Free
**CWE:** CWE-416
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2440_0`)

## Vulnerability Information & PoC

## Description
Use After Free - The use of previously-freed memory can have any number of adverse consequences, ranging from the corruption of valid data to the execution of arbitrary code, depending on the instantiation and timi...

## Vulnerable Code
```c
Lines 1696-1736 of the vulnerable file.

	pin->request_count++;
	rdev->ena_pin = pin;
	return 0;
}

static void regulator_ena_gpio_free(struct regulator_dev *rdev)
{
	struct regulator_enable_gpio *pin, *n;

	if (!rdev->ena_pin)
		return;

	/* Free the GPIO only in case of no use */
	list_for_each_entry_safe(pin, n, &regulator_ena_gpio_list, list) {
		if (pin->gpiod == rdev->ena_pin->gpiod) {
			if (pin->request_count <= 1) {
				pin->request_count = 0;
				gpiod_put(pin->gpiod);
				list_del(&pin->list);
				kfree(pin);
			} else {
				pin->request_count--;
			}
		}
	}
}

/**
 * regulator_ena_gpio_ctrl - balance enable_count of each GPIO and actual GPIO pin control
 * @rdev: regulator_dev structure
 * @enable: enable GPIO at initial use?
 *
 * GPIO is enabled in case of initial use. (enable_count is 0)
 * GPIO is disabled when it is not shared any more. (enable_count <= 1)
 */
static int regulator_ena_gpio_ctrl(struct regulator_dev *rdev, bool enable)
{
	struct regulator_enable_gpio *pin = rdev->ena_pin;

	if (!pin)
		return -EINVAL;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1713,6 +1713,8 @@
 				gpiod_put(pin->gpiod);
 				list_del(&pin->list);
 				kfree(pin);
+				rdev->ena_pin = NULL;
+				return;
 			} else {
 				pin->request_count--;
 			}
```
