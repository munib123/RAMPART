# CrossVul Fix Pair: 7PK in c
**Pair ID:** 3321_0
**Vulnerability Class:** 7PK
**CWE:** CWE-388
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3321_0`)

## Vulnerability Information & PoC

## Description
7PK - Errors

## Vulnerable Code
```c
Lines 196-236 of the vulnerable file.

	if (ret != CP2112_GPIO_CONFIG_LENGTH) {
		hid_err(hdev, "error requesting GPIO config: %d\n", ret);
		goto exit;
	}

	buf[1] &= ~(1 << offset);
	buf[2] = gpio_push_pull;

	ret = hid_hw_raw_request(hdev, CP2112_GPIO_CONFIG, buf,
				 CP2112_GPIO_CONFIG_LENGTH, HID_FEATURE_REPORT,
				 HID_REQ_SET_REPORT);
	if (ret < 0) {
		hid_err(hdev, "error setting GPIO config: %d\n", ret);
		goto exit;
	}

	ret = 0;

exit:
	mutex_unlock(&dev->lock);
	return ret <= 0 ? ret : -EIO;
}

static void cp2112_gpio_set(struct gpio_chip *chip, unsigned offset, int value)
{
	struct cp2112_device *dev = gpiochip_get_data(chip);
	struct hid_device *hdev = dev->hdev;
	u8 *buf = dev->in_out_buffer;
	int ret;

	mutex_lock(&dev->lock);

	buf[0] = CP2112_GPIO_SET;
	buf[1] = value ? 0xff : 0;
	buf[2] = 1 << offset;

	ret = hid_hw_raw_request(hdev, CP2112_GPIO_SET, buf,
				 CP2112_GPIO_SET_LENGTH, HID_FEATURE_REPORT,
				 HID_REQ_SET_REPORT);
	if (ret < 0)
		hid_err(hdev, "error setting GPIO values: %d\n", ret);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -213,7 +213,7 @@
 
 exit:
 	mutex_unlock(&dev->lock);
-	return ret <= 0 ? ret : -EIO;
+	return ret < 0 ? ret : -EIO;
 }
 
 static void cp2112_gpio_set(struct gpio_chip *chip, unsigned offset, int value)
```
