# CrossVul Fix Pair: Improper Resource Shutdown or Release in c
**Pair ID:** 3320_0
**Vulnerability Class:** Improper Resource Shutdown or Release
**CWE:** CWE-404
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3320_0`)

## Vulnerability Information & PoC

## Description
Improper Resource Shutdown or Release - When a resource is created or allocated, the developer is responsible for properly releasing the resource as well as accounting for all potential paths of expiration or invalidation, such as a set ...

## Vulnerable Code
```c
Lines 151-191 of the vulnerable file.

static const int RESPONSE_TIMEOUT = 50;

static const struct hid_device_id cp2112_devices[] = {
	{ HID_USB_DEVICE(USB_VENDOR_ID_CYGNAL, USB_DEVICE_ID_CYGNAL_CP2112) },
	{ }
};
MODULE_DEVICE_TABLE(hid, cp2112_devices);

struct cp2112_device {
	struct i2c_adapter adap;
	struct hid_device *hdev;
	wait_queue_head_t wait;
	u8 read_data[61];
	u8 read_length;
	u8 hwversion;
	int xfer_status;
	atomic_t read_avail;
	atomic_t xfer_avail;
	struct gpio_chip gc;
	u8 *in_out_buffer;
	spinlock_t lock;

	struct gpio_desc *desc[8];
	bool gpio_poll;
	struct delayed_work gpio_poll_worker;
	unsigned long irq_mask;
	u8 gpio_prev_state;
};

static int gpio_push_pull = 0xFF;
module_param(gpio_push_pull, int, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(gpio_push_pull, "GPIO push-pull configuration bitmask");

static int cp2112_gpio_direction_input(struct gpio_chip *chip, unsigned offset)
{
	struct cp2112_device *dev = gpiochip_get_data(chip);
	struct hid_device *hdev = dev->hdev;
	u8 *buf = dev->in_out_buffer;
	unsigned long flags;
	int ret;

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -168,7 +168,7 @@
 	atomic_t xfer_avail;
 	struct gpio_chip gc;
 	u8 *in_out_buffer;
-	spinlock_t lock;
+	struct mutex lock;
 
 	struct gpio_desc *desc[8];
 	bool gpio_poll;
@@ -186,10 +186,9 @@
 	struct cp2112_device *dev = gpiochip_get_data(chip);
 	struct hid_device *hdev = dev->hdev;
 	u8 *buf = dev->in_out_buffer;
-	unsigned long flags;
-	int ret;
-
-	spin_lock_irqsave(&dev->lock, flags);
+	int ret;
+
+	mutex_lock(&dev->lock);
 
 	ret = hid_hw_raw_request(hdev, CP2112_GPIO_CONFIG, buf,
 				 CP2112_GPIO_CONFIG_LENGTH, HID_FEATURE_REPORT,
@@ -213,7 +212,7 @@
 	ret = 0;
 
 exit:
-	spin_unlock_irqrestore(&dev->lock, flags);
+	mutex_unlock(&dev->lock);
 	return ret <= 0 ? ret : -EIO;
 }
 
@@ -222,10 +221,9 @@
 	struct cp2112_device *dev = gpiochip_get_data(chip);
 	struct hid_device *hdev = dev->hdev;
 	u8 *buf = dev->in_out_buffer;
-	unsigned long flags;
-	int ret;
-
-	spin_lock_irqsave(&dev->lock, flags);
+	int ret;
+
+	mutex_lock(&dev->lock);
 
 	buf[0] = CP2112_GPIO_SET;
 	buf[1] = value ? 0xff : 0;
@@ -237,7 +235,7 @@
 	if (ret < 0)
 		hid_err(hdev, "error setting GPIO values: %d\n", ret);
 
-	spin_unlock_irqrestore(&dev->lock, flags);
+	mutex_unlock(&dev->lock);
 }
 
 static int cp2112_gpio_get_all(struct gpio_chip *chip)
@@ -245,10 +243,9 @@
 	struct cp2112_device *dev = gpiochip_get_data(chip);
 	struct hid_device *hdev = dev->hdev;
 	u8 *buf = dev->in_out_buffer;
-	unsigned long flags;
-	int ret;
-
-	spin_lock_irqsave(&dev->lock, flags);
+	int ret;
+
+	mutex_lock(&dev->lock);
 
 	ret = hid_hw_raw_request(hdev, CP2112_GPIO_GET, buf,
 				 CP2112_GPIO_GET_LENGTH, HID_FEATURE_REPORT,
@@ -262,7 +259,7 @@
 	ret = buf[1];
 
 exit:
-	spin_unlock_irqrestore(&dev->lock, flags);
+	mutex_unlock(&dev->lock);
 
 	return ret;
 }
@@ -284,10 +281,9 @@
 	struct cp2112_device *dev = gpiochip_get_data(chip);
 	struct hid_device *hdev = dev->hdev;
 	u8 *buf = dev->in_out_buffer;
-	unsigned long flags;
-	int ret;
-
-	spin_lock_irqsave(&dev->lock, flags);
+	int ret;
+
+	mutex_lock(&dev->lock);
 
 	ret = hid_hw_raw_request(hdev, CP2112_GPIO_CONFIG, buf,
 				 CP2112_GPIO_CONFIG_LENGTH, HID_FEATURE_REPORT,
@@ -308,7 +304,7 @@
 		goto fail;
 	}
 
-	spin_unlock_irqrestore(&dev->lock, flags);
+	mutex_unlock(&dev->lock);
 
 	/*
 	 * Set gpio value when output direction is already set,
@@ -319,7 +315,7 @@
 	return 0;
 
 fail:
-	spin_unlock_irqrestore(&dev->lock, flags);
+	mutex_unlock(&dev->lock);
 	return ret < 0 ? ret : -EIO;
 }
 
@@ -1235,7 +1231,7 @@
 	if (!dev->in_out_buffer)
 		return -ENOMEM;
 
-	spin_lock_init(&dev->lock);
+	mutex_init(&dev->lock);
 
 	ret = hid_parse(hdev);
 	if (ret) {
```
