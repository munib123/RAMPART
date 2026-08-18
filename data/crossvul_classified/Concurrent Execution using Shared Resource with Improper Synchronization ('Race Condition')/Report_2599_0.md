# CrossVul Fix Pair: Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') in c
**Pair ID:** 2599_0
**Vulnerability Class:** Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')
**CWE:** CWE-362
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2599_0`)

## Vulnerability Information & PoC

## Description
Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') - This can have security implications when the expected synchronization is in security-critical code, such as recording whether a user is authenticated or modifying important state information that s...

## Vulnerable Code
```c
Lines 849-889 of the vulnerable file.


	len = of_device_modalias(dev, buf, PAGE_SIZE);
	if (len != -ENODEV)
		return len;

	len = acpi_device_modalias(dev, buf, PAGE_SIZE -1);
	if (len != -ENODEV)
		return len;

	len = snprintf(buf, PAGE_SIZE, "platform:%s\n", pdev->name);

	return (len >= PAGE_SIZE) ? (PAGE_SIZE - 1) : len;
}
static DEVICE_ATTR_RO(modalias);

static ssize_t driver_override_store(struct device *dev,
				     struct device_attribute *attr,
				     const char *buf, size_t count)
{
	struct platform_device *pdev = to_platform_device(dev);
	char *driver_override, *old = pdev->driver_override, *cp;

	if (count > PATH_MAX)
		return -EINVAL;

	driver_override = kstrndup(buf, count, GFP_KERNEL);
	if (!driver_override)
		return -ENOMEM;

	cp = strchr(driver_override, '\n');
	if (cp)
		*cp = '\0';

	if (strlen(driver_override)) {
		pdev->driver_override = driver_override;
	} else {
		kfree(driver_override);
		pdev->driver_override = NULL;
	}

	kfree(old);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -866,7 +866,7 @@
 				     const char *buf, size_t count)
 {
 	struct platform_device *pdev = to_platform_device(dev);
-	char *driver_override, *old = pdev->driver_override, *cp;
+	char *driver_override, *old, *cp;
 
 	if (count > PATH_MAX)
 		return -EINVAL;
@@ -879,12 +879,15 @@
 	if (cp)
 		*cp = '\0';
 
+	device_lock(dev);
+	old = pdev->driver_override;
 	if (strlen(driver_override)) {
 		pdev->driver_override = driver_override;
 	} else {
 		kfree(driver_override);
 		pdev->driver_override = NULL;
 	}
+	device_unlock(dev);
 
 	kfree(old);
 
@@ -895,8 +898,12 @@
 				    struct device_attribute *attr, char *buf)
 {
 	struct platform_device *pdev = to_platform_device(dev);
-
-	return sprintf(buf, "%s\n", pdev->driver_override);
+	ssize_t len;
+
+	device_lock(dev);
+	len = sprintf(buf, "%s\n", pdev->driver_override);
+	device_unlock(dev);
+	return len;
 }
 static DEVICE_ATTR_RW(driver_override);
 
```
