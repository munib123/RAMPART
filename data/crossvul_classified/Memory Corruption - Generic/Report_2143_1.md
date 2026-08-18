# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 2143_1
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2143_1`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 5785-5825 of the vulnerable file.

char *netdev_drivername(const struct net_device *dev, char *buffer, int len)
{
	const struct device_driver *driver;
	const struct device *parent;

	if (len <= 0 || !buffer)
		return buffer;
	buffer[0] = 0;

	parent = dev->dev.parent;

	if (!parent)
		return buffer;

	driver = parent->driver;
	if (driver && driver->name)
		strlcpy(buffer, driver->name, len);
	return buffer;
}

static void __net_exit netdev_exit(struct net *net)
{
	kfree(net->dev_name_head);
	kfree(net->dev_index_head);
}

static struct pernet_operations __net_initdata netdev_net_ops = {
	.init = netdev_init,
	.exit = netdev_exit,
};

static void __net_exit default_device_exit(struct net *net)
{
	struct net_device *dev, *aux;
	/*
	 * Push all migratable network devices back to the
	 * initial network namespace
	 */
	rtnl_lock();
	for_each_netdev_safe(net, dev, aux) {
		int err;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -5802,6 +5802,68 @@
 	return buffer;
 }
 
+static int __netdev_printk(const char *level, const struct net_device *dev,
+			   struct va_format *vaf)
+{
+	int r;
+
+	if (dev && dev->dev.parent)
+		r = dev_printk(level, dev->dev.parent, "%s: %pV",
+			       netdev_name(dev), vaf);
+	else if (dev)
+		r = printk("%s%s: %pV", level, netdev_name(dev), vaf);
+	else
+		r = printk("%s(NULL net_device): %pV", level, vaf);
+
+	return r;
+}
+
+int netdev_printk(const char *level, const struct net_device *dev,
+		  const char *format, ...)
+{
+	struct va_format vaf;
+	va_list args;
+	int r;
+
+	va_start(args, format);
+
+	vaf.fmt = format;
+	vaf.va = &args;
+
+	r = __netdev_printk(level, dev, &vaf);
+	va_end(args);
+
+	return r;
+}
+EXPORT_SYMBOL(netdev_printk);
+
+#define define_netdev_printk_level(func, level)			\
+int func(const struct net_device *dev, const char *fmt, ...)	\
+{								\
+	int r;							\
+	struct va_format vaf;					\
+	va_list args;						\
+								\
+	va_start(args, fmt);					\
+								\
+	vaf.fmt = fmt;						\
+	vaf.va = &args;						\
+								\
+	r = __netdev_printk(level, dev, &vaf);			\
+	va_end(args);						\
+								\
+	return r;						\
+}								\
+EXPORT_SYMBOL(func);
+
+define_netdev_printk_level(netdev_emerg, KERN_EMERG);
+define_netdev_printk_level(netdev_alert, KERN_ALERT);
+define_netdev_printk_level(netdev_crit, KERN_CRIT);
+define_netdev_printk_level(netdev_err, KERN_ERR);
+define_netdev_printk_level(netdev_warn, KERN_WARNING);
+define_netdev_printk_level(netdev_notice, KERN_NOTICE);
+define_netdev_printk_level(netdev_info, KERN_INFO);
+
 static void __net_exit netdev_exit(struct net *net)
 {
 	kfree(net->dev_name_head);
```
