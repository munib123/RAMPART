# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 2143_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2143_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 2233-2291 of the vulnerable file.

}

static inline u32 dev_ethtool_get_flags(struct net_device *dev)
{
	if (!dev->ethtool_ops || !dev->ethtool_ops->get_flags)
		return 0;
	return dev->ethtool_ops->get_flags(dev);
}

/* Logging, debugging and troubleshooting/diagnostic helpers. */

/* netdev_printk helpers, similar to dev_printk */

static inline const char *netdev_name(const struct net_device *dev)
{
	if (dev->reg_state != NETREG_REGISTERED)
		return "(unregistered net_device)";
	return dev->name;
}

#define netdev_printk(level, netdev, format, args...)		\
	dev_printk(level, (netdev)->dev.parent,			\
		   "%s: " format,				\
		   netdev_name(netdev), ##args)

#define netdev_emerg(dev, format, args...)			\
	netdev_printk(KERN_EMERG, dev, format, ##args)
#define netdev_alert(dev, format, args...)			\
	netdev_printk(KERN_ALERT, dev, format, ##args)
#define netdev_crit(dev, format, args...)			\
	netdev_printk(KERN_CRIT, dev, format, ##args)
#define netdev_err(dev, format, args...)			\
	netdev_printk(KERN_ERR, dev, format, ##args)
#define netdev_warn(dev, format, args...)			\
	netdev_printk(KERN_WARNING, dev, format, ##args)
#define netdev_notice(dev, format, args...)			\
	netdev_printk(KERN_NOTICE, dev, format, ##args)
#define netdev_info(dev, format, args...)			\
	netdev_printk(KERN_INFO, dev, format, ##args)

#if defined(DEBUG)
#define netdev_dbg(__dev, format, args...)			\
	netdev_printk(KERN_DEBUG, __dev, format, ##args)
#elif defined(CONFIG_DYNAMIC_DEBUG)
#define netdev_dbg(__dev, format, args...)			\
do {								\
	dynamic_dev_dbg((__dev)->dev.parent, "%s: " format,	\
			netdev_name(__dev), ##args);		\
} while (0)
#else
#define netdev_dbg(__dev, format, args...)			\
({								\
	if (0)							\
		netdev_printk(KERN_DEBUG, __dev, format, ##args); \
	0;							\
})
#endif

#if defined(VERBOSE_DEBUG)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2250,25 +2250,23 @@
 	return dev->name;
 }
 
-#define netdev_printk(level, netdev, format, args...)		\
-	dev_printk(level, (netdev)->dev.parent,			\
-		   "%s: " format,				\
-		   netdev_name(netdev), ##args)
-
-#define netdev_emerg(dev, format, args...)			\
-	netdev_printk(KERN_EMERG, dev, format, ##args)
-#define netdev_alert(dev, format, args...)			\
-	netdev_printk(KERN_ALERT, dev, format, ##args)
-#define netdev_crit(dev, format, args...)			\
-	netdev_printk(KERN_CRIT, dev, format, ##args)
-#define netdev_err(dev, format, args...)			\
-	netdev_printk(KERN_ERR, dev, format, ##args)
-#define netdev_warn(dev, format, args...)			\
-	netdev_printk(KERN_WARNING, dev, format, ##args)
-#define netdev_notice(dev, format, args...)			\
-	netdev_printk(KERN_NOTICE, dev, format, ##args)
-#define netdev_info(dev, format, args...)			\
-	netdev_printk(KERN_INFO, dev, format, ##args)
+extern int netdev_printk(const char *level, const struct net_device *dev,
+			 const char *format, ...)
+	__attribute__ ((format (printf, 3, 4)));
+extern int netdev_emerg(const struct net_device *dev, const char *format, ...)
+	__attribute__ ((format (printf, 2, 3)));
+extern int netdev_alert(const struct net_device *dev, const char *format, ...)
+	__attribute__ ((format (printf, 2, 3)));
+extern int netdev_crit(const struct net_device *dev, const char *format, ...)
+	__attribute__ ((format (printf, 2, 3)));
+extern int netdev_err(const struct net_device *dev, const char *format, ...)
+	__attribute__ ((format (printf, 2, 3)));
+extern int netdev_warn(const struct net_device *dev, const char *format, ...)
+	__attribute__ ((format (printf, 2, 3)));
+extern int netdev_notice(const struct net_device *dev, const char *format, ...)
+	__attribute__ ((format (printf, 2, 3)));
+extern int netdev_info(const struct net_device *dev, const char *format, ...)
+	__attribute__ ((format (printf, 2, 3)));
 
 #if defined(DEBUG)
 #define netdev_dbg(__dev, format, args...)			\
```
