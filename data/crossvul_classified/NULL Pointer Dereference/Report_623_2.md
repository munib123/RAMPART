# CrossVul Fix Pair: NULL Pointer Dereference in c
**Pair ID:** 623_2
**Vulnerability Class:** NULL Pointer Dereference
**CWE:** CWE-476
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `623_2`)

## Vulnerability Information & PoC

## Description
NULL Pointer Dereference - NULL pointer dereference issues can occur through a number of flaws, including race conditions, and simple programming omissions.

## Vulnerable Code
```c
Lines 1130-1172 of the vulnerable file.

	ret = __dev_alloc_name(net, name, buf);
	if (ret >= 0)
		strlcpy(dev->name, buf, IFNAMSIZ);
	return ret;
}
EXPORT_SYMBOL(dev_alloc_name);

static int dev_alloc_name_ns(struct net *net,
			     struct net_device *dev,
			     const char *name)
{
	char buf[IFNAMSIZ];
	int ret;

	ret = __dev_alloc_name(net, name, buf);
	if (ret >= 0)
		strlcpy(dev->name, buf, IFNAMSIZ);
	return ret;
}

static int dev_get_valid_name(struct net *net,
			      struct net_device *dev,
			      const char *name)
{
	BUG_ON(!net);

	if (!dev_valid_name(name))
		return -EINVAL;

	if (strchr(name, '%'))
		return dev_alloc_name_ns(net, dev, name);
	else if (__dev_get_by_name(net, name))
		return -EEXIST;
	else if (dev->name != name)
		strlcpy(dev->name, name, IFNAMSIZ);

	return 0;
}

/**
 *	dev_change_name - change name of a device
 *	@dev: device
 *	@newname: name (or format string) must be at least IFNAMSIZ
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1147,9 +1147,8 @@
 	return ret;
 }
 
-static int dev_get_valid_name(struct net *net,
-			      struct net_device *dev,
-			      const char *name)
+int dev_get_valid_name(struct net *net, struct net_device *dev,
+		       const char *name)
 {
 	BUG_ON(!net);
 
@@ -1165,6 +1164,7 @@
 
 	return 0;
 }
+EXPORT_SYMBOL(dev_get_valid_name);
 
 /**
  *	dev_change_name - change name of a device
```
