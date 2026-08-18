# CrossVul Fix Pair: Use After Free in c
**Pair ID:** 3269_0
**Vulnerability Class:** Use After Free
**CWE:** CWE-416
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3269_0`)

## Vulnerability Information & PoC

## Description
Use After Free - The use of previously-freed memory can have any number of adverse consequences, ranging from the corruption of valid data to the execution of arbitrary code, depending on the instantiation and timi...

## Vulnerable Code
```c
Lines 1151-1191 of the vulnerable file.

		struct net_device *dev;

		rc = -EFAULT;
		if (copy_from_user(&ifr, arg, sizeof(ifr)))
			break;
		sipx = (struct sockaddr_ipx *)&ifr.ifr_addr;
		dev  = __dev_get_by_name(&init_net, ifr.ifr_name);
		rc   = -ENODEV;
		if (!dev)
			break;
		ipxif = ipxitf_find_using_phys(dev,
					   ipx_map_frame_type(sipx->sipx_type));
		rc = -EADDRNOTAVAIL;
		if (!ipxif)
			break;

		sipx->sipx_family	= AF_IPX;
		sipx->sipx_network	= ipxif->if_netnum;
		memcpy(sipx->sipx_node, ipxif->if_node,
			sizeof(sipx->sipx_node));
		rc = -EFAULT;
		if (copy_to_user(arg, &ifr, sizeof(ifr)))
			break;
		ipxitf_put(ipxif);
		rc = 0;
		break;
	}
	case SIOCAIPXITFCRT:
		rc = -EFAULT;
		if (get_user(val, (unsigned char __user *) arg))
			break;
		rc = 0;
		ipxcfg_auto_create_interfaces = val;
		break;
	case SIOCAIPXPRISLT:
		rc = -EFAULT;
		if (get_user(val, (unsigned char __user *) arg))
			break;
		rc = 0;
		ipxcfg_set_auto_select(val);
		break;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1168,11 +1168,10 @@
 		sipx->sipx_network	= ipxif->if_netnum;
 		memcpy(sipx->sipx_node, ipxif->if_node,
 			sizeof(sipx->sipx_node));
-		rc = -EFAULT;
+		rc = 0;
 		if (copy_to_user(arg, &ifr, sizeof(ifr)))
-			break;
+			rc = -EFAULT;
 		ipxitf_put(ipxif);
-		rc = 0;
 		break;
 	}
 	case SIOCAIPXITFCRT:
```
