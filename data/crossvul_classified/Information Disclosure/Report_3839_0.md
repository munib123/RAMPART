# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in c
**Pair ID:** 3839_0
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3839_0`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```c
Lines 795-835 of the vulnerable file.

		return -EFAULT;
	if (__SO_LEVEL_MATCH(optname, level) && len != __SO_SIZE(optname))
		return -EINVAL;

	vcc = ATM_SD(sock);
	switch (optname) {
	case SO_ATMQOS:
		if (!test_bit(ATM_VF_HASQOS, &vcc->flags))
			return -EINVAL;
		return copy_to_user(optval, &vcc->qos, sizeof(vcc->qos))
			? -EFAULT : 0;
	case SO_SETCLP:
		return put_user(vcc->atm_options & ATM_ATMOPT_CLP ? 1 : 0,
				(unsigned long __user *)optval) ? -EFAULT : 0;
	case SO_ATMPVC:
	{
		struct sockaddr_atmpvc pvc;

		if (!vcc->dev || !test_bit(ATM_VF_ADDR, &vcc->flags))
			return -ENOTCONN;
		pvc.sap_family = AF_ATMPVC;
		pvc.sap_addr.itf = vcc->dev->number;
		pvc.sap_addr.vpi = vcc->vpi;
		pvc.sap_addr.vci = vcc->vci;
		return copy_to_user(optval, &pvc, sizeof(pvc)) ? -EFAULT : 0;
	}
	default:
		if (level == SOL_SOCKET)
			return -EINVAL;
		break;
	}
	if (!vcc->dev || !vcc->dev->ops->getsockopt)
		return -EINVAL;
	return vcc->dev->ops->getsockopt(vcc, level, optname, optval, len);
}

int register_atmdevice_notifier(struct notifier_block *nb)
{
	return atomic_notifier_chain_register(&atm_dev_notify_chain, nb);
}
EXPORT_SYMBOL_GPL(register_atmdevice_notifier);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -812,6 +812,7 @@
 
 		if (!vcc->dev || !test_bit(ATM_VF_ADDR, &vcc->flags))
 			return -ENOTCONN;
+		memset(&pvc, 0, sizeof(pvc));
 		pvc.sap_family = AF_ATMPVC;
 		pvc.sap_addr.itf = vcc->dev->number;
 		pvc.sap_addr.vpi = vcc->vpi;
```
