# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in c
**Pair ID:** 506_0
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `506_0`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```c
Lines 266-307 of the vulnerable file.


static int ipddp_ioctl(struct net_device *dev, struct ifreq *ifr, int cmd)
{
        struct ipddp_route __user *rt = ifr->ifr_data;
        struct ipddp_route rcp, rcp2, *rp;

        if(!capable(CAP_NET_ADMIN))
                return -EPERM;

	if(copy_from_user(&rcp, rt, sizeof(rcp)))
		return -EFAULT;

        switch(cmd)
        {
		case SIOCADDIPDDPRT:
                        return ipddp_create(&rcp);

                case SIOCFINDIPDDPRT:
			spin_lock_bh(&ipddp_route_lock);
			rp = __ipddp_find_route(&rcp);
			if (rp)
				memcpy(&rcp2, rp, sizeof(rcp2));
			spin_unlock_bh(&ipddp_route_lock);

			if (rp) {
				if (copy_to_user(rt, &rcp2,
						 sizeof(struct ipddp_route)))
					return -EFAULT;
				return 0;
			} else
				return -ENOENT;

                case SIOCDELIPDDPRT:
                        return ipddp_delete(&rcp);

                default:
                        return -EINVAL;
        }
}

static struct net_device *dev_ipddp;

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -283,8 +283,12 @@
                 case SIOCFINDIPDDPRT:
 			spin_lock_bh(&ipddp_route_lock);
 			rp = __ipddp_find_route(&rcp);
-			if (rp)
-				memcpy(&rcp2, rp, sizeof(rcp2));
+			if (rp) {
+				memset(&rcp2, 0, sizeof(rcp2));
+				rcp2.ip    = rp->ip;
+				rcp2.at    = rp->at;
+				rcp2.flags = rp->flags;
+			}
 			spin_unlock_bh(&ipddp_route_lock);
 
 			if (rp) {
```
