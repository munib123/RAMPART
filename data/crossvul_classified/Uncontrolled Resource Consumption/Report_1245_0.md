# CrossVul Fix Pair: Uncontrolled Resource Consumption in c
**Pair ID:** 1245_0
**Vulnerability Class:** Uncontrolled Resource Consumption
**CWE:** CWE-400
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1245_0`)

## Vulnerability Information & PoC

## Description
Uncontrolled Resource Consumption - Limited resources include memory, file system storage, database connection pool entries, and CPU.

## Vulnerable Code
```c
Lines 13665-13705 of the vulnerable file.

	struct nlattr *ftm_stats_attr;
	int err;

	if (wdev->iftype != NL80211_IFTYPE_AP || !wdev->beacon_interval)
		return -EOPNOTSUPP;

	err = rdev_get_ftm_responder_stats(rdev, dev, &ftm_stats);
	if (err)
		return err;

	if (!ftm_stats.filled)
		return -ENODATA;

	msg = nlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);
	if (!msg)
		return -ENOMEM;

	hdr = nl80211hdr_put(msg, info->snd_portid, info->snd_seq, 0,
			     NL80211_CMD_GET_FTM_RESPONDER_STATS);
	if (!hdr)
		return -ENOBUFS;

	if (nla_put_u32(msg, NL80211_ATTR_IFINDEX, dev->ifindex))
		goto nla_put_failure;

	ftm_stats_attr = nla_nest_start_noflag(msg,
					       NL80211_ATTR_FTM_RESPONDER_STATS);
	if (!ftm_stats_attr)
		goto nla_put_failure;

#define SET_FTM(field, name, type)					 \
	do { if ((ftm_stats.filled & BIT(NL80211_FTM_STATS_ ## name)) && \
	    nla_put_ ## type(msg, NL80211_FTM_STATS_ ## name,		 \
			     ftm_stats.field))				 \
		goto nla_put_failure; } while (0)
#define SET_FTM_U64(field, name)					 \
	do { if ((ftm_stats.filled & BIT(NL80211_FTM_STATS_ ## name)) && \
	    nla_put_u64_64bit(msg, NL80211_FTM_STATS_ ## name,		 \
			      ftm_stats.field, NL80211_FTM_STATS_PAD))	 \
		goto nla_put_failure; } while (0)

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -13682,7 +13682,7 @@
 	hdr = nl80211hdr_put(msg, info->snd_portid, info->snd_seq, 0,
 			     NL80211_CMD_GET_FTM_RESPONDER_STATS);
 	if (!hdr)
-		return -ENOBUFS;
+		goto nla_put_failure;
 
 	if (nla_put_u32(msg, NL80211_ATTR_IFINDEX, dev->ifindex))
 		goto nla_put_failure;
```
