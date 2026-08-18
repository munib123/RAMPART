# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in c
**Pair ID:** 5098_0
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5098_0`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```c
Lines 587-627 of the vulnerable file.

	return 0;
}

static int tipc_nl_compat_link_dump(struct tipc_nl_compat_msg *msg,
				    struct nlattr **attrs)
{
	struct nlattr *link[TIPC_NLA_LINK_MAX + 1];
	struct tipc_link_info link_info;
	int err;

	if (!attrs[TIPC_NLA_LINK])
		return -EINVAL;

	err = nla_parse_nested(link, TIPC_NLA_LINK_MAX, attrs[TIPC_NLA_LINK],
			       NULL);
	if (err)
		return err;

	link_info.dest = nla_get_flag(link[TIPC_NLA_LINK_DEST]);
	link_info.up = htonl(nla_get_flag(link[TIPC_NLA_LINK_UP]));
	strcpy(link_info.str, nla_data(link[TIPC_NLA_LINK_NAME]));

	return tipc_add_tlv(msg->rep, TIPC_TLV_LINK_INFO,
			    &link_info, sizeof(link_info));
}

static int __tipc_add_link_prop(struct sk_buff *skb,
				struct tipc_nl_compat_msg *msg,
				struct tipc_link_config *lc)
{
	switch (msg->cmd) {
	case TIPC_CMD_SET_LINK_PRI:
		return nla_put_u32(skb, TIPC_NLA_PROP_PRIO, ntohl(lc->value));
	case TIPC_CMD_SET_LINK_TOL:
		return nla_put_u32(skb, TIPC_NLA_PROP_TOL, ntohl(lc->value));
	case TIPC_CMD_SET_LINK_WINDOW:
		return nla_put_u32(skb, TIPC_NLA_PROP_WIN, ntohl(lc->value));
	}

	return -EINVAL;
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -604,7 +604,8 @@
 
 	link_info.dest = nla_get_flag(link[TIPC_NLA_LINK_DEST]);
 	link_info.up = htonl(nla_get_flag(link[TIPC_NLA_LINK_UP]));
-	strcpy(link_info.str, nla_data(link[TIPC_NLA_LINK_NAME]));
+	nla_strlcpy(link_info.str, nla_data(link[TIPC_NLA_LINK_NAME]),
+		    TIPC_MAX_LINK_NAME);
 
 	return tipc_add_tlv(msg->rep, TIPC_TLV_LINK_INFO,
 			    &link_info, sizeof(link_info));
```
