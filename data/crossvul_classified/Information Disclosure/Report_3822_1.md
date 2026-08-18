# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in c
**Pair ID:** 3822_1
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3822_1`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```c
Lines 106-146 of the vulnerable file.


static inline int verify_sec_ctx_len(struct nlattr **attrs)
{
	struct nlattr *rt = attrs[XFRMA_SEC_CTX];
	struct xfrm_user_sec_ctx *uctx;

	if (!rt)
		return 0;

	uctx = nla_data(rt);
	if (uctx->len != (sizeof(struct xfrm_user_sec_ctx) + uctx->ctx_len))
		return -EINVAL;

	return 0;
}

static inline int verify_replay(struct xfrm_usersa_info *p,
				struct nlattr **attrs)
{
	struct nlattr *rt = attrs[XFRMA_REPLAY_ESN_VAL];

	if ((p->flags & XFRM_STATE_ESN) && !rt)
		return -EINVAL;

	if (!rt)
		return 0;

	if (p->id.proto != IPPROTO_ESP)
		return -EINVAL;

	if (p->replay_window != 0)
		return -EINVAL;

	return 0;
}

static int verify_newsa_info(struct xfrm_usersa_info *p,
			     struct nlattr **attrs)
{
	int err;

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -123,9 +123,21 @@
 				struct nlattr **attrs)
 {
 	struct nlattr *rt = attrs[XFRMA_REPLAY_ESN_VAL];
-
-	if ((p->flags & XFRM_STATE_ESN) && !rt)
-		return -EINVAL;
+	struct xfrm_replay_state_esn *rs;
+
+	if (p->flags & XFRM_STATE_ESN) {
+		if (!rt)
+			return -EINVAL;
+
+		rs = nla_data(rt);
+
+		if (rs->bmp_len > XFRMA_REPLAY_ESN_MAX / sizeof(rs->bmp[0]) / 8)
+			return -EINVAL;
+
+		if (nla_len(rt) < xfrm_replay_state_esn_len(rs) &&
+		    nla_len(rt) != sizeof(*rs))
+			return -EINVAL;
+	}
 
 	if (!rt)
 		return 0;
@@ -370,14 +382,15 @@
 					 struct nlattr *rp)
 {
 	struct xfrm_replay_state_esn *up;
+	int ulen;
 
 	if (!replay_esn || !rp)
 		return 0;
 
 	up = nla_data(rp);
-
-	if (xfrm_replay_state_esn_len(replay_esn) !=
-			xfrm_replay_state_esn_len(up))
+	ulen = xfrm_replay_state_esn_len(up);
+
+	if (nla_len(rp) < ulen || xfrm_replay_state_esn_len(replay_esn) != ulen)
 		return -EINVAL;
 
 	return 0;
@@ -388,21 +401,27 @@
 				       struct nlattr *rta)
 {
 	struct xfrm_replay_state_esn *p, *pp, *up;
+	int klen, ulen;
 
 	if (!rta)
 		return 0;
 
 	up = nla_data(rta);
-
-	p = kmemdup(up, xfrm_replay_state_esn_len(up), GFP_KERNEL);
+	klen = xfrm_replay_state_esn_len(up);
+	ulen = nla_len(rta) >= klen ? klen : sizeof(*up);
+
+	p = kzalloc(klen, GFP_KERNEL);
 	if (!p)
 		return -ENOMEM;
 
-	pp = kmemdup(up, xfrm_replay_state_esn_len(up), GFP_KERNEL);
+	pp = kzalloc(klen, GFP_KERNEL);
 	if (!pp) {
 		kfree(p);
 		return -ENOMEM;
 	}
+
+	memcpy(p, up, ulen);
+	memcpy(pp, up, ulen);
 
 	*replay_esn = p;
 	*preplay_esn = pp;
```
