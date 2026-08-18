# CrossVul Fix Pair: Data Processing Errors in c
**Pair ID:** 1487_0
**Vulnerability Class:** Data Processing Errors
**CWE:** CWE-19
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1487_0`)

## Vulnerability Information & PoC

## Description
Data Processing Errors

## Vulnerable Code
```c
Lines 696-736 of the vulnerable file.

	INIT_LIST_HEAD(&table->sets);
	table->flags = flags;

	nft_ctx_init(&ctx, skb, nlh, afi, table, NULL, nla);
	err = nft_trans_table_add(&ctx, NFT_MSG_NEWTABLE);
	if (err < 0) {
		kfree(table);
		module_put(afi->owner);
		return err;
	}
	list_add_tail_rcu(&table->list, &afi->tables);
	return 0;
}

static int nft_flush_table(struct nft_ctx *ctx)
{
	int err;
	struct nft_chain *chain, *nc;
	struct nft_set *set, *ns;

	list_for_each_entry_safe(chain, nc, &ctx->table->chains, list) {
		ctx->chain = chain;

		err = nft_delrule_by_chain(ctx);
		if (err < 0)
			goto out;

		err = nft_delchain(ctx);
		if (err < 0)
			goto out;
	}

	list_for_each_entry_safe(set, ns, &ctx->table->sets, list) {
		if (set->flags & NFT_SET_ANONYMOUS &&
		    !list_empty(&set->bindings))
			continue;

		err = nft_delset(ctx, set);
		if (err < 0)
			goto out;
	}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -713,14 +713,10 @@
 	struct nft_chain *chain, *nc;
 	struct nft_set *set, *ns;
 
-	list_for_each_entry_safe(chain, nc, &ctx->table->chains, list) {
+	list_for_each_entry(chain, &ctx->table->chains, list) {
 		ctx->chain = chain;
 
 		err = nft_delrule_by_chain(ctx);
-		if (err < 0)
-			goto out;
-
-		err = nft_delchain(ctx);
 		if (err < 0)
 			goto out;
 	}
@@ -731,6 +727,14 @@
 			continue;
 
 		err = nft_delset(ctx, set);
+		if (err < 0)
+			goto out;
+	}
+
+	list_for_each_entry_safe(chain, nc, &ctx->table->chains, list) {
+		ctx->chain = chain;
+
+		err = nft_delchain(ctx);
 		if (err < 0)
 			goto out;
 	}
```
