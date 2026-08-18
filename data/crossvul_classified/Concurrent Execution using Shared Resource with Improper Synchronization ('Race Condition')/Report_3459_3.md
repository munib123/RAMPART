# CrossVul Fix Pair: Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') in c
**Pair ID:** 3459_3
**Vulnerability Class:** Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')
**CWE:** CWE-362
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3459_3`)

## Vulnerability Information & PoC

## Description
Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') - This can have security implications when the expected synchronization is in security-critical code, such as recording whether a user is authenticated or modifying important state information that s...

## Vulnerable Code
```c
Lines 65-121 of the vulnerable file.


static DEFINE_SPINLOCK(xfrm6_tunnel_spi_lock);

static struct kmem_cache *xfrm6_tunnel_spi_kmem __read_mostly;

static inline unsigned xfrm6_tunnel_spi_hash_byaddr(xfrm_address_t *addr)
{
	unsigned h;

	h = (__force u32)(addr->a6[0] ^ addr->a6[1] ^ addr->a6[2] ^ addr->a6[3]);
	h ^= h >> 16;
	h ^= h >> 8;
	h &= XFRM6_TUNNEL_SPI_BYADDR_HSIZE - 1;

	return h;
}

static inline unsigned xfrm6_tunnel_spi_hash_byspi(u32 spi)
{
	return spi % XFRM6_TUNNEL_SPI_BYSPI_HSIZE;
}


static int __init xfrm6_tunnel_spi_init(void)
{
	xfrm6_tunnel_spi_kmem = kmem_cache_create("xfrm6_tunnel_spi",
						  sizeof(struct xfrm6_tunnel_spi),
						  0, SLAB_HWCACHE_ALIGN,
						  NULL);
	if (!xfrm6_tunnel_spi_kmem)
		return -ENOMEM;
	return 0;
}

static void xfrm6_tunnel_spi_fini(void)
{
	kmem_cache_destroy(xfrm6_tunnel_spi_kmem);
}

static struct xfrm6_tunnel_spi *__xfrm6_tunnel_spi_lookup(struct net *net, xfrm_address_t *saddr)
{
	struct xfrm6_tunnel_net *xfrm6_tn = xfrm6_tunnel_pernet(net);
	struct xfrm6_tunnel_spi *x6spi;
	struct hlist_node *pos;

	hlist_for_each_entry_rcu(x6spi, pos,
			     &xfrm6_tn->spi_byaddr[xfrm6_tunnel_spi_hash_byaddr(saddr)],
			     list_byaddr) {
		if (memcmp(&x6spi->addr, saddr, sizeof(x6spi->addr)) == 0)
			return x6spi;
	}

	return NULL;
}

__be32 xfrm6_tunnel_spi_lookup(struct net *net, xfrm_address_t *saddr)
{
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -82,23 +82,6 @@
 static inline unsigned xfrm6_tunnel_spi_hash_byspi(u32 spi)
 {
 	return spi % XFRM6_TUNNEL_SPI_BYSPI_HSIZE;
-}
-
-
-static int __init xfrm6_tunnel_spi_init(void)
-{
-	xfrm6_tunnel_spi_kmem = kmem_cache_create("xfrm6_tunnel_spi",
-						  sizeof(struct xfrm6_tunnel_spi),
-						  0, SLAB_HWCACHE_ALIGN,
-						  NULL);
-	if (!xfrm6_tunnel_spi_kmem)
-		return -ENOMEM;
-	return 0;
-}
-
-static void xfrm6_tunnel_spi_fini(void)
-{
-	kmem_cache_destroy(xfrm6_tunnel_spi_kmem);
 }
 
 static struct xfrm6_tunnel_spi *__xfrm6_tunnel_spi_lookup(struct net *net, xfrm_address_t *saddr)
@@ -375,42 +358,44 @@
 {
 	int rv;
 
+	xfrm6_tunnel_spi_kmem = kmem_cache_create("xfrm6_tunnel_spi",
+						  sizeof(struct xfrm6_tunnel_spi),
+						  0, SLAB_HWCACHE_ALIGN,
+						  NULL);
+	if (!xfrm6_tunnel_spi_kmem)
+		return -ENOMEM;
+	rv = register_pernet_subsys(&xfrm6_tunnel_net_ops);
+	if (rv < 0)
+		goto out_pernet;
 	rv = xfrm_register_type(&xfrm6_tunnel_type, AF_INET6);
 	if (rv < 0)
-		goto err;
+		goto out_type;
 	rv = xfrm6_tunnel_register(&xfrm6_tunnel_handler, AF_INET6);
 	if (rv < 0)
-		goto unreg;
+		goto out_xfrm6;
 	rv = xfrm6_tunnel_register(&xfrm46_tunnel_handler, AF_INET);
 	if (rv < 0)
-		goto dereg6;
-	rv = xfrm6_tunnel_spi_init();
-	if (rv < 0)
-		goto dereg46;
-	rv = register_pernet_subsys(&xfrm6_tunnel_net_ops);
-	if (rv < 0)
-		goto deregspi;
+		goto out_xfrm46;
 	return 0;
 
-deregspi:
-	xfrm6_tunnel_spi_fini();
-dereg46:
-	xfrm6_tunnel_deregister(&xfrm46_tunnel_handler, AF_INET);
-dereg6:
+out_xfrm46:
 	xfrm6_tunnel_deregister(&xfrm6_tunnel_handler, AF_INET6);
-unreg:
+out_xfrm6:
 	xfrm_unregister_type(&xfrm6_tunnel_type, AF_INET6);
-err:
+out_type:
+	unregister_pernet_subsys(&xfrm6_tunnel_net_ops);
+out_pernet:
+	kmem_cache_destroy(xfrm6_tunnel_spi_kmem);
 	return rv;
 }
 
 static void __exit xfrm6_tunnel_fini(void)
 {
-	unregister_pernet_subsys(&xfrm6_tunnel_net_ops);
-	xfrm6_tunnel_spi_fini();
 	xfrm6_tunnel_deregister(&xfrm46_tunnel_handler, AF_INET);
 	xfrm6_tunnel_deregister(&xfrm6_tunnel_handler, AF_INET6);
 	xfrm_unregister_type(&xfrm6_tunnel_type, AF_INET6);
+	unregister_pernet_subsys(&xfrm6_tunnel_net_ops);
+	kmem_cache_destroy(xfrm6_tunnel_spi_kmem);
 }
 
 module_init(xfrm6_tunnel_init);
```
