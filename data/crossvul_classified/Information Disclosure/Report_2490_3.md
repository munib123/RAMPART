# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in c
**Pair ID:** 2490_3
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2490_3`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```c
Lines 1326-1366 of the vulnerable file.

  /* XXXXipv6 */
  if (node->rs)
    tor_addr_from_ipv4h(&addr, node->rs->addr);
  else if (node->ri)
    tor_addr_from_ipv4h(&addr, node->ri->addr);

  node->country = geoip_get_country_by_addr(&addr);
}

/** Set the country code of all routers in the routerlist. */
void
nodelist_refresh_countries(void)
{
  smartlist_t *nodes = nodelist_get_list();
  SMARTLIST_FOREACH(nodes, node_t *, node,
                    node_set_country(node));
}

/** Return true iff router1 and router2 have similar enough network addresses
 * that we should treat them as being in the same family */
static inline int
addrs_in_same_network_family(const tor_addr_t *a1,
                             const tor_addr_t *a2)
{
  return 0 == tor_addr_compare_masked(a1, a2, 16, CMP_SEMANTIC);
}

/** Return true if <b>node</b>'s nickname matches <b>nickname</b>
 * (case-insensitive), or if <b>node's</b> identity key digest
 * matches a hexadecimal value stored in <b>nickname</b>.  Return
 * false otherwise. */
static int
node_nickname_matches(const node_t *node, const char *nickname)
{
  const char *n = node_get_nickname(node);
  if (n && nickname[0]!='$' && !strcasecmp(n, nickname))
    return 1;
  return hex_digest_nickname_matches(nickname,
                                     node->identity,
                                     n,
                                     node_is_named(node));
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1343,7 +1343,7 @@
 
 /** Return true iff router1 and router2 have similar enough network addresses
  * that we should treat them as being in the same family */
-static inline int
+int
 addrs_in_same_network_family(const tor_addr_t *a1,
                              const tor_addr_t *a2)
 {
```
