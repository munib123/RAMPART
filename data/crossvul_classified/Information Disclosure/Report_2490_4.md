# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in c
**Pair ID:** 2490_4
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2490_4`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```c
Lines 77-117 of the vulnerable file.

int node_has_curve25519_onion_key(const node_t *node);

MOCK_DECL(smartlist_t *, nodelist_get_list, (void));

/* Temporary during transition to multiple addresses.  */
void node_get_addr(const node_t *node, tor_addr_t *addr_out);
#define node_get_addr_ipv4h(n) node_get_prim_addr_ipv4h((n))

void nodelist_refresh_countries(void);
void node_set_country(node_t *node);
void nodelist_add_node_and_family(smartlist_t *nodes, const node_t *node);
int nodes_in_same_family(const node_t *node1, const node_t *node2);

const node_t *router_find_exact_exit_enclave(const char *address,
                                             uint16_t port);
int node_is_unreliable(const node_t *router, int need_uptime,
                         int need_capacity, int need_guard);
int router_exit_policy_all_nodes_reject(const tor_addr_t *addr, uint16_t port,
                                        int need_uptime);
void router_set_status(const char *digest, int up);

/** router_have_minimum_dir_info tests to see if we have enough
 * descriptor information to create circuits.
 * If there are exits in the consensus, we wait until we have enough
 * info to create exit paths before creating any circuits. If there are
 * no exits in the consensus, we wait for enough info to create internal
 * paths, and should avoid creating exit paths, as they will simply fail.
 * We make sure we create all available circuit types at the same time. */
int router_have_minimum_dir_info(void);

/** Set to CONSENSUS_PATH_EXIT if there is at least one exit node
 * in the consensus. We update this flag in compute_frac_paths_available if
 * there is at least one relay that has an Exit flag in the consensus.
 * Used to avoid building exit circuits when they will almost certainly fail.
 * Set to CONSENSUS_PATH_INTERNAL if there are no exits in the consensus.
 * (This situation typically occurs during bootstrap of a test network.)
 * Set to CONSENSUS_PATH_UNKNOWN if we have never checked, or have
 * reason to believe our last known value was invalid or has expired.
 */
typedef enum {
  /* we haven't checked yet, or we have invalidated our previous check */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -94,6 +94,8 @@
 int router_exit_policy_all_nodes_reject(const tor_addr_t *addr, uint16_t port,
                                         int need_uptime);
 void router_set_status(const char *digest, int up);
+int addrs_in_same_network_family(const tor_addr_t *a1,
+                                 const tor_addr_t *a2);
 
 /** router_have_minimum_dir_info tests to see if we have enough
  * descriptor information to create circuits.
```
