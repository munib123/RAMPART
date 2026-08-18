# CrossVul Fix Pair: Reachable Assertion in c
**Pair ID:** 390_0
**Vulnerability Class:** Reachable Assertion
**CWE:** CWE-617
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `390_0`)

## Vulnerability Information & PoC

## Description
Reachable Assertion - While assertion is good for catching logic errors and reducing the chances of reaching more serious vulnerability conditions, it can still lead to a denial of service.

## Vulnerable Code
```c
Lines 8466-8506 of the vulnerable file.


    /* Add the new eviction groups, if enabled. */
    table->eviction = eviction;
    if (table->eviction) {
        table->eviction_group_id_basis = random_uint32();
        CLS_FOR_EACH (rule, cr, &table->cls) {
            eviction_group_add_rule(rule);
        }
    }
}

/* Inserts 'rule' from the ofproto data structures BEFORE caller has inserted
 * it to the classifier. */
static void
ofproto_rule_insert__(struct ofproto *ofproto, struct rule *rule)
    OVS_REQUIRES(ofproto_mutex)
{
    const struct rule_actions *actions = rule_get_actions(rule);

    /* A rule may not be reinserted. */
    ovs_assert(rule->state == RULE_INITIALIZED);

    if (rule->hard_timeout || rule->idle_timeout) {
        ovs_list_insert(&ofproto->expirable, &rule->expirable);
    }
    cookies_insert(ofproto, rule);
    eviction_group_add_rule(rule);
    if (actions->has_meter) {
        meter_insert_rule(rule);
    }
    if (actions->has_groups) {
        const struct ofpact_group *a;
        OFPACT_FOR_EACH_TYPE_FLATTENED (a, GROUP, actions->ofpacts,
                                        actions->ofpacts_len) {
            struct ofgroup *group;

            group = ofproto_group_lookup(ofproto, a->group_id, OVS_VERSION_MAX,
                                         false);
            ovs_assert(group != NULL);
            group_add_rule(group, rule);
        }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -8483,7 +8483,7 @@
     const struct rule_actions *actions = rule_get_actions(rule);
 
     /* A rule may not be reinserted. */
-    ovs_assert(rule->state == RULE_INITIALIZED);
+    ovs_assert(rule->state != RULE_INSERTED);
 
     if (rule->hard_timeout || rule->idle_timeout) {
         ovs_list_insert(&ofproto->expirable, &rule->expirable);
```
