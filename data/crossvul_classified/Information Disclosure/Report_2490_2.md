# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in c
**Pair ID:** 2490_2
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2490_2`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```c
Lines 259-301 of the vulnerable file.

   * sampled_entry_guards, and its pointers point to elements of
   * sampled_entry_guards.
   */
  smartlist_t *primary_entry_guards;

  /** When did we last successfully build a circuit or use a circuit? */
  time_t last_time_on_internet;

  /** What confirmed_idx value should the next-added member of
   * confirmed_entry_guards receive? */
  int next_confirmed_idx;

};

struct entry_guard_handle_t;

/**
 * A restriction to remember which entry guards are off-limits for a given
 * circuit.
 *
 * Right now, we only use restrictions to block a single guard from being
 * selected; this mechanism is designed to be more extensible in the future,
 * however.
 *
 * Note: This mechanism is NOT for recording which guards are never to be
 * used: only which guards cannot be used on <em>one particular circuit</em>.
 */
struct entry_guard_restriction_t {
  /**
   * The guard's RSA identity digest must not equal this.
   */
  uint8_t exclude_id[DIGEST_LEN];
};

/**
 * Per-circuit state to track whether we'll be able to use the circuit.
 */
struct circuit_guard_state_t {
  /** Handle to the entry guard object for this circuit. */
  struct entry_guard_handle_t *guard;
  /** The time at which <b>state</b> last changed. */
  time_t state_set_at;
  /** One of GUARD_CIRC_STATE_* */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -276,16 +276,17 @@
  * A restriction to remember which entry guards are off-limits for a given
  * circuit.
  *
- * Right now, we only use restrictions to block a single guard from being
- * selected; this mechanism is designed to be more extensible in the future,
- * however.
+ * Right now, we only use restrictions to block a single guard and its family
+ * from being selected; this mechanism is designed to be more extensible in
+ * the future, however.
  *
  * Note: This mechanism is NOT for recording which guards are never to be
  * used: only which guards cannot be used on <em>one particular circuit</em>.
  */
 struct entry_guard_restriction_t {
   /**
-   * The guard's RSA identity digest must not equal this.
+   * The guard's RSA identity digest must not equal this; and it must not
+   * be in the same family as any node with this digest.
    */
   uint8_t exclude_id[DIGEST_LEN];
 };
```
