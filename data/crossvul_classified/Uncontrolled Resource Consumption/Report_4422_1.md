# CrossVul Fix Pair: Uncontrolled Resource Consumption in c
**Pair ID:** 4422_1
**Vulnerability Class:** Uncontrolled Resource Consumption
**CWE:** CWE-400
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4422_1`)

## Vulnerability Information & PoC

## Description
Uncontrolled Resource Consumption - Limited resources include memory, file system storage, database connection pool entries, and CPU.

## Vulnerable Code
```c
Lines 144-184 of the vulnerable file.

 */
#define MASK_LSBS(w, i) (w & ((~((xen_ulong_t)0UL)) << i))

static inline xen_ulong_t active_evtchns(unsigned int cpu,
					 struct shared_info *sh,
					 unsigned int idx)
{
	return sh->evtchn_pending[idx] &
		per_cpu(cpu_evtchn_mask, cpu)[idx] &
		~sh->evtchn_mask[idx];
}

/*
 * Search the CPU's pending events bitmasks.  For each one found, map
 * the event number to an irq, and feed it into do_IRQ() for handling.
 *
 * Xen uses a two-level bitmap to speed searching.  The first level is
 * a bitset of words which contain pending event bits.  The second
 * level is a bitset of pending events themselves.
 */
static void evtchn_2l_handle_events(unsigned cpu)
{
	int irq;
	xen_ulong_t pending_words;
	xen_ulong_t pending_bits;
	int start_word_idx, start_bit_idx;
	int word_idx, bit_idx;
	int i;
	struct shared_info *s = HYPERVISOR_shared_info;
	struct vcpu_info *vcpu_info = __this_cpu_read(xen_vcpu);

	/* Timer interrupt has highest priority. */
	irq = irq_from_virq(cpu, VIRQ_TIMER);
	if (irq != -1) {
		evtchn_port_t evtchn = evtchn_from_irq(irq);
		word_idx = evtchn / BITS_PER_LONG;
		bit_idx = evtchn % BITS_PER_LONG;
		if (active_evtchns(cpu, s, word_idx) & (1ULL << bit_idx))
			generic_handle_irq(irq);
	}

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -161,7 +161,7 @@
  * a bitset of words which contain pending event bits.  The second
  * level is a bitset of pending events themselves.
  */
-static void evtchn_2l_handle_events(unsigned cpu)
+static void evtchn_2l_handle_events(unsigned cpu, struct evtchn_loop_ctrl *ctrl)
 {
 	int irq;
 	xen_ulong_t pending_words;
@@ -242,10 +242,7 @@
 
 			/* Process port. */
 			port = (word_idx * BITS_PER_EVTCHN_WORD) + bit_idx;
-			irq = get_evtchn_to_irq(port);
-
-			if (irq != -1)
-				generic_handle_irq(irq);
+			handle_irq_for_port(port, ctrl);
 
 			bit_idx = (bit_idx + 1) % BITS_PER_EVTCHN_WORD;
 
```
