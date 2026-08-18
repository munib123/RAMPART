# CrossVul Fix Pair: NULL Pointer Dereference in c
**Pair ID:** 99_1
**Vulnerability Class:** NULL Pointer Dereference
**CWE:** CWE-476
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `99_1`)

## Vulnerability Information & PoC

## Description
NULL Pointer Dereference - NULL pointer dereference issues can occur through a number of flaws, including race conditions, and simple programming omissions.

## Vulnerable Code
```c
Lines 313-353 of the vulnerable file.

		if (!t->u.kernel.target->target) {
			int v;

			v = ((struct xt_standard_target *)t)->verdict;
			if (v < 0) {
				/* Pop from stack? */
				if (v != XT_RETURN) {
					verdict = (unsigned int)(-v) - 1;
					break;
				}
				if (stackidx == 0) {
					e = get_entry(table_base,
					    private->underflow[hook]);
				} else {
					e = jumpstack[--stackidx];
					e = ipt_next_entry(e);
				}
				continue;
			}
			if (table_base + v != ipt_next_entry(e) &&
			    !(e->ip.flags & IPT_F_GOTO))
				jumpstack[stackidx++] = e;

			e = get_entry(table_base, v);
			continue;
		}

		acpar.target   = t->u.kernel.target;
		acpar.targinfo = t->data;

		verdict = t->u.kernel.target->target(skb, &acpar);
		if (verdict == XT_CONTINUE) {
			/* Target might have changed stuff. */
			ip = ip_hdr(skb);
			e = ipt_next_entry(e);
		} else {
			/* Verdict */
			break;
		}
	} while (!acpar.hotdrop);

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -330,8 +330,13 @@
 				continue;
 			}
 			if (table_base + v != ipt_next_entry(e) &&
-			    !(e->ip.flags & IPT_F_GOTO))
+			    !(e->ip.flags & IPT_F_GOTO)) {
+				if (unlikely(stackidx >= private->stacksize)) {
+					verdict = NF_DROP;
+					break;
+				}
 				jumpstack[stackidx++] = e;
+			}
 
 			e = get_entry(table_base, v);
 			continue;
```
