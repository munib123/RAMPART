# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 5849_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5849_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 289-330 of the vulnerable file.

	passert(ugh == NULL);
	passert(cur_state == NULL);
	passert(st != NULL);

	passert(st->st_suspended_md == ke->md);
	set_suspended(st, NULL); /* no longer connected or suspended */

	set_cur_state(st);

	st->st_calculating = FALSE;

	e = ikev2_parent_outI1_tail(pcrc, r);

	if (ke->md != NULL) {
		complete_v2_state_transition(&ke->md, e);
		if (ke->md)
			release_md(ke->md);
	}
	reset_cur_state();
	reset_globals();

	passert(GLOBALS_ARE_RESET());
}

/*
 * unpack the calculate KE value, store it in state.
 * used by IKEv2: parent, child (PFS)
 */
static int unpack_v2KE(struct state *st,
		       struct pluto_crypto_req *r,
		       chunk_t *g)
{
	struct pcr_kenonce *kn = &r->pcr_d.kn;

	unpack_KE(st, r, g);
	return kn->oakley_group;
}

/*
 * package up the calculate KE value, and emit it as a KE payload.
 * used by IKEv2: parent, child (PFS)
 */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -306,8 +306,6 @@
 	}
 	reset_cur_state();
 	reset_globals();
-
-	passert(GLOBALS_ARE_RESET());
 }
 
 /*
@@ -729,18 +727,31 @@
 	 */
 	{
 		struct ikev2_ke *ke;
+		char fromname[ADDRTOT_BUF];
+		addrtot(&md->sender, 0, fromname, ADDRTOT_BUF);
+
+		if (!md->chain[ISAKMP_NEXT_v2KE]) {
+			/* is this a notify? If so, log it */
+			if(md->chain[ISAKMP_NEXT_v2N]) {
+				libreswan_log("Received Notify(%d): %s",
+					md->chain[ISAKMP_NEXT_v2N]->payload.v2n.isan_type,
+					enum_name(&ikev2_notify_names,
+						md->chain[ISAKMP_NEXT_v2N]->payload.v2n.isan_type));
+			}
+			libreswan_log(
+				"rejecting I1 from %s:%u, no KE payload present",
+				fromname, md->sender_port);
+			return STF_FAIL + v2N_INVALID_KE_PAYLOAD;
+		}
 		ke = &md->chain[ISAKMP_NEXT_v2KE]->payload.v2ke;
 
 		st->st_oakley.group = lookup_group(ke->isak_group);
 		if (st->st_oakley.group == NULL) {
-			char fromname[ADDRTOT_BUF];
-
-			addrtot(&md->sender, 0, fromname, ADDRTOT_BUF);
 			libreswan_log(
 				"rejecting I1 from %s:%u, invalid DH group=%u",
 				fromname, md->sender_port,
 				ke->isak_group);
-			return v2N_INVALID_KE_PAYLOAD;
+			return STF_FAIL + v2N_INVALID_KE_PAYLOAD;
 		}
 	}
 
@@ -819,8 +830,6 @@
 			release_md(ke->md);
 	}
 	reset_globals();
-
-	passert(GLOBALS_ARE_RESET());
 }
 
 static stf_status ikev2_parent_inI1outR1_tail(
@@ -1145,8 +1154,6 @@
 			release_md(dh->md);
 	}
 	reset_globals();
-
-	passert(GLOBALS_ARE_RESET());
 }
 
 static void ikev2_padup_pre_encrypt(struct msg_digest *md,
@@ -1714,7 +1721,7 @@
 	/* verify that there is in fact an encrypted payload */
 	if (!md->chain[ISAKMP_NEXT_v2E]) {
 		libreswan_log("R2 state should receive an encrypted payload");
-		reset_globals();
+		reset_globals(); /* XXX suspicious - why was this deemed neccessary? */
 		return STF_FATAL;
 	}
 
@@ -1794,8 +1801,6 @@
 			release_md(dh->md);
 	}
 	reset_globals();
-
-	passert(GLOBALS_ARE_RESET());
 }
 
 static stf_status ikev2_parent_inI2outR2_tail(
```
