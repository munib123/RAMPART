# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 4250_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4250_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 2112-2152 of the vulnerable file.

				}
				passert(sd != NULL);
			}

			passert(np < LELEM_ROOF);

			{
				lset_t s = LELEM(np);

				if (LDISJOINT(s,
					      needed | smc->opt_payloads |
					      LELEM(ISAKMP_NEXT_VID) |
					      LELEM(ISAKMP_NEXT_N) |
					      LELEM(ISAKMP_NEXT_D) |
					      LELEM(ISAKMP_NEXT_CR) |
					      LELEM(ISAKMP_NEXT_CERT))) {
					loglog(RC_LOG_SERIOUS,
						"%smessage ignored because it contains a payload type (%s) unexpected by state %s",
						excuse,
						enum_show(&ikev1_payload_names, np),
						st->st_state->name);
					if (!md->encrypted) {
						SEND_NOTIFICATION(INVALID_PAYLOAD_TYPE);
					}
					return;
				}

				DBG(DBG_PARSING,
				    DBG_log("got payload 0x%" PRIxLSET"  (%s) needed: 0x%" PRIxLSET " opt: 0x%" PRIxLSET,
					    s, enum_show(&ikev1_payload_names, np),
					    needed, smc->opt_payloads));
				needed &= ~s;
			}

			/*
			 * Read in the payload recording what type it
			 * should be
			 */
			pd->payload_type = np;
			if (!in_struct(&pd->payload, sd, &md->message_pbs,
				       &pd->pbs)) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2129,7 +2129,7 @@
 						"%smessage ignored because it contains a payload type (%s) unexpected by state %s",
 						excuse,
 						enum_show(&ikev1_payload_names, np),
-						st->st_state->name);
+						finite_states[smc->state]->name);
 					if (!md->encrypted) {
 						SEND_NOTIFICATION(INVALID_PAYLOAD_TYPE);
 					}
```
