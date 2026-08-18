# CrossVul Fix Pair: Resource Management Errors in c
**Pair ID:** 2289_0
**Vulnerability Class:** Resource Management Errors
**CWE:** CWE-399
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2289_0`)

## Vulnerability Information & PoC

## Description
Resource Management Errors

## Vulnerable Code
```c
Lines 2592-2632 of the vulnerable file.


	case SCTP_PARAM_UNRECOGNIZED_PARAMETERS:
		/* Rejected during verify stage. */
		break;

	case SCTP_PARAM_ECN_CAPABLE:
		asoc->peer.ecn_capable = 1;
		break;

	case SCTP_PARAM_ADAPTATION_LAYER_IND:
		asoc->peer.adaptation_ind = ntohl(param.aind->adaptation_ind);
		break;

	case SCTP_PARAM_SET_PRIMARY:
		if (!net->sctp.addip_enable)
			goto fall_through;

		addr_param = param.v + sizeof(sctp_addip_param_t);

		af = sctp_get_af_specific(param_type2af(param.p->type));
		af->from_addr_param(&addr, addr_param,
				    htons(asoc->peer.port), 0);

		/* if the address is invalid, we can't process it.
		 * XXX: see spec for what to do.
		 */
		if (!af->addr_valid(&addr, NULL, NULL))
			break;

		t = sctp_assoc_lookup_paddr(asoc, &addr);
		if (!t)
			break;

		sctp_assoc_set_primary(asoc, t);
		break;

	case SCTP_PARAM_SUPPORTED_EXT:
		sctp_process_ext_param(asoc, param);
		break;

	case SCTP_PARAM_FWD_TSN_SUPPORT:
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2609,6 +2609,9 @@
 		addr_param = param.v + sizeof(sctp_addip_param_t);
 
 		af = sctp_get_af_specific(param_type2af(param.p->type));
+		if (af == NULL)
+			break;
+
 		af->from_addr_param(&addr, addr_param,
 				    htons(asoc->peer.port), 0);
 
```
