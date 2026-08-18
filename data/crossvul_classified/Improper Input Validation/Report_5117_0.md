# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 5117_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5117_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 228-268 of the vulnerable file.

 */

static const struct state_microcode
	*ike_microcode_index[STATE_IKE_ROOF - STATE_IKE_FLOOR];

static const struct state_microcode v1_state_microcode_table[] = {

#define PT(n) ISAKMP_NEXT_ ## n
#define P(n) LELEM(PT(n))

	/***** Phase 1 Main Mode *****/

	/* No state for main_outI1: --> HDR, SA */

	/* STATE_MAIN_R0: I1 --> R1
	 * HDR, SA --> HDR, SA
	 */
	{ STATE_MAIN_R0, STATE_MAIN_R1,
	  SMF_ALL_AUTH | SMF_REPLY,
	  P(SA), P(VID) | P(CR), PT(NONE),
	  EVENT_v1_RETRANSMIT, main_inI1_outR1 },

	/* STATE_MAIN_I1: R1 --> I2
	 * HDR, SA --> auth dependent
	 * SMF_PSK_AUTH, SMF_DS_AUTH: --> HDR, KE, Ni
	 * SMF_PKE_AUTH:
	 *	--> HDR, KE, [ HASH(1), ] <IDi1_b>PubKey_r, <Ni_b>PubKey_r
	 * SMF_RPKE_AUTH:
	 *	--> HDR, [ HASH(1), ] <Ni_b>Pubkey_r, <KE_b>Ke_i, <IDi1_b>Ke_i [,<<Cert-I_b>Ke_i]
	 * Note: since we don't know auth at start, we cannot differentiate
	 * microcode entries based on it.
	 */
	{ STATE_MAIN_I1, STATE_MAIN_I2,
	  SMF_ALL_AUTH | SMF_INITIATOR | SMF_REPLY,
	  P(SA), P(VID) | P(CR), PT(NONE), /* don't know yet */
	  EVENT_v1_RETRANSMIT, main_inR1_outI2 },

	/* STATE_MAIN_R1: I2 --> R2
	 * SMF_PSK_AUTH, SMF_DS_AUTH: HDR, KE, Ni --> HDR, KE, Nr
	 * SMF_PKE_AUTH: HDR, KE, [ HASH(1), ] <IDi1_b>PubKey_r, <Ni_b>PubKey_r
	 *	    --> HDR, KE, <IDr1_b>PubKey_i, <Nr_b>PubKey_i
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -245,7 +245,7 @@
 	{ STATE_MAIN_R0, STATE_MAIN_R1,
 	  SMF_ALL_AUTH | SMF_REPLY,
 	  P(SA), P(VID) | P(CR), PT(NONE),
-	  EVENT_v1_RETRANSMIT, main_inI1_outR1 },
+	  EVENT_NULL, main_inI1_outR1 },
 
 	/* STATE_MAIN_I1: R1 --> I2
 	 * HDR, SA --> auth dependent
@@ -394,7 +394,7 @@
 	{ STATE_AGGR_R0, STATE_AGGR_R1,
 	  SMF_PSK_AUTH | SMF_DS_AUTH | SMF_REPLY,
 	  P(SA) | P(KE) | P(NONCE) | P(ID), P(VID) | P(NATD_RFC), PT(NONE),
-	  EVENT_v1_RETRANSMIT, aggr_inI1_outR1 },
+	  EVENT_NULL, aggr_inI1_outR1 },
 
 	/* STATE_AGGR_I1:
 	 * SMF_PSK_AUTH: HDR, SA, KE, Nr, IDir, HASH_R
@@ -571,12 +571,12 @@
 	{ STATE_XAUTH_I0, STATE_XAUTH_I1,
 	  SMF_ALL_AUTH | SMF_ENCRYPTED | SMF_REPLY | SMF_RELEASE_PENDING_P2,
 	  P(MCFG_ATTR) | P(HASH), P(VID), PT(HASH),
-	  EVENT_SA_REPLACE, xauth_inI0 },
+	  EVENT_v1_RETRANSMIT, xauth_inI0 },
 
 	{ STATE_XAUTH_I1, STATE_MAIN_I4,
 	  SMF_ALL_AUTH | SMF_ENCRYPTED | SMF_REPLY | SMF_RELEASE_PENDING_P2,
 	  P(MCFG_ATTR) | P(HASH), P(VID), PT(HASH),
-	  EVENT_SA_REPLACE, xauth_inI1 },
+	  EVENT_v1_RETRANSMIT, xauth_inI1 },
 
 #undef P
 #undef PT
```
