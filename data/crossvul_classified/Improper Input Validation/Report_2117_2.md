# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 2117_2
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2117_2`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 584-605 of the vulnerable file.

struct ib_cm_sidr_rep_param {
	u32			qp_num;
	u32			qkey;
	enum ib_cm_sidr_status	status;
	const void		*info;
	u8			info_length;
	const void		*private_data;
	u8			private_data_len;
};

/**
 * ib_send_cm_sidr_rep - Sends a service ID resolution reply to the
 *   remote node.
 * @cm_id: Communication identifier associated with the received service ID
 *   resolution request.
 * @param: Service ID resolution reply information.
 */
int ib_send_cm_sidr_rep(struct ib_cm_id *cm_id,
			struct ib_cm_sidr_rep_param *param);

int ib_update_cm_av(struct ib_cm_id *id, const u8 *smac, const u8 *alt_smac);
#endif /* IB_CM_H */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -601,5 +601,4 @@
 int ib_send_cm_sidr_rep(struct ib_cm_id *cm_id,
 			struct ib_cm_sidr_rep_param *param);
 
-int ib_update_cm_av(struct ib_cm_id *id, const u8 *smac, const u8 *alt_smac);
 #endif /* IB_CM_H */
```
