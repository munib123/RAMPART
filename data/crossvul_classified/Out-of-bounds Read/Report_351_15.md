# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 351_15
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `351_15`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 533-573 of the vulnerable file.

	}

	for(i=0; i<32; i++) {
		cinfo = (struct sc_pkcs15_data_info *) objs[i]->data;
		if(!strcmp("EF_DatiPersonali", objs[i]->label))
			break;
	}

	if(i>=32) {
		sc_debug(p15card->card->ctx, SC_LOG_DEBUG_NORMAL,
			"Could not find EF_DatiPersonali: "
			"keeping generic card name");
		return SC_SUCCESS;
	}

	rv = sc_pkcs15_read_data_object(p15card, cinfo, &p15_personaldata);
	if (rv) {
		sc_debug(p15card->card->ctx, SC_LOG_DEBUG_NORMAL,
			"Could not read EF_DatiPersonali: "
			"keeping generic card name");
	}

	{
		char fullname[160];
		if(get_name_from_EF_DatiPersonali(p15_personaldata->data,
			fullname, sizeof(fullname))) {
			sc_debug(p15card->card->ctx, SC_LOG_DEBUG_NORMAL,
				"Could not parse EF_DatiPersonali: "
				"keeping generic card name");
			sc_pkcs15_free_data_object(p15_personaldata);
			return SC_SUCCESS;
		}
		set_string(&p15card->tokeninfo->label, fullname);
	}
	sc_pkcs15_free_data_object(p15_personaldata);
	return SC_SUCCESS;
}

static int itacns_add_keyset(sc_pkcs15_card_t *p15card,
	const char *label, int sec_env, sc_pkcs15_id_t *cert_id,
	const char *pubkey_path, const char *prkey_path,
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -550,6 +550,7 @@
 		sc_debug(p15card->card->ctx, SC_LOG_DEBUG_NORMAL,
 			"Could not read EF_DatiPersonali: "
 			"keeping generic card name");
+		return SC_SUCCESS;
 	}
 
 	{
```
