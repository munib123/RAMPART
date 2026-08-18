# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 351_16
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `351_16`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 115-155 of the vulnerable file.

	memset(&prkey_info, 0, sizeof(prkey_info));
	prkey_info.id.len         = 1;
	prkey_info.id.value[0]    = id;
	prkey_info.native         = 1;
	prkey_info.key_reference  = key_reference;
	prkey_info.modulus_length = key_length;
	sc_format_path(path, &prkey_info.path);

	memset(&prkey_obj, 0, sizeof(prkey_obj));
	strlcpy(prkey_obj.label, label, sizeof(prkey_obj.label));
	prkey_obj.flags            = SC_PKCS15_CO_FLAG_PRIVATE;
	prkey_obj.auth_id.len      = 1;
	prkey_obj.auth_id.value[0] = auth_id;

	can_sign=can_crypt=0;
	if(card->type==SC_CARD_TYPE_TCOS_V3){
		unsigned char buf[256];
		int i, rec_no=0;
		if(prkey_info.path.len>=2) prkey_info.path.len-=2;
		sc_append_file_id(&prkey_info.path, 0x5349);
		if(sc_select_file(card, &prkey_info.path, NULL)!=SC_SUCCESS){
			sc_debug(ctx, SC_LOG_DEBUG_NORMAL,
				"Select(%s) failed\n",
				sc_print_path(&prkey_info.path));
			return 1;
		}
		sc_debug(ctx, SC_LOG_DEBUG_NORMAL,
			"Searching for Key-Ref %02X\n", key_reference);
		while((r=sc_read_record(card, ++rec_no, buf, sizeof(buf), SC_RECORD_BY_REC_NR))>0){
			int found=0;
			if(buf[0]!=0xA0) continue;
			for(i=2;i<buf[1]+2;i+=2+buf[i+1]){
				if(buf[i]==0x83 && buf[i+1]==1 && buf[i+2]==key_reference) ++found;
			}
			if(found) break;
		}
		if(r<=0){
			sc_debug(ctx, SC_LOG_DEBUG_NORMAL,"No EF_KEYD-Record found\n");
			return 1;
		}
		for(i=0;i<r;i+=2+buf[i+1]){
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -132,7 +132,7 @@
 		int i, rec_no=0;
 		if(prkey_info.path.len>=2) prkey_info.path.len-=2;
 		sc_append_file_id(&prkey_info.path, 0x5349);
-		if(sc_select_file(card, &prkey_info.path, NULL)!=SC_SUCCESS){
+		if(sc_select_file(card, &prkey_info.path, NULL)!=SC_SUCCESS || !f->prop_attr){
 			sc_debug(ctx, SC_LOG_DEBUG_NORMAL,
 				"Select(%s) failed\n",
 				sc_print_path(&prkey_info.path));
@@ -157,7 +157,8 @@
 			if(buf[i]==0xB8) can_crypt++;
 		}
 	} else {
-		if(sc_select_file(card, &prkey_info.path, &f)!=SC_SUCCESS){
+		if(sc_select_file(card, &prkey_info.path, &f)!=SC_SUCCESS
+			   	|| !f->prop_attr || f->prop_attr_len < 2){
 			sc_debug(ctx, SC_LOG_DEBUG_NORMAL,
 				"Select(%s) failed\n",
 				sc_print_path(&prkey_info.path));
@@ -245,7 +246,8 @@
 			return 1;
 		}
 	} else {
-		if(sc_select_file(card, &pin_info.path, &f)!=SC_SUCCESS){
+		if(sc_select_file(card, &pin_info.path, &f)!=SC_SUCCESS
+			   	|| !f->prop_attr || f->prop_attr_len < 4){
 			sc_debug(ctx, SC_LOG_DEBUG_NORMAL,"Select(%s) failed\n", path);
 			return 1;
 		}
```
