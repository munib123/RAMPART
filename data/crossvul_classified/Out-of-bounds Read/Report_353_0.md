# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 353_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `353_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 354-395 of the vulnerable file.

    } else {
	ND_TCHECK2(w[7 * 2], 2);
	paramlen = EXTRACT_LE_16BITS(w + 3 * 2);
	param = buf + EXTRACT_LE_16BITS(w + 4 * 2);
	datalen = EXTRACT_LE_16BITS(w + 6 * 2);
	data = buf + EXTRACT_LE_16BITS(w + 7 * 2);
	f1 = "TotParamCnt=[d] \nTotDataCnt=[d] \nRes1=[d]\nParamCnt=[d] \nParamOff=[d] \nRes2=[d] \nDataCnt=[d] \nDataOff=[d] \nRes3=[d]\nLsetup=[d]\n";
	f2 = "|Unknown ";
	f3 = "|Param ";
	f4 = "|Data ";
    }

    smb_fdata(ndo, words + 1, f1, min(words + 1 + 2 * words[0], maxbuf),
        unicodestr);

    ND_TCHECK2(*data1, 2);
    bcc = EXTRACT_LE_16BITS(data1);
    ND_PRINT((ndo, "smb_bcc=%u\n", bcc));
    if (bcc > 0) {
	smb_fdata(ndo, data1 + 2, f2, maxbuf - (paramlen + datalen), unicodestr);

	if (strcmp((const char *)(data1 + 2), "\\MAILSLOT\\BROWSE") == 0) {
	    print_browse(ndo, param, paramlen, data, datalen);
	    return;
	}

	if (strcmp((const char *)(data1 + 2), "\\PIPE\\LANMAN") == 0) {
	    print_ipc(ndo, param, paramlen, data, datalen);
	    return;
	}

	if (paramlen)
	    smb_fdata(ndo, param, f3, min(param + paramlen, maxbuf), unicodestr);
	if (datalen)
	    smb_fdata(ndo, data, f4, min(data + datalen, maxbuf), unicodestr);
    }
    return;
trunc:
    ND_PRINT((ndo, "%s", tstr));
}


```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -371,16 +371,21 @@
     ND_PRINT((ndo, "smb_bcc=%u\n", bcc));
     if (bcc > 0) {
 	smb_fdata(ndo, data1 + 2, f2, maxbuf - (paramlen + datalen), unicodestr);
-
-	if (strcmp((const char *)(data1 + 2), "\\MAILSLOT\\BROWSE") == 0) {
+#define MAILSLOT_BROWSE_STR "\\MAILSLOT\\BROWSE"
+	ND_TCHECK2(*(data1 + 2), strlen(MAILSLOT_BROWSE_STR) + 1);
+	if (strcmp((const char *)(data1 + 2), MAILSLOT_BROWSE_STR) == 0) {
 	    print_browse(ndo, param, paramlen, data, datalen);
 	    return;
 	}
-
-	if (strcmp((const char *)(data1 + 2), "\\PIPE\\LANMAN") == 0) {
+#undef MAILSLOT_BROWSE_STR
+
+#define PIPE_LANMAN_STR "\\PIPE\\LANMAN"
+	ND_TCHECK2(*(data1 + 2), strlen(PIPE_LANMAN_STR) + 1);
+	if (strcmp((const char *)(data1 + 2), PIPE_LANMAN_STR) == 0) {
 	    print_ipc(ndo, param, paramlen, data, datalen);
 	    return;
 	}
+#undef PIPE_LANMAN_STR
 
 	if (paramlen)
 	    smb_fdata(ndo, param, f3, min(param + paramlen, maxbuf), unicodestr);
```
