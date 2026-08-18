# CrossVul Fix Pair: Out-of-bounds Write in c
**Pair ID:** 526_1
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-787
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `526_1`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Write - Typically, this can result in corruption of data, a crash, or code execution.

## Vulnerable Code
```c
Lines 188-228 of the vulnerable file.

		lang[2] = (import->esd->langDesc->langCode) & 0xFF;
		lang[3] = 0;
		gf_isom_set_media_language(import->dest, track, lang);
	}
}
#endif

char *gf_text_get_utf8_line(char *szLine, u32 lineSize, FILE *txt_in, s32 unicode_type)
{
	u32 i, j, len;
	char *sOK;
	char szLineConv[1024];
	unsigned short *sptr;

	memset(szLine, 0, sizeof(char)*lineSize);
	sOK = fgets(szLine, lineSize, txt_in);
	if (!sOK) return NULL;
	if (unicode_type<=1) {
		j=0;
		len = (u32) strlen(szLine);
		for (i=0; i<len; i++) {
			if (!unicode_type && (szLine[i] & 0x80)) {
				/*non UTF8 (likely some win-CP)*/
				if ((szLine[i+1] & 0xc0) != 0x80) {
					szLineConv[j] = 0xc0 | ( (szLine[i] >> 6) & 0x3 );
					j++;
					szLine[i] &= 0xbf;
				}
				/*UTF8 2 bytes char*/
				else if ( (szLine[i] & 0xe0) == 0xc0) {
					szLineConv[j] = szLine[i];
					i++;
					j++;
				}
				/*UTF8 3 bytes char*/
				else if ( (szLine[i] & 0xf0) == 0xe0) {
					szLineConv[j] = szLine[i];
					i++;
					j++;
					szLineConv[j] = szLine[i];
					i++;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -205,49 +205,76 @@
 	if (unicode_type<=1) {
 		j=0;
 		len = (u32) strlen(szLine);
-		for (i=0; i<len; i++) {
+		for (i=0; i<len && j < sizeof(szLineConv) - 1; i++, j++) {
+
 			if (!unicode_type && (szLine[i] & 0x80)) {
 				/*non UTF8 (likely some win-CP)*/
 				if ((szLine[i+1] & 0xc0) != 0x80) {
-					szLineConv[j] = 0xc0 | ( (szLine[i] >> 6) & 0x3 );
-					j++;
-					szLine[i] &= 0xbf;
+					if (j + 1 < sizeof(szLineConv) - 1) {
+						szLineConv[j] = 0xc0 | ((szLine[i] >> 6) & 0x3);
+						j++;
+						szLine[i] &= 0xbf;
+					}
+					else
+						break;
 				}
 				/*UTF8 2 bytes char*/
 				else if ( (szLine[i] & 0xe0) == 0xc0) {
-					szLineConv[j] = szLine[i];
-					i++;
-					j++;
+
+					// don't cut multibyte in the middle in there is no more room in dest
+					if (j + 1 < sizeof(szLineConv) - 1 && i + 1 < len) {
+						szLineConv[j] = szLine[i];
+						i++;
+						j++;
+					}
+					else {
+						break;
+					}
 				}
 				/*UTF8 3 bytes char*/
 				else if ( (szLine[i] & 0xf0) == 0xe0) {
-					szLineConv[j] = szLine[i];
-					i++;
-					j++;
-					szLineConv[j] = szLine[i];
-					i++;
-					j++;
+					if (j + 2 < sizeof(szLineConv) - 1 && i + 2 < len) {
+						szLineConv[j] = szLine[i];
+						i++;
+						j++;
+						szLineConv[j] = szLine[i];
+						i++;
+						j++;
+					}
+					else {
+						break;
+					}
 				}
 				/*UTF8 4 bytes char*/
 				else if ( (szLine[i] & 0xf8) == 0xf0) {
-					szLineConv[j] = szLine[i];
-					i++;
-					j++;
-					szLineConv[j] = szLine[i];
-					i++;
-					j++;
-					szLineConv[j] = szLine[i];
-					i++;
-					j++;
+					if (j + 3 < sizeof(szLineConv) - 1 && i + 3 < len) {
+						szLineConv[j] = szLine[i];
+						i++;
+						j++;
+						szLineConv[j] = szLine[i];
+						i++;
+						j++;
+						szLineConv[j] = szLine[i];
+						i++;
+						j++;
+					}
+					else {
+						break;
+					}
 				} else {
 					i+=1;
 					continue;
 				}
 			}
-			szLineConv[j] = szLine[i];
-			j++;
-		}
-		szLineConv[j] = 0;
+			if (j < sizeof(szLineConv)-1 && i<len)
+				szLineConv[j] = szLine[i];
+
+		}
+		if (j >= sizeof(szLineConv))
+			szLineConv[sizeof(szLineConv) - 1] = 0;
+		else
+			szLineConv[j] = 0;
+
 		strcpy(szLine, szLineConv);
 		return sOK;
 	}
```
