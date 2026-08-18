# CrossVul Fix Pair: Out-of-bounds Write in c
**Pair ID:** 524_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-787
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `524_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Write - Typically, this can result in corruption of data, a crash, or code execution.

## Vulnerable Code
```c
Lines 252-292 of the vulnerable file.

		return sOK;
	}

#ifdef GPAC_BIG_ENDIAN
	if (unicode_type==3) {
#else
	if (unicode_type==2) {
#endif
		i=0;
		while (1) {
			char c;
			if (!szLine[i] && !szLine[i+1]) break;
			c = szLine[i+1];
			szLine[i+1] = szLine[i];
			szLine[i] = c;
			i+=2;
		}
	}
	sptr = (u16 *)szLine;
	i = (u32) gf_utf8_wcstombs(szLineConv, 1024, (const unsigned short **) &sptr);
	szLineConv[i] = 0;
	strcpy(szLine, szLineConv);
	/*this is ugly indeed: since input is UTF16-LE, there are many chances the fgets never reads the \0 after a \n*/
	if (unicode_type==3) fgetc(txt_in);
	return sOK;
}


#ifndef GPAC_DISABLE_MEDIA_IMPORT

static GF_Err gf_text_import_srt(GF_MediaImporter *import)
{
	FILE *srt_in;
	u32 track, timescale, i, count;
	GF_TextConfig*cfg;
	GF_Err e;
	GF_StyleRecord rec;
	GF_TextSample * samp;
	GF_ISOSample *s;
	u32 sh, sm, ss, sms, eh, em, es, ems, txt_line, char_len, char_line, nb_samp, j, duration, rem_styles;
	Bool set_start_char, set_end_char, first_samp, rem_color;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -269,6 +269,8 @@
 	}
 	sptr = (u16 *)szLine;
 	i = (u32) gf_utf8_wcstombs(szLineConv, 1024, (const unsigned short **) &sptr);
+	if (i >= (u32)ARRAY_LENGTH(szLineConv))
+		return NULL;
 	szLineConv[i] = 0;
 	strcpy(szLine, szLineConv);
 	/*this is ugly indeed: since input is UTF16-LE, there are many chances the fgets never reads the \0 after a \n*/
```
