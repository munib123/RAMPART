# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 210_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `210_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 3693-3733 of the vulnerable file.

	GF_TextKaraokeBox *cur_karaoke;
};

GF_TextSample *gf_isom_parse_texte_sample(GF_BitStream *bs);
GF_TextSample *gf_isom_parse_texte_sample_from_data(char *data, u32 dataLength);

struct _generic_subtitle_sample
{
	char *text;
	u32 len;
};
GF_GenericSubtitleSample *gf_isom_parse_generic_subtitle_sample(GF_BitStream *bs);
GF_GenericSubtitleSample *gf_isom_parse_generic_subtitle_sample_from_data(char *data, u32 dataLength);


/*do not throw fatal errors if boxes are duplicated, just warn and remove extra ones*/
#define ERROR_ON_DUPLICATED_BOX(__abox, __parent) {	\
		char __ptype[5];\
		strcpy(__ptype, gf_4cc_to_str(__parent->type) );\
		GF_LOG(GF_LOG_WARNING, GF_LOG_CONTAINER, ("[iso file] extra box %s found in %s, deleting\n", gf_4cc_to_str(__abox->type), __ptype)); \
		gf_isom_box_del(a);\
		return GF_OK;\
	}


#ifndef GPAC_DISABLE_VTT

GF_Err gf_isom_update_webvtt_description(GF_ISOFile *movie, u32 trackNumber, u32 descriptionIndex, const char *config);
GF_ISOSample *gf_isom_webvtt_to_sample(void *samp);

typedef struct
{
	GF_ISOM_BOX
	char *string;
} GF_StringBox;

typedef struct
{
	GF_ISOM_SAMPLE_ENTRY_FIELDS
	GF_StringBox *config;
} GF_WebVTTSampleEntryBox;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -3710,7 +3710,7 @@
 		char __ptype[5];\
 		strcpy(__ptype, gf_4cc_to_str(__parent->type) );\
 		GF_LOG(GF_LOG_WARNING, GF_LOG_CONTAINER, ("[iso file] extra box %s found in %s, deleting\n", gf_4cc_to_str(__abox->type), __ptype)); \
-		gf_isom_box_del(a);\
+		gf_isom_box_del(__abox);\
 		return GF_OK;\
 	}
 
```
