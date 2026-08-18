# CrossVul Fix Pair: Uncontrolled Resource Consumption in c
**Pair ID:** 551_0
**Vulnerability Class:** Uncontrolled Resource Consumption
**CWE:** CWE-400
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `551_0`)

## Vulnerability Information & PoC

## Description
Uncontrolled Resource Consumption - Limited resources include memory, file system storage, database connection pool entries, and CPU.

## Vulnerable Code
```c
Lines 914-954 of the vulnerable file.

	GF_DataInformationBox *ptr = (GF_DataInformationBox *)s;
	switch(a->type) {
	case GF_ISOM_BOX_TYPE_DREF:
		if (ptr->dref) ERROR_ON_DUPLICATED_BOX(a, ptr)

			ptr->dref = (GF_DataReferenceBox *)a;
		return GF_OK;
	default:
		return gf_isom_box_add_default(s, a);
	}
	return GF_OK;
}

GF_Err dinf_Read(GF_Box *s, GF_BitStream *bs)
{
	GF_Err e = gf_isom_box_array_read(s, bs, dinf_AddBox);
	if (e) {
		return e;
	}
	if (!((GF_DataInformationBox *)s)->dref) {
		GF_LOG(GF_LOG_ERROR, GF_LOG_CONTAINER, ("[iso file] Missing dref box in dinf\n"));
		((GF_DataInformationBox *)s)->dref = (GF_DataReferenceBox *)gf_isom_box_new(GF_ISOM_BOX_TYPE_DREF);
	}
	return GF_OK;
}

GF_Box *dinf_New()
{
	ISOM_DECL_BOX_ALLOC(GF_DataInformationBox, GF_ISOM_BOX_TYPE_DINF);
	return (GF_Box *)tmp;
}

#ifndef GPAC_DISABLE_ISOM_WRITE

GF_Err dinf_Write(GF_Box *s, GF_BitStream *bs)
{
	GF_Err e;
	GF_DataInformationBox *ptr = (GF_DataInformationBox *)s;

	e = gf_isom_box_write_header(s, bs);
	if (e) return e;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -931,8 +931,11 @@
 		return e;
 	}
 	if (!((GF_DataInformationBox *)s)->dref) {
+		GF_Box* dref;
 		GF_LOG(GF_LOG_ERROR, GF_LOG_CONTAINER, ("[iso file] Missing dref box in dinf\n"));
-		((GF_DataInformationBox *)s)->dref = (GF_DataReferenceBox *)gf_isom_box_new(GF_ISOM_BOX_TYPE_DREF);
+		dref = gf_isom_box_new(GF_ISOM_BOX_TYPE_DREF);
+		((GF_DataInformationBox *)s)->dref = (GF_DataReferenceBox *)dref;
+		gf_isom_box_add_for_dump_mode(s, dref);
 	}
 	return GF_OK;
 }
```
