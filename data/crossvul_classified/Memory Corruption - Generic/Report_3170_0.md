# CrossVul Fix Pair: Out-of-bounds Write in c
**Pair ID:** 3170_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-787
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3170_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Write - Typically, this can result in corruption of data, a crash, or code execution.

## Vulnerable Code
```c
Lines 157-197 of the vulnerable file.

    }
    return NULL;
}

/*
  2009/07/07
  Microsoft documentation reference: [MS-OXPROPS] v 2.0, April 10, 2009

  only multivalue types appearing are:
  szMAPI_INT, szMAPI_SYSTIME, szMAPI_UNICODE_STRING, szMAPI_BINARY
*/

/* parses out the MAPI attibutes hidden in the character buffer */
MAPI_Attr**
mapi_attr_read (size_t len, unsigned char *buf)
{
    size_t idx = 0;
    uint32 i,j;
    assert(len > 4);
    uint32 num_properties = GETINT32(buf+idx);
    MAPI_Attr** attrs = CHECKED_XMALLOC (MAPI_Attr*, (num_properties + 1));

    idx += 4;

    if (!attrs) return NULL;
    for (i = 0; i < num_properties; i++)
    {
	MAPI_Attr* a = attrs[i] = CHECKED_XCALLOC(MAPI_Attr, 1);
	MAPI_Value* v = NULL;

	CHECKINT16(idx, len); a->type = GETINT16(buf+idx); idx += 2;
	CHECKINT16(idx, len); a->name = GETINT16(buf+idx); idx += 2;

	/* handle special case of GUID prefixed properties */
	if (a->name & GUID_EXISTS_FLAG)
	{
	    /* copy GUID */
	    a->guid = CHECKED_XMALLOC(GUID, 1);
	    copy_guid_from_buf(a->guid, buf+idx, len);
	    idx += sizeof (GUID);

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -174,6 +174,7 @@
     uint32 i,j;
     assert(len > 4);
     uint32 num_properties = GETINT32(buf+idx);
+    assert((num_properties+1) != 0);
     MAPI_Attr** attrs = CHECKED_XMALLOC (MAPI_Attr*, (num_properties + 1));
 
     idx += 4;
@@ -212,6 +213,7 @@
 		    /* read the data into a buffer */
 		    a->names[i].data 
 			= CHECKED_XMALLOC(unsigned char, a->names[i].len);
+		    assert((idx+(a->names[i].len*2)) <= len);
 		    for (j = 0; j < (a->names[i].len >> 1); j++)
 			a->names[i].data[j] = (buf+idx)[j*2];
 
@@ -308,8 +310,11 @@
 	    case szMAPI_BINARY:
 		CHECKINT32(idx, len); v->len = GETINT32(buf+idx); idx += 4;
 
+		assert(v->len + idx <= len);
+
 		if (a->type == szMAPI_UNICODE_STRING)
 		{
+		    assert(v->len != 0);
 		    v->data.buf = (unsigned char*)unicode_to_utf8(v->len, buf+idx);
 		}
 		else
```
