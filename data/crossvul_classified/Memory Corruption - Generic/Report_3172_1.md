# CrossVul Fix Pair: Out-of-bounds Write in c
**Pair ID:** 3172_1
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-787
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3172_1`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Write - Typically, this can result in corruption of data, a crash, or code execution.

## Vulnerable Code
```c
Lines 149-192 of the vulnerable file.

static VarLenData**
get_text_data (Attr *attr)
{
    VarLenData **body = XCALLOC(VarLenData*, 2);

    body[0] = XCALLOC(VarLenData, 1);
    body[0]->len = attr->len;
    body[0]->data = CHECKED_XCALLOC(unsigned char, attr->len);
    memmove (body[0]->data, attr->buf, attr->len);
    return body;
}

static VarLenData**
get_html_data (MAPI_Attr *a)
{
    VarLenData **body = XCALLOC(VarLenData*, a->num_values + 1);

    int j;
    for (j = 0; j < a->num_values; j++)
    {
	body[j] = XMALLOC(VarLenData, 1);
	body[j]->len = a->values[j].len;
	body[j]->data = CHECKED_XCALLOC(unsigned char, a->values[j].len);
	memmove (body[j]->data, a->values[j].data.buf, body[j]->len);
    }
    return body;
}

int
data_left (FILE* input_file)
{
    int retval = 1;
    
    if (feof(input_file)) retval = 0;
    else if (input_file != stdin)
    {
	/* check if there is enough data left */
	struct stat statbuf;
	size_t pos, data_left;
	fstat (fileno(input_file), &statbuf);
	pos = ftell(input_file);
	data_left = (statbuf.st_size - pos);

	if (data_left > 0 && data_left < MINIMUM_ATTR_LENGTH) 
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -166,10 +166,12 @@
     int j;
     for (j = 0; j < a->num_values; j++)
     {
-	body[j] = XMALLOC(VarLenData, 1);
-	body[j]->len = a->values[j].len;
-	body[j]->data = CHECKED_XCALLOC(unsigned char, a->values[j].len);
-	memmove (body[j]->data, a->values[j].data.buf, body[j]->len);
+        if (a->type == szMAPI_BINARY) {
+ 	    body[j] = XMALLOC(VarLenData, 1);
+	    body[j]->len = a->values[j].len;
+	    body[j]->data = CHECKED_XCALLOC(unsigned char, a->values[j].len);
+	    memmove (body[j]->data, a->values[j].data.buf, body[j]->len);
+        }
     }
     return body;
 }
@@ -308,13 +310,13 @@
 		    for (i = 0; mapi_attrs[i]; i++)
 		    {
 			MAPI_Attr *a = mapi_attrs[i];
-			    
-			if (a->name == MAPI_BODY_HTML)
+		
+			if (a->type == szMAPI_BINARY && a->name == MAPI_BODY_HTML)
 			{
 			    body.html_bodies = get_html_data (a);
                                 html_size = a->num_values;
 			}
-			else if (a->name == MAPI_RTF_COMPRESSED)
+			else if (a->type == szMAPI_BINARY && a->name == MAPI_RTF_COMPRESSED)
 			{
 			    body.rtf_bodies = get_rtf_data (a);
                                 rtf_size = a->num_values;
```
