# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 1357_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1357_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 194-234 of the vulnerable file.

      data->schematahash = schematahash = solv_calloc(256, sizeof(Id));
      for (i = 1; i < data->nschemata; i++)
	{
	  for (sp = data->schemadata + data->schemata[i], h = 0; *sp;)
	    h = h * 7 + *sp++;
	  h &= 255;
	  schematahash[h] = i;
	}
      data->schemadata = solv_extend_resize(data->schemadata, data->schemadatalen, sizeof(Id), SCHEMATADATA_BLOCK);
      data->schemata = solv_extend_resize(data->schemata, data->nschemata, sizeof(Id), SCHEMATA_BLOCK);
    }

  for (sp = schema, len = 0, h = 0; *sp; len++)
    h = h * 7 + *sp++;
  h &= 255;
  len++;

  cid = schematahash[h];
  if (cid)
    {
      if (!memcmp(data->schemadata + data->schemata[cid], schema, len * sizeof(Id)))
        return cid;
      /* cache conflict, do a slow search */
      for (cid = 1; cid < data->nschemata; cid++)
        if (!memcmp(data->schemadata + data->schemata[cid], schema, len * sizeof(Id)))
          return cid;
    }
  /* a new one */
  if (!create)
    return 0;
  data->schemadata = solv_extend(data->schemadata, data->schemadatalen, len, sizeof(Id), SCHEMATADATA_BLOCK);
  data->schemata = solv_extend(data->schemata, data->nschemata, 1, sizeof(Id), SCHEMATA_BLOCK);
  /* add schema */
  memcpy(data->schemadata + data->schemadatalen, schema, len * sizeof(Id));
  data->schemata[data->nschemata] = data->schemadatalen;
  data->schemadatalen += len;
  schematahash[h] = data->nschemata;
#if 0
fprintf(stderr, "schema2id: new schema\n");
#endif
  return data->nschemata++;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -211,11 +211,13 @@
   cid = schematahash[h];
   if (cid)
     {
-      if (!memcmp(data->schemadata + data->schemata[cid], schema, len * sizeof(Id)))
+      if ((data->schemata[cid] + len <= data->schemadatalen) &&
+			  !memcmp(data->schemadata + data->schemata[cid], schema, len * sizeof(Id)))
         return cid;
       /* cache conflict, do a slow search */
       for (cid = 1; cid < data->nschemata; cid++)
-        if (!memcmp(data->schemadata + data->schemata[cid], schema, len * sizeof(Id)))
+        if ((data->schemata[cid] + len <= data->schemadatalen) &&
+				!memcmp(data->schemadata + data->schemata[cid], schema, len * sizeof(Id)))
           return cid;
     }
   /* a new one */
```
