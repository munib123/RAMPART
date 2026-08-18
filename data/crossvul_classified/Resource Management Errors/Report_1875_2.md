# CrossVul Fix Pair: Resource Management Errors in cpp
**Pair ID:** 1875_2
**Vulnerability Class:** Resource Management Errors
**CWE:** CWE-399
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1875_2`)

## Vulnerability Information & PoC

## Description
Resource Management Errors

## Vulnerable Code
```cpp
Lines 1454-1494 of the vulnerable file.

			      "EOF after endobj");
	    }
	}
	qpdf_offset_t end_after_space = this->file->tell();

	this->obj_cache[og] =
	    ObjCache(QPDFObjectHandle::ObjAccessor::getObject(oh),
		     end_before_space, end_after_space);
    }

    return oh;
}

PointerHolder<QPDFObject>
QPDF::resolve(int objid, int generation)
{
    // Check object cache before checking xref table.  This allows us
    // to insert things into the object cache that don't actually
    // exist in the file.
    QPDFObjGen og(objid, generation);
    if (! this->obj_cache.count(og))
    {
	if (! this->xref_table.count(og))
	{
	    // PDF spec says unknown objects resolve to the null object.
	    return new QPDF_Null;
	}

	QPDFXRefEntry const& entry = this->xref_table[og];
	switch (entry.getType())
	{
	  case 1:
	    {
		qpdf_offset_t offset = entry.getOffset();
		// Object stored in cache by readObjectAtOffset
		int aobjid;
		int ageneration;
		QPDFObjectHandle oh =
		    readObjectAtOffset(true, offset, "", objid, generation,
				       aobjid, ageneration);
	    }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1471,6 +1471,21 @@
     // to insert things into the object cache that don't actually
     // exist in the file.
     QPDFObjGen og(objid, generation);
+    if (this->resolving.count(og))
+    {
+        // This can happen if an object references itself directly or
+        // indirectly in some key that has to be resolved during
+        // object parsing, such as stream length.
+	QTC::TC("qpdf", "QPDF recursion loop in resolve");
+	warn(QPDFExc(qpdf_e_damaged_pdf, this->file->getName(),
+		     "", this->file->getLastOffset(),
+		     "loop detected resolving object " +
+		     QUtil::int_to_string(objid) + " " +
+		     QUtil::int_to_string(generation)));
+        return new QPDF_Null;
+    }
+    ResolveRecorder rr(this, og);
+
     if (! this->obj_cache.count(og))
     {
 	if (! this->xref_table.count(og))
```
