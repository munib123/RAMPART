# CrossVul Fix Pair: Loop with Unreachable Exit Condition ('Infinite Loop') in cpp
**Pair ID:** 3005_0
**Vulnerability Class:** Loop with Unreachable Exit Condition ('Infinite Loop')
**CWE:** CWE-835
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3005_0`)

## Vulnerability Information & PoC

## Description
Loop with Unreachable Exit Condition ('Infinite Loop') - If the loop can be influenced by an attacker, this weakness could allow attackers to consume excessive resources such as CPU or memory.

## Vulnerable Code
```cpp
Lines 1037-1077 of the vulnerable file.

    {
        if (object.getOwningQPDF() != &(this->pdf))
        {
            QTC::TC("qpdf", "QPDFWriter foreign object");
            throw std::logic_error(
                "QPDFObjectHandle from different QPDF found while writing."
                "  Use QPDF::copyForeignObject to add objects from"
                " another file.");
        }

	QPDFObjGen og = object.getObjGen();

	if (obj_renumber.count(og) == 0)
	{
	    if (this->object_to_object_stream.count(og))
	    {
		// This is in an object stream.  Don't process it
		// here.  Instead, enqueue the object stream.  Object
		// streams always have generation 0.
		int stream_id = this->object_to_object_stream[og];
		enqueueObject(this->pdf.getObjectByID(stream_id, 0));
	    }
	    else
	    {
		object_queue.push_back(object);
		obj_renumber[og] = next_objid++;

		if ((og.getGen() == 0) &&
                    this->object_stream_to_objects.count(og.getObj()))
		{
		    // For linearized files, uncompressed objects go
		    // at end, and we take care of assigning numbers
		    // to them elsewhere.
		    if (! this->linearized)
		    {
			assignCompressedObjectNumbers(og);
		    }
		}
		else if ((! this->direct_stream_lengths) && object.isStream())
		{
		    // reserve next object ID for length
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1054,6 +1054,9 @@
 		// here.  Instead, enqueue the object stream.  Object
 		// streams always have generation 0.
 		int stream_id = this->object_to_object_stream[og];
+                // Detect loops by storing invalid object ID 0, which
+                // will get overwritten later.
+                obj_renumber[og] = 0;
 		enqueueObject(this->pdf.getObjectByID(stream_id, 0));
 	    }
 	    else
@@ -1079,6 +1082,12 @@
 		}
 	    }
 	}
+        else if (obj_renumber[og] == 0)
+        {
+            // This can happen if a specially constructed file
+            // indicates that an object stream is inside itself.
+            QTC::TC("qpdf", "QPDFWriter ignore self-referential object stream");
+        }
     }
     else if (object.isArray())
     {
```
