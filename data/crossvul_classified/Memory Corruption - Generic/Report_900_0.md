# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 900_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `900_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 1152-1192 of the vulnerable file.


	if ( shape->isEnded || shape->isMorph )
		return;
	
	if(fill == NOFILL)
	{
		record = addStyleRecord(shape);
		record.record.stateChange->leftFill = 0;
		record.record.stateChange->flags |= SWF_SHAPE_FILLSTYLE0FLAG;
		return;
	}

	idx = getFillIdx(shape, fill);
	if(idx == 0) // fill not present in array
	{
		SWFFillStyle_addDependency(fill, (SWFCharacter)shape);
		if(addFillStyle(shape, fill) < 0)
			return;		
		idx = getFillIdx(shape, fill);
	}
				
	record = addStyleRecord(shape);
	record.record.stateChange->leftFill = idx;
	record.record.stateChange->flags |= SWF_SHAPE_FILLSTYLE0FLAG;
}


void
SWFShape_setRightFillStyle(SWFShape shape, SWFFillStyle fill)
{
	ShapeRecord record;
	int idx;

	if ( shape->isEnded || shape->isMorph )
		return;
	
	if(fill == NOFILL)
	{
		record = addStyleRecord(shape);
		record.record.stateChange->rightFill = 0;
		record.record.stateChange->flags |= SWF_SHAPE_FILLSTYLE1FLAG;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1169,6 +1169,11 @@
 			return;		
 		idx = getFillIdx(shape, fill);
 	}
+	else if (idx >= 255 && shape->useVersion == SWF_SHAPE1)
+	{
+		SWF_error("Too many fills for SWFShape V1.\n" 
+			  "Use a higher SWFShape version\n");
+	}
 				
 	record = addStyleRecord(shape);
 	record.record.stateChange->leftFill = idx;
```
