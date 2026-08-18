# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in cpp
**Pair ID:** 2487_0
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2487_0`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```cpp
Lines 460-500 of the vulnerable file.

    {
        TypeId typeId = JavascriptOperators::GetTypeId(aValue);
        return JavascriptArray::IsVarArray(typeId);
    }

    bool JavascriptArray::IsVarArray(TypeId typeId)
    {
        return typeId == TypeIds_Array;
    }

    template<typename T>
    bool JavascriptArray::IsMissingItemAt(uint32 index) const
    {
        SparseArraySegment<T>* headSeg = (SparseArraySegment<T>*)this->head;

        return SparseArraySegment<T>::IsMissingItem(&headSeg->elements[index]);
    }

    bool JavascriptArray::IsMissingItem(uint32 index)
    {
        bool isIntArray = false, isFloatArray = false;
        this->GetArrayTypeAndConvert(&isIntArray, &isFloatArray);

        if (isIntArray)
        {
            return IsMissingItemAt<int32>(index);
        }
        else if (isFloatArray)
        {
            return IsMissingItemAt<double>(index);
        }
        else
        {
            return IsMissingItemAt<Var>(index);
        }
    }

    JavascriptArray* JavascriptArray::FromVar(Var aValue)
    {
        AssertMsg(Is(aValue), "Ensure var is actually a 'JavascriptArray'");

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -477,6 +477,11 @@
 
     bool JavascriptArray::IsMissingItem(uint32 index)
     {
+        if (this->length <= index)
+        {
+            return false;
+        }
+
         bool isIntArray = false, isFloatArray = false;
         this->GetArrayTypeAndConvert(&isIntArray, &isFloatArray);
 
@@ -5767,7 +5772,7 @@
         // Prototype lookup for missing elements
         if (!pArr->HasNoMissingValues())
         {
-            for (uint32 i = 0; i < newLen; i++)
+            for (uint32 i = 0; i < newLen && (i + start) < pArr->length; i++)
             {
                 // array type might be changed in the below call to DirectGetItemAtFull
                 // need recheck array type before checking array item [i + start]
```
