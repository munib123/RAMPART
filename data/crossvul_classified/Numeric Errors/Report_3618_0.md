# CrossVul Fix Pair: Numeric Errors in cpp
**Pair ID:** 3618_0
**Vulnerability Class:** Numeric Errors
**CWE:** CWE-189
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3618_0`)

## Vulnerability Information & PoC

## Description
Numeric Errors

## Vulnerable Code
```cpp
Lines 346-386 of the vulnerable file.

char *ByteVector::data()
{
  detach();
  return size() > 0 ? DATA(d) : 0;
}

const char *ByteVector::data() const
{
  return size() > 0 ? DATA(d) : 0;
}

ByteVector ByteVector::mid(uint index, uint length) const
{
  ByteVector v;

  if(index > size())
    return v;

  ConstIterator endIt;

  if(length < 0xffffffff && length + index < size())
    endIt = d->data.begin() + index + length;
  else
    endIt = d->data.end();

  v.d->data.insert(v.d->data.begin(), ConstIterator(d->data.begin() + index), endIt);
  v.d->size = v.d->data.size();

  return v;
}

char ByteVector::at(uint index) const
{
  return index < size() ? d->data[index] : 0;
}

int ByteVector::find(const ByteVector &pattern, uint offset, int byteAlign) const
{
  return vectorFind<ByteVector>(*this, pattern, offset, byteAlign);
}

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -363,7 +363,7 @@
 
   ConstIterator endIt;
 
-  if(length < 0xffffffff && length + index < size())
+  if(length < size() - index)
     endIt = d->data.begin() + index + length;
   else
     endIt = d->data.end();
```
