# CrossVul Fix Pair: Out-of-bounds Read in cpp
**Pair ID:** 2812_1
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2812_1`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```cpp
Lines 56-96 of the vulnerable file.

+---------------------------------------------------------------------*/
AP4_StszAtom::AP4_StszAtom() :
    AP4_Atom(AP4_ATOM_TYPE_STSZ, AP4_FULL_ATOM_HEADER_SIZE+8, 0, 0),
    m_SampleSize(0),
    m_SampleCount(0)
{
}

/*----------------------------------------------------------------------
|   AP4_StszAtom::AP4_StszAtom
+---------------------------------------------------------------------*/
AP4_StszAtom::AP4_StszAtom(AP4_UI32        size, 
                           AP4_UI08        version,
                           AP4_UI32        flags,
                           AP4_ByteStream& stream) :
    AP4_Atom(AP4_ATOM_TYPE_STSZ, size, version, flags)
{
    stream.ReadUI32(m_SampleSize);
    stream.ReadUI32(m_SampleCount);
    if (m_SampleSize == 0) { // means that the samples have different sizes
        AP4_Cardinal sample_count = m_SampleCount;
        m_Entries.SetItemCount(sample_count);
        unsigned char* buffer = new unsigned char[sample_count*4];
        AP4_Result result = stream.Read(buffer, sample_count*4);
        if (AP4_FAILED(result)) {
            delete[] buffer;
            return;
        }
        for (unsigned int i=0; i<sample_count; i++) {
            m_Entries[i] = AP4_BytesToUInt32BE(&buffer[i*4]);
        }
        delete[] buffer;
    }
}

/*----------------------------------------------------------------------
|   AP4_StszAtom::WriteFields
+---------------------------------------------------------------------*/
AP4_Result
AP4_StszAtom::WriteFields(AP4_ByteStream& stream)
{
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -73,6 +73,13 @@
     stream.ReadUI32(m_SampleSize);
     stream.ReadUI32(m_SampleCount);
     if (m_SampleSize == 0) { // means that the samples have different sizes
+        // check for overflow
+        if (m_SampleCount > (size-8)/4) {
+            m_SampleCount = 0;
+            return;
+        }
+        
+        // read the entries
         AP4_Cardinal sample_count = m_SampleCount;
         m_Entries.SetItemCount(sample_count);
         unsigned char* buffer = new unsigned char[sample_count*4];
```
