# CrossVul Fix Pair: Access of Resource Using Incompatible Type ('Type Confusion') in cpp
**Pair ID:** 2808_0
**Vulnerability Class:** Access of Resource Using Incompatible Type ('Type Confusion')
**CWE:** CWE-843
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2808_0`)

## Vulnerability Information & PoC

## Description
Access of Resource Using Incompatible Type ('Type Confusion') - When the product accesses the resource using an incompatible type, this could trigger logical errors because the resource does not have expected properties.

## Vulnerable Code
```cpp
Lines 755-795 of the vulnerable file.

|   AP4_VisualSampleEntry::ReadFields
+---------------------------------------------------------------------*/
AP4_Result
AP4_VisualSampleEntry::ReadFields(AP4_ByteStream& stream)
{
    // sample entry
    AP4_Result result = AP4_SampleEntry::ReadFields(stream);
    if (result < 0) return result;

    // read fields from this class
    stream.ReadUI16(m_Predefined1);
    stream.ReadUI16(m_Reserved2);
    stream.Read(m_Predefined2, sizeof(m_Predefined2));
    stream.ReadUI16(m_Width);
    stream.ReadUI16(m_Height);
    stream.ReadUI32(m_HorizResolution);
    stream.ReadUI32(m_VertResolution);
    stream.ReadUI32(m_Reserved3);
    stream.ReadUI16(m_FrameCount);

    char compressor_name[33];
    compressor_name[32] = 0;
    stream.Read(compressor_name, 32);
    int name_length = compressor_name[0];
    if (name_length < 32) {
        compressor_name[name_length+1] = 0; // force null termination
        m_CompressorName = &compressor_name[1];
    }

    stream.ReadUI16(m_Depth);
    stream.ReadUI16(m_Predefined3);

    return AP4_SUCCESS;
}

/*----------------------------------------------------------------------
|   AP4_VisualSampleEntry::WriteFields
+---------------------------------------------------------------------*/
AP4_Result
AP4_VisualSampleEntry::WriteFields(AP4_ByteStream& stream)
{
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -772,13 +772,13 @@
     stream.ReadUI32(m_Reserved3);
     stream.ReadUI16(m_FrameCount);
 
-    char compressor_name[33];
+    AP4_UI08 compressor_name[33];
     compressor_name[32] = 0;
     stream.Read(compressor_name, 32);
-    int name_length = compressor_name[0];
+    AP4_UI08 name_length = compressor_name[0];
     if (name_length < 32) {
         compressor_name[name_length+1] = 0; // force null termination
-        m_CompressorName = &compressor_name[1];
+        m_CompressorName = (const char*)(&compressor_name[1]);
     }
 
     stream.ReadUI16(m_Depth);
```
