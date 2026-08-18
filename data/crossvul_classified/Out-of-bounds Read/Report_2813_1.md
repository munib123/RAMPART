# CrossVul Fix Pair: Out-of-bounds Read in cpp
**Pair ID:** 2813_1
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2813_1`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```cpp
Lines 230-270 of the vulnerable file.

    pps_sequence.m_ArrayCompleteness = 0;
    for (unsigned int i=0; i<picture_parameters.ItemCount(); i++) {
        pps_sequence.m_Nalus.Append(picture_parameters[i]);
    }
    if (pps_sequence.m_Nalus.ItemCount()) {
        m_Sequences.Append(pps_sequence);
    }
    
    UpdateRawBytes();
    m_Size32 += m_RawBytes.GetDataSize();
}

/*----------------------------------------------------------------------
|   AP4_HvccAtom::AP4_HvccAtom
+---------------------------------------------------------------------*/
AP4_HvccAtom::AP4_HvccAtom(AP4_UI32 size, const AP4_UI08* payload) :
    AP4_Atom(AP4_ATOM_TYPE_HVCC, size)
{
    // make a copy of our configuration bytes
    unsigned int payload_size = size-AP4_ATOM_HEADER_SIZE;
    m_RawBytes.SetData(payload, payload_size);

    // parse the payload
    m_ConfigurationVersion   = payload[0];
    m_GeneralProfileSpace    = (payload[1]>>6) & 0x03;
    m_GeneralTierFlag        = (payload[1]>>5) & 0x01;
    m_GeneralProfile         = (payload[1]   ) & 0x1F;
    m_GeneralProfileCompatibilityFlags = AP4_BytesToUInt32BE(&payload[2]);
    m_GeneralConstraintIndicatorFlags  = (((AP4_UI64)AP4_BytesToUInt32BE(&payload[6]))<<16) | AP4_BytesToUInt16BE(&payload[10]);
    m_GeneralLevel           = payload[12];
    m_Reserved1              = (payload[13]>>4) & 0x0F;
    m_MinSpatialSegmentation = AP4_BytesToUInt16BE(&payload[13]) & 0x0FFF;
    m_Reserved2              = (payload[15]>>2) & 0x3F;
    m_ParallelismType        = payload[15] & 0x03;
    m_Reserved3              = (payload[16]>>2) & 0x3F;
    m_ChromaFormat           = payload[16] & 0x03;
    m_Reserved4              = (payload[17]>>3) & 0x1F;
    m_LumaBitDepth           = 8+(payload[17] & 0x07);
    m_Reserved5              = (payload[18]>>3) & 0x1F;
    m_ChromaBitDepth         = 8+(payload[18] & 0x07);
    m_AverageFrameRate       = AP4_BytesToUInt16BE(&payload[19]);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -247,6 +247,9 @@
 {
     // make a copy of our configuration bytes
     unsigned int payload_size = size-AP4_ATOM_HEADER_SIZE;
+
+    // keep a raw copy
+    if (payload_size < 22) return;
     m_RawBytes.SetData(payload, payload_size);
 
     // parse the payload
```
