# CrossVul Fix Pair: NULL Pointer Dereference in cpp
**Pair ID:** 2810_0
**Vulnerability Class:** NULL Pointer Dereference
**CWE:** CWE-476
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2810_0`)

## Vulnerability Information & PoC

## Description
NULL Pointer Dereference - NULL pointer dereference issues can occur through a number of flaws, including race conditions, and simple programming omissions.

## Vulnerable Code
```cpp
Lines 1241-1281 of the vulnerable file.


/*----------------------------------------------------------------------
|   AP4_AtomMetaDataValue::ToInteger
+---------------------------------------------------------------------*/
long       
AP4_AtomMetaDataValue::ToInteger() const
{
    long value;
    if (AP4_SUCCEEDED(m_DataAtom->LoadInteger(value))) {
        return value;
    } else {
        return 0;
    }
}

/*----------------------------------------------------------------------
|   AP4_DataAtom::AP4_DataAtom
+---------------------------------------------------------------------*/
AP4_DataAtom::AP4_DataAtom(const AP4_MetaData::Value& value) :
    AP4_Atom(AP4_ATOM_TYPE_DATA, AP4_ATOM_HEADER_SIZE),
    m_DataType(DATA_TYPE_BINARY)
{
    AP4_MemoryByteStream* memory = new AP4_MemoryByteStream();
    AP4_Size payload_size = 8;
    m_Source = memory;
    
    switch (value.GetType()) {
        case AP4_MetaData::Value::TYPE_STRING_UTF_8: {
            m_DataType = DATA_TYPE_STRING_UTF_8;
            AP4_String string_value = value.ToString();
            if (string_value.GetLength()) {
                memory->Write(string_value.GetChars(), string_value.GetLength());
            }
            payload_size += string_value.GetLength();
            break;
        }
         
        case AP4_MetaData::Value::TYPE_INT_08_BE: {
            m_DataType = DATA_TYPE_SIGNED_INT_BE;
            AP4_UI08 int_value = (AP4_UI08)value.ToInteger();
            memory->Write(&int_value, 1);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1258,7 +1258,8 @@
 +---------------------------------------------------------------------*/
 AP4_DataAtom::AP4_DataAtom(const AP4_MetaData::Value& value) :
     AP4_Atom(AP4_ATOM_TYPE_DATA, AP4_ATOM_HEADER_SIZE),
-    m_DataType(DATA_TYPE_BINARY)
+    m_DataType(DATA_TYPE_BINARY),
+    m_Source(NULL)
 {
     AP4_MemoryByteStream* memory = new AP4_MemoryByteStream();
     AP4_Size payload_size = 8;
@@ -1334,7 +1335,8 @@
 |   AP4_DataAtom::AP4_DataAtom
 +---------------------------------------------------------------------*/
 AP4_DataAtom::AP4_DataAtom(AP4_UI32 size, AP4_ByteStream& stream) :
-    AP4_Atom(AP4_ATOM_TYPE_DATA, size)
+    AP4_Atom(AP4_ATOM_TYPE_DATA, size),
+    m_Source(NULL)
 {
     if (size < AP4_ATOM_HEADER_SIZE+8) return;
 
```
