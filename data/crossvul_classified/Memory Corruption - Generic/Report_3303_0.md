# CrossVul Fix Pair: Out-of-bounds Write in cpp
**Pair ID:** 3303_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-787
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3303_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Write - Typically, this can result in corruption of data, a crash, or code execution.

## Vulnerable Code
```cpp
Lines 340-380 of the vulnerable file.

                     ReadBlock(_hwpInfo.back_info.filename, 260);
                     ReadBlock(_hwpInfo.back_info.color, 3);
                     unsigned short nFlag;
                     if (!Read2b(nFlag))
                        return;
                     _hwpInfo.back_info.flag = nFlag >> 8 ;
                     int nRange;
                     if (!Read4b(nRange))
                        return;
                     _hwpInfo.back_info.range = nRange >> 24;
                     ReadBlock(_hwpInfo.back_info.reserved3, 27);
                     if (!Read4b(_hwpInfo.back_info.size))
                        return;

                     if (_hwpInfo.back_info.size < 0)
                     {
                        _hwpInfo.back_info.size = 0;
                        return;
                     }

                     //read potentially compressed data in blocks as its more
                     //likely large values are simply broken and we'll run out
                     //of data before we need to realloc
                     for (int i = 0; i < _hwpInfo.back_info.size; i+= SAL_MAX_UINT16)
                     {
                        int nOldSize = _hwpInfo.back_info.data.size();
                        size_t nBlock = std::min<int>(SAL_MAX_UINT16, _hwpInfo.back_info.size - nOldSize);
                        _hwpInfo.back_info.data.resize(nOldSize + nBlock);
                        size_t nReadBlock = ReadBlock(_hwpInfo.back_info.data.data() + nOldSize, nBlock);
                        if (nBlock != nReadBlock)
                        {
                            _hwpInfo.back_info.data.resize(nOldSize + nReadBlock);
                            break;
                        }
                     }
                     _hwpInfo.back_info.size = _hwpInfo.back_info.data.size();

                     if( _hwpInfo.back_info.size > 0 )
                          _hwpInfo.back_info.type = 2;
                     else if( _hwpInfo.back_info.filename[0] )
                          _hwpInfo.back_info.type = 1;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -357,6 +357,8 @@
                         return;
                      }
 
+                     _hwpInfo.back_info.data.clear();
+
                      //read potentially compressed data in blocks as its more
                      //likely large values are simply broken and we'll run out
                      //of data before we need to realloc
```
