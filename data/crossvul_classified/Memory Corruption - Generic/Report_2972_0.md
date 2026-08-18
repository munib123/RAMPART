# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in cpp
**Pair ID:** 2972_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2972_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```cpp
Lines 316-356 of the vulnerable file.

                        int v = ((ushort *)src)[x];
                        src[x] = (uchar)(v >> 8);
                    }
                }

                if( m_bpp == 8 ) // image has one channel
                {
                    if( color )
                    {
                        if( img.depth() == CV_8U ) {
                            uchar *d = data, *s = src, *end = src + m_width;
                            for( ; s < end; d += 3, s++)
                                d[0] = d[1] = d[2] = *s;
                        } else {
                            ushort *d = (ushort *)data, *s = (ushort *)src, *end = ((ushort *)src) + m_width;
                            for( ; s < end; s++, d += 3)
                                d[0] = d[1] = d[2] = *s;
                        }
                    }
                    else
                        memcpy( data, src, CV_ELEM_SIZE1(m_type)*m_width);
                }
                else
                {
                    if( color )
                    {
                        if( img.depth() == CV_8U )
                            icvCvt_RGB2BGR_8u_C3R( src, 0, data, 0, cvSize(m_width,1) );
                        else
                            icvCvt_RGB2BGR_16u_C3R( (ushort *)src, 0, (ushort *)data, 0, cvSize(m_width,1) );
                    }
                    else if( img.depth() == CV_8U )
                        icvCvt_BGR2Gray_8u_C3C1R( src, 0, data, 0, cvSize(m_width,1), 2 );
                    else
                        icvCvt_BGRA2Gray_16u_CnC1R( (ushort *)src, 0, (ushort *)data, 0, cvSize(m_width,1), 3, 2 );
                }
            }
            result = true;
            break;
        }
        default:
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -333,7 +333,7 @@
                         }
                     }
                     else
-                        memcpy( data, src, CV_ELEM_SIZE1(m_type)*m_width);
+                        memcpy(data, src, img.elemSize1()*m_width);
                 }
                 else
                 {
```
