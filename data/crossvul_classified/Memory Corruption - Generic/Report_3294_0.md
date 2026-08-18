# CrossVul Fix Pair: Out-of-bounds Write in cpp
**Pair ID:** 3294_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-787
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3294_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Write - Typically, this can result in corruption of data, a crash, or code execution.

## Vulnerable Code
```cpp
Lines 971-1011 of the vulnerable file.

                            for (sal_Int32 j = 0; j < nAryLen; ++j)
                                rIStm.ReadInt32( nTmp ), pDXAry[ j ] = nTmp;

                            // #106172# Add last DX array elem, if missing
                            if( nAryLen != nStrLen )
                            {
                                if (nAryLen+1 == nStrLen && nIndex >= 0)
                                {
                                    std::unique_ptr<long[]> pTmpAry(new long[nStrLen]);

                                    aFontVDev->GetTextArray( aStr, pTmpAry.get(), nIndex, nLen );

                                    // now, the difference between the
                                    // last and the second last DX array
                                    // is the advancement for the last
                                    // glyph. Thus, to complete our meta
                                    // action's DX array, just add that
                                    // difference to last elem and store
                                    // in very last.
                                    if( nStrLen > 1 )
                                        pDXAry[ nStrLen-3 ] = pDXAry[ nStrLen-2 ] + pTmpAry[ nStrLen-1 ] - pTmpAry[ nStrLen-2 ];
                                    else
                                        pDXAry[ nStrLen-1 ] = pTmpAry[ nStrLen-1 ]; // len=1: 0th position taken to be 0
                                }
#ifdef DBG_UTIL
                                else
                                    OSL_FAIL("More than one DX array element missing on SVM import");
#endif
                            }
                        }
                    }
                    if ( nUnicodeCommentActionNumber == i )
                        ImplReadUnicodeComment( nUnicodeCommentStreamPos, rIStm, aStr );
                    rMtf.AddAction( new MetaTextArrayAction( aPt, aStr, pDXAry.get(), nIndex, nLen ) );
                }
                rIStm.Seek( nActBegin + nActionSize );
            }
            break;

            case GDI_STRETCHTEXT_ACTION:
            {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -988,7 +988,7 @@
                                     // difference to last elem and store
                                     // in very last.
                                     if( nStrLen > 1 )
-                                        pDXAry[ nStrLen-3 ] = pDXAry[ nStrLen-2 ] + pTmpAry[ nStrLen-1 ] - pTmpAry[ nStrLen-2 ];
+                                        pDXAry[ nStrLen-1 ] = pDXAry[ nStrLen-2 ] + pTmpAry[ nStrLen-1 ] - pTmpAry[ nStrLen-2 ];
                                     else
                                         pDXAry[ nStrLen-1 ] = pTmpAry[ nStrLen-1 ]; // len=1: 0th position taken to be 0
                                 }
```
