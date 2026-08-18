# CrossVul Fix Pair: Out-of-bounds Write in cpp
**Pair ID:** 4860_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-787
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4860_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Write - Typically, this can result in corruption of data, a crash, or code execution.

## Vulnerable Code
```cpp
Lines 1235-1275 of the vulnerable file.

                    sal_uInt32 cbBmiSrc(0), offBitsSrc(0), cbBitsSrc(0);

                    sal_uInt32   nStart = pWMF->Tell() - 8;
                    pWMF->SeekRel( 0x10 );

                    pWMF->ReadInt32( xDest ).ReadInt32( yDest ).ReadInt32( cxDest ).ReadInt32( cyDest );
                    *pWMF >> aFunc;
                    pWMF->ReadInt32( xSrc ).ReadInt32( ySrc );
                    *pWMF >> xformSrc;
                    pWMF->ReadUInt32( BkColorSrc ).ReadUInt32( iUsageSrc ).ReadUInt32( offBmiSrc ).ReadUInt32( cbBmiSrc )
                               .ReadUInt32( offBitsSrc ).ReadUInt32( cbBitsSrc ).ReadInt32( cxSrc ).ReadInt32( cySrc ) ;

                    sal_uInt32  dwRop = SRCAND|SRCINVERT;
                    Rectangle   aRect( Point( xDest, yDest ), Size( cxDest+1, cyDest+1 ) );

                    if ( (cbBitsSrc > (SAL_MAX_UINT32 - 14)) || ((SAL_MAX_UINT32 - 14) - cbBitsSrc < cbBmiSrc) )
                        bStatus = false;
                    else
                    {
                        const sal_uInt32 nSourceSize = cbBmiSrc + cbBitsSrc + 14;
                        if ( nSourceSize <= ( nEndPos - nStartPos ) )
                        {
                            // we need to read alpha channel data if AlphaFormat of BLENDFUNCTION is
                            // AC_SRC_ALPHA (==0x01). To read it, create a temp DIB-File which is ready
                            // for DIB-5 format
                            const bool bReadAlpha(0x01 == aFunc.aAlphaFormat);
                            const sal_uInt32 nDeltaToDIB5HeaderSize(bReadAlpha ? getDIBV5HeaderSize() - cbBmiSrc : 0);
                            const sal_uInt32 nTargetSize(cbBmiSrc + nDeltaToDIB5HeaderSize + cbBitsSrc + 14);
                            char* pBuf = new char[ nTargetSize ];
                            SvMemoryStream aTmp( pBuf, nTargetSize, StreamMode::READ | StreamMode::WRITE );

                            aTmp.ObjectOwnsMemory( true );

                            // write BM-Header (14 bytes)
                            aTmp.WriteUChar( 'B' )
                                .WriteUChar( 'M' )
                                .WriteUInt32( cbBitsSrc )
                                .WriteUInt16( 0 )
                                .WriteUInt16( 0 )
                                .WriteUInt32( cbBmiSrc + nDeltaToDIB5HeaderSize + 14 );

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1252,13 +1252,22 @@
                     else
                     {
                         const sal_uInt32 nSourceSize = cbBmiSrc + cbBitsSrc + 14;
-                        if ( nSourceSize <= ( nEndPos - nStartPos ) )
+                        bool bSafeRead = nSourceSize <= (nEndPos - nStartPos);
+                        sal_uInt32 nDeltaToDIB5HeaderSize(0);
+                        const bool bReadAlpha(0x01 == aFunc.aAlphaFormat);
+                        if (bSafeRead && bReadAlpha)
                         {
                             // we need to read alpha channel data if AlphaFormat of BLENDFUNCTION is
                             // AC_SRC_ALPHA (==0x01). To read it, create a temp DIB-File which is ready
                             // for DIB-5 format
-                            const bool bReadAlpha(0x01 == aFunc.aAlphaFormat);
-                            const sal_uInt32 nDeltaToDIB5HeaderSize(bReadAlpha ? getDIBV5HeaderSize() - cbBmiSrc : 0);
+                            const sal_uInt32 nHeaderSize = getDIBV5HeaderSize();
+                            if (cbBmiSrc > nHeaderSize)
+                                bSafeRead = false;
+                            else
+                                nDeltaToDIB5HeaderSize = nHeaderSize - cbBmiSrc;
+                        }
+                        if (bSafeRead)
+                        {
                             const sal_uInt32 nTargetSize(cbBmiSrc + nDeltaToDIB5HeaderSize + cbBitsSrc + 14);
                             char* pBuf = new char[ nTargetSize ];
                             SvMemoryStream aTmp( pBuf, nTargetSize, StreamMode::READ | StreamMode::WRITE );
@@ -1277,7 +1286,7 @@
                             pWMF->Seek( nStart + offBmiSrc );
                             pWMF->ReadBytes(pBuf + 14, cbBmiSrc);
 
-                            if(bReadAlpha)
+                            if (bReadAlpha)
                             {
                                 // need to add values for all stuff that DIBV5Header is bigger
                                 // than DIBInfoHeader, all values are correctly initialized to zero,
```
