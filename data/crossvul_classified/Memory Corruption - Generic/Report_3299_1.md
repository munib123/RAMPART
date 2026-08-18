# CrossVul Fix Pair: Out-of-bounds Write in cpp
**Pair ID:** 3299_1
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-787
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3299_1`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Write - Typically, this can result in corruption of data, a crash, or code execution.

## Vulnerable Code
```cpp
Lines 195-235 of the vulnerable file.

                {
                    // initialize new flags to zero
                    memset( pNewFlagAry+mnPoints, 0, nNewSize-mnPoints );
                    memcpy( pNewFlagAry, mpFlagAry, mnPoints );
                }
                else
                    memcpy( pNewFlagAry, mpFlagAry, nNewSize );
            }
        }
        else
            pNewFlagAry = nullptr;

        delete[] mpFlagAry;
        mpFlagAry  = pNewFlagAry;
    }

    mpPointAry = pNewAry;
    mnPoints   = nNewSize;
}

void ImplPolygon::ImplSplit( sal_uInt16 nPos, sal_uInt16 nSpace, ImplPolygon const * pInitPoly )
{
    //Can't fit this in :-(, throw ?
    if (mnPoints + nSpace > USHRT_MAX)
        return;

    const sal_uInt16    nNewSize = mnPoints + nSpace;
    const std::size_t   nSpaceSize = static_cast<std::size_t>(nSpace) * sizeof(Point);

    if( nPos >= mnPoints )
    {
        // Append at the back
        nPos = mnPoints;
        ImplSetSize( nNewSize );

        if( pInitPoly )
        {
            memcpy( mpPointAry + nPos, pInitPoly->mpPointAry, nSpaceSize );

            if( pInitPoly->mpFlagAry )
                memcpy( mpFlagAry + nPos, pInitPoly->mpFlagAry, nSpace );
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -212,11 +212,14 @@
     mnPoints   = nNewSize;
 }
 
-void ImplPolygon::ImplSplit( sal_uInt16 nPos, sal_uInt16 nSpace, ImplPolygon const * pInitPoly )
+bool ImplPolygon::ImplSplit( sal_uInt16 nPos, sal_uInt16 nSpace, ImplPolygon const * pInitPoly )
 {
     //Can't fit this in :-(, throw ?
     if (mnPoints + nSpace > USHRT_MAX)
-        return;
+    {
+        SAL_WARN("tools", "Polygon needs " << mnPoints + nSpace << " points, but only " << USHRT_MAX << " possible");
+        return false;
+    }
 
     const sal_uInt16    nNewSize = mnPoints + nSpace;
     const std::size_t   nSpaceSize = static_cast<std::size_t>(nSpace) * sizeof(Point);
@@ -272,6 +275,8 @@
         mpPointAry = pNewAry;
         mnPoints   = nNewSize;
     }
+
+    return true;
 }
 
 void ImplPolygon::ImplCreateFlagArray()
@@ -1472,8 +1477,8 @@
     if( nPos >= mpImplPolygon->mnPoints )
         nPos = mpImplPolygon->mnPoints;
 
-    mpImplPolygon->ImplSplit( nPos, 1 );
-    mpImplPolygon->mpPointAry[ nPos ] = rPt;
+    if (mpImplPolygon->ImplSplit(nPos, 1))
+        mpImplPolygon->mpPointAry[ nPos ] = rPt;
 }
 
 void Polygon::Insert( sal_uInt16 nPos, const tools::Polygon& rPoly )
```
