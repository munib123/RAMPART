# CrossVul Fix Pair: Out-of-bounds Write in c
**Pair ID:** 3299_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-787
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3299_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Write - Typically, this can result in corruption of data, a crash, or code execution.

## Vulnerable Code
```c
Lines 26-66 of the vulnerable file.


class SAL_WARN_UNUSED ImplPolygonData
{
public:
    Point*          mpPointAry;
    PolyFlags*      mpFlagAry;
    sal_uInt16      mnPoints;
    sal_uInt32      mnRefCount;
};

class SAL_WARN_UNUSED ImplPolygon  : public ImplPolygonData
{
public:
                    ImplPolygon( sal_uInt16 nInitSize, bool bFlags = false );
                    ImplPolygon( sal_uInt16 nPoints, const Point* pPtAry, const PolyFlags* pInitFlags );
                    ImplPolygon( const ImplPolygon& rImplPoly );
                    ~ImplPolygon();

    void            ImplSetSize( sal_uInt16 nSize, bool bResize = true );
    void            ImplCreateFlagArray();
    void            ImplSplit( sal_uInt16 nPos, sal_uInt16 nSpace, ImplPolygon const * pInitPoly = nullptr );
};

#define MAX_POLYGONS        ((sal_uInt16)0x3FF0)

namespace tools {
class Polygon;
}

class SAL_WARN_UNUSED ImplPolyPolygon
{
public:
    tools::Polygon** mpPolyAry;
    sal_uInt32          mnRefCount;
    sal_uInt16          mnCount;
    sal_uInt16          mnSize;
    sal_uInt16          mnResize;

                    ImplPolyPolygon( sal_uInt16 nInitSize, sal_uInt16 nResize )
                        { mpPolyAry = nullptr; mnCount = 0; mnRefCount = 1;
                          mnSize = nInitSize; mnResize = nResize; }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -43,7 +43,7 @@
 
     void            ImplSetSize( sal_uInt16 nSize, bool bResize = true );
     void            ImplCreateFlagArray();
-    void            ImplSplit( sal_uInt16 nPos, sal_uInt16 nSpace, ImplPolygon const * pInitPoly = nullptr );
+    bool            ImplSplit( sal_uInt16 nPos, sal_uInt16 nSpace, ImplPolygon const * pInitPoly = nullptr );
 };
 
 #define MAX_POLYGONS        ((sal_uInt16)0x3FF0)
```
