# CrossVul Fix Pair: NULL Pointer Dereference in cpp
**Pair ID:** 656_1
**Vulnerability Class:** NULL Pointer Dereference
**CWE:** CWE-476
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `656_1`)

## Vulnerability Information & PoC

## Description
NULL Pointer Dereference - NULL pointer dereference issues can occur through a number of flaws, including race conditions, and simple programming omissions.

## Vulnerable Code
```cpp
Lines 67-107 of the vulnerable file.


        value_type          operator * () const {
            return value_type(key(), be::peek<uint16>(_v));
        }

    protected:
        const byte     * _e, * _v;
        size_t        _n;
    };

    typedef _glat_iterator<uint8>   glat_iterator;
    typedef _glat_iterator<uint16>  glat2_iterator;
}

const SlantBox SlantBox::empty = {0,0,0,0};


class GlyphCache::Loader
{
public:
    Loader(const Face & face, const bool dumb_font);    //return result indicates success. Do not use if failed.

    operator bool () const throw();
    unsigned short int units_per_em() const throw();
    unsigned short int num_glyphs() const throw();
    unsigned short int num_attrs() const throw();
    bool has_boxes() const throw();

    const GlyphFace * read_glyph(unsigned short gid, GlyphFace &, int *numsubs) const throw();
    GlyphBox * read_box(uint16 gid, GlyphBox *curr, const GlyphFace & face) const throw();

    CLASS_NEW_DELETE;
private:
    Face::Table _head,
                _hhea,
                _hmtx,
                _glyf,
                _loca,
                m_pGlat,
                m_pGloc;

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -84,7 +84,7 @@
 class GlyphCache::Loader
 {
 public:
-    Loader(const Face & face, const bool dumb_font);    //return result indicates success. Do not use if failed.
+    Loader(const Face & face);    //return result indicates success. Do not use if failed.
 
     operator bool () const throw();
     unsigned short int units_per_em() const throw();
@@ -115,7 +115,7 @@
 
 
 GlyphCache::GlyphCache(const Face & face, const uint32 face_options)
-: _glyph_loader(new Loader(face, bool(face_options & gr_face_dumbRendering))),
+: _glyph_loader(new Loader(face)),
   _glyphs(_glyph_loader && *_glyph_loader && _glyph_loader->num_glyphs()
         ? grzeroalloc<const GlyphFace *>(_glyph_loader->num_glyphs()) : 0),
   _boxes(_glyph_loader && _glyph_loader->has_boxes() && _glyph_loader->num_glyphs()
@@ -239,7 +239,7 @@
 
 
 
-GlyphCache::Loader::Loader(const Face & face, const bool dumb_font)
+GlyphCache::Loader::Loader(const Face & face)
 : _head(face, Tag::head),
   _hhea(face, Tag::hhea),
   _hmtx(face, Tag::hmtx),
@@ -265,52 +265,49 @@
         return;
     }
 
-    if (!dumb_font)
-    {
-        if ((m_pGlat = Face::Table(face, Tag::Glat, 0x00030000)) == NULL
-            || (m_pGloc = Face::Table(face, Tag::Gloc)) == NULL
-            || m_pGloc.size() < 8)
-        {
-            _head = Face::Table();
-            return;
-        }
-        const byte    * p = m_pGloc;
-        int       version = be::read<uint32>(p);
-        const uint16    flags = be::read<uint16>(p);
-        _num_attrs = be::read<uint16>(p);
-        // We can accurately calculate the number of attributed glyphs by
-        //  subtracting the length of the attribids array (numAttribs long if present)
-        //  and dividing by either 2 or 4 depending on shor or lonf format
-        _long_fmt              = flags & 1;
-        int tmpnumgattrs       = (m_pGloc.size()
-                                   - (p - m_pGloc)
-                                   - sizeof(uint16)*(flags & 0x2 ? _num_attrs : 0))
-                                       / (_long_fmt ? sizeof(uint32) : sizeof(uint16)) - 1;
-
-        if (version >= 0x00020000 || tmpnumgattrs < 0 || tmpnumgattrs > 65535
-            || _num_attrs == 0 || _num_attrs > 0x3000  // is this hard limit appropriate?
-            || _num_glyphs_graphics > tmpnumgattrs
-            || m_pGlat.size() < 4)
-        {
-            _head = Face::Table();
-            return;
-        }
-
-        _num_glyphs_attributes = static_cast<unsigned short>(tmpnumgattrs);
-        p = m_pGlat;
-        version = be::read<uint32>(p);
-        if (version >= 0x00040000 || (version >= 0x00030000 && m_pGlat.size() < 8))       // reject Glat tables that are too new
-        {
-            _head = Face::Table();
-            return;
-        }
-        else if (version >= 0x00030000)
-        {
-            unsigned int glatflags = be::read<uint32>(p);
-            _has_boxes = glatflags & 1;
-            // delete this once the compiler is fixed
-            _has_boxes = true;
-        }
+    if ((m_pGlat = Face::Table(face, Tag::Glat, 0x00030000)) == NULL
+        || (m_pGloc = Face::Table(face, Tag::Gloc)) == NULL
+        || m_pGloc.size() < 8)
+    {
+        _head = Face::Table();
+        return;
+    }
+    const byte    * p = m_pGloc;
+    int       version = be::read<uint32>(p);
+    const uint16    flags = be::read<uint16>(p);
+    _num_attrs = be::read<uint16>(p);
+    // We can accurately calculate the number of attributed glyphs by
+    //  subtracting the length of the attribids array (numAttribs long if present)
+    //  and dividing by either 2 or 4 depending on shor or lonf format
+    _long_fmt              = flags & 1;
+    int tmpnumgattrs       = (m_pGloc.size()
+                               - (p - m_pGloc)
+                               - sizeof(uint16)*(flags & 0x2 ? _num_attrs : 0))
+                                   / (_long_fmt ? sizeof(uint32) : sizeof(uint16)) - 1;
+
+    if (version >= 0x00020000 || tmpnumgattrs < 0 || tmpnumgattrs > 65535
+        || _num_attrs == 0 || _num_attrs > 0x3000  // is this hard limit appropriate?
+        || _num_glyphs_graphics > tmpnumgattrs
+        || m_pGlat.size() < 4)
+    {
+        _head = Face::Table();
+        return;
+    }
+
+    _num_glyphs_attributes = static_cast<unsigned short>(tmpnumgattrs);
+    p = m_pGlat;
+    version = be::read<uint32>(p);
+    if (version >= 0x00040000 || (version >= 0x00030000 && m_pGlat.size() < 8))       // reject Glat tables that are too new
+    {
+        _head = Face::Table();
+        return;
+    }
+    else if (version >= 0x00030000)
+    {
+        unsigned int glatflags = be::read<uint32>(p);
+        _has_boxes = glatflags & 1;
+        // delete this once the compiler is fixed
+        _has_boxes = true;
     }
 }
 
```
