# CrossVul Fix Pair: NULL Pointer Dereference in c
**Pair ID:** 656_0
**Vulnerability Class:** NULL Pointer Dereference
**CWE:** CWE-476
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `656_0`)

## Vulnerability Information & PoC

## Description
NULL Pointer Dereference - NULL pointer dereference issues can occur through a number of flaws, including race conditions, and simple programming omissions.

## Vulnerable Code
```c
Lines 39-79 of the vulnerable file.


typedef struct gr_face          gr_face;
typedef struct gr_font          gr_font;
typedef struct gr_feature_ref   gr_feature_ref;
typedef struct gr_feature_val   gr_feature_val;

/**
* Returns version information on this engine
*/
GR2_API void gr_engine_version(int *nMajor, int *nMinor, int *nBugFix);

/**
* The Face Options allow the application to require that certain tables are
* read during face construction. This may be of concern if the appFaceHandle
* used in the gr_get_table_fn may change.
* The values can be combined 
*/
enum gr_face_options {
    /** No preload, no cmap caching, fail if the graphite tables are invalid */
    gr_face_default = 0,
    /** Dumb rendering will be enabled if the graphite tables are invalid */
    gr_face_dumbRendering = 1,
    /** preload glyphs at construction time */
    gr_face_preloadGlyphs = 2,
    /** Cache the lookup from code point to glyph ID at construction time */
    gr_face_cacheCmap = 4,
    /** Preload everything */
    gr_face_preloadAll = gr_face_preloadGlyphs | gr_face_cacheCmap
};

/** Holds information about a particular Graphite silf table that has been loaded */
struct gr_faceinfo {
    gr_uint16 extra_ascent;     /**< The extra_ascent in the GDL, in design units */
    gr_uint16 extra_descent;    /**< The extra_descent in the GDL, in design units */
    gr_uint16 upem;             /**< The design units for the font */
    enum gr_space_contextuals {
        gr_space_unknown = 0,       /**< no information is known. */
        gr_space_none = 1,          /**< the space character never occurs in any rules. */
        gr_space_left_only = 2,     /**< the space character only occurs as the first element in a rule. */
        gr_space_right_only = 3,    /**< the space character only occurs as the last element in a rule. */
        gr_space_either_only = 4,   /**< the space character only occurs as the only element in a rule. */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -56,7 +56,7 @@
 enum gr_face_options {
     /** No preload, no cmap caching, fail if the graphite tables are invalid */
     gr_face_default = 0,
-    /** Dumb rendering will be enabled if the graphite tables are invalid */
+    /** Dumb rendering will be enabled if the graphite tables are invalid. DEPRECATED. */
     gr_face_dumbRendering = 1,
     /** preload glyphs at construction time */
     gr_face_preloadGlyphs = 2,
```
