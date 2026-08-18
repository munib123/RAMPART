# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in c
**Pair ID:** 3491_4
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3491_4`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```c
Lines 224-264 of the vulnerable file.

/**
 * Section definition.
 */
class IniSection : public IniBase
{
private:
    // huh??? allow_values, allow_sections and allow_subsub
    // were never actuially used

    /** The parser, queried about global settings
     * But once the const is discarded to add to deleted_sections
     */
    const IniParser *ip;

    /**
     * if this is global section, there may be comment at the end
     * this is quite special case, it is impossible to change it
     */
    string end_comment;

    /** index to IniParser::rewrites for filename - section name mapping
     * It appears that read_by was used for both purposes,
     * causing bug (#19066).
     */
    int rewrite_by;

    /**
     * What entries of cvalues and csections are valid
     * Values contained by this section
     * Sections contained by this section
     */
    IniContainer container;
    // these must be kept up to date!
    /**
     * Index of values
     */
    IniEntryIndex ivalues;
    /**
     * Index of sections
     */
    IniSectionIndex isections;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -241,6 +241,13 @@
      */
     string end_comment;
 
+    /**
+     * It is effective only when the section corresponds to a file.
+     * The file will not be readable by group and others.
+     * bnc#713661
+     */
+    bool is_private;
+
     /** index to IniParser::rewrites for filename - section name mapping
      * It appears that read_by was used for both purposes,
      * causing bug (#19066).
@@ -435,7 +442,7 @@
     IniSection (const IniParser *p)
 	: IniBase (-1),
 	  ip (p),
-	  end_comment (), rewrite_by(-1),
+	  end_comment (), is_private(false), rewrite_by(-1),
 	  container (), ivalues (), isections ()
 	    {}
 
@@ -446,7 +453,7 @@
     IniSection (const IniSection &s) :
 	IniBase (s),
 	  ip (s.ip),
-	  end_comment (s.end_comment), rewrite_by (s.rewrite_by),
+          end_comment (s.end_comment), is_private(s.is_private), rewrite_by (s.rewrite_by),
 	  container (s.container)
 	{ reindex (); }
 
@@ -458,7 +465,9 @@
 	    } 
 	    IniBase::operator = (s);
 	    ip = s.ip;
-	    end_comment = s.end_comment; rewrite_by = s.rewrite_by;
+	    end_comment = s.end_comment;
+            is_private = s.is_private;
+            rewrite_by = s.rewrite_by;
 	    container = s.container;
 
 	    reindex ();
@@ -474,7 +483,7 @@
     IniSection (const IniParser *p, string n)
 	: IniBase (n),
 	  ip (p),
-	  end_comment (), rewrite_by(0),
+	  end_comment (), is_private(false), rewrite_by(0),
 	  container(), ivalues (), isections ()
 	    {}
     /**
@@ -510,6 +519,9 @@
      * @return rewrite-by of section or -1 if the section wasn't found
      */
     int getSubSectionRewriteBy (const char*name);
+
+    void setPrivate(bool p) { is_private = p; }
+    bool isPrivate() const { return is_private; }
 
     /** 
      * If there is no comment at the beginning and no values and no
```
