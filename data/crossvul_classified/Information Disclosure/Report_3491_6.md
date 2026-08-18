# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in c
**Pair ID:** 3491_6
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3491_6`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```c
Lines 355-395 of the vulnerable file.

    /**
     * Open ini file.
     */
    int scanner_start(const char*fn);
    /**
     * Close ini file.
     */
    void scanner_stop();
    /**
     * get line from ini file.
     */
    int scanner_get(string&s);

    /**
     * Parse one ini file and build a structure of IniSection.
     */
    int parse_helper(IniSection&ini);
    /**
     * Write one ini file.
     */
    int write_helper(IniSection&ini, ofstream&of,int depth);
public:
    /**
     * If Write (.s.section_name, nil) was called in multiple files mode,
     * than the file section_name has to be removed at the end. But as we
     * have file name rewrite rules, section_name needn't be file name.
     * Hence it is necessary to convert section_name to file name before
     * inserting to deleted_sections. <br>
     * Note: <tt>Write (.s.section_name, nil); Write (.v.section_name.k, "v");</tt>
     * means that section is deleted at first and created again later. In
     * this case file isn't removed!
     */
    set<string> deleted_sections;
    /**
     * Toplevel ini section.
     */
    IniSection inifile;
    // apparently the uninitialized members are filled in
    // by the grammar definition
    IniParser () :
	timestamp (0),
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -372,6 +372,10 @@
     /**
      * Write one ini file.
      */
+    int write_file(const string & filename, IniSection & section);
+    /**
+     * Write one ini file.
+     */
     int write_helper(IniSection&ini, ofstream&of,int depth);
 public:
     /**
```
