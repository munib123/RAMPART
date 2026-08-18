# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in cpp
**Pair ID:** 3491_3
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3491_3`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```cpp
Lines 54-94 of the vulnerable file.

 */
static
YCPString as_string (const YCPValue& v, const char * context)
{
    if (v->isString ())
	return v->asString ();
    ycp2error ("Expected a string for %s, got %s %s",
	       context, v->valuetype_str(), v->toString().c_str());
    return YCPNull ();
}

/**
 * Return the YCPInteger or YCPNull if it is not one. Log an error.
 */
static
YCPInteger as_integer (const YCPValue& v, const char * context)
{
    if (v->isInteger ())
	return v->asInteger ();
    ycp2error ("Expected an integer for %s, got %s %s",
	       context, v->valuetype_str(), v->toString().c_str());
    return YCPNull ();
}

void IniSection::initValue (const string&key,const string&val,const string&comment,int rb)
{
    string k = ip->changeCase (key);
    IniEntry e;
    IniEntryIdxIterator exi;
    if (!ip->repeatNames () && (exi = ivalues.find (k)) != ivalues.end ())
	{
	    IniIterator ei = exi->second;
	    // update existing value
	    // copy the old value
	    e = ei->e ();
	    // remove and unindex the old value
	    // This means that container needs to be a list, not vector,
	    // so that iterators kept in ivalues are still valid
	    container.erase (ei);
	    ivalues.erase (exi);
	}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -75,6 +75,19 @@
     return YCPNull ();
 }
 
+/**
+ * Return the YCPBoolean or YCPNull if it is not one. Log an error.
+ */
+static
+YCPBoolean as_boolean (const YCPValue& v, const char * context)
+{
+    if (v->isBoolean ())
+	return v->asBoolean ();
+    ycp2error ("Expected a boolean for %s, got %s %s",
+	       context, v->valuetype_str(), v->toString().c_str());
+    return YCPNull ();
+}
+
 void IniSection::initValue (const string&key,const string&val,const string&comment,int rb)
 {
     string k = ip->changeCase (key);
@@ -486,6 +499,9 @@
       return setSectionProp (p, v, 0, 1);
     if (s == "st" || s == "section_type" || s == "sectiontype")
       return setSectionProp (p, v, rewrite? 1:2, 1);
+    if (s == "section_private")
+      return setSectionProp (p, v, 3, 1);
+
     return -1;
 }
 
@@ -591,11 +607,17 @@
 			return -1;
 		    s.setRewriteBy (i->value());
 		}
-		else {
+		else if (what == 2) {
 		    YCPInteger i = as_integer (prop, "section_type");
 		    if (i.isNull())
 			return -1;
 		    s.setReadBy (i->value());
+		}
+		else if (what == 3) {
+		    YCPBoolean b = as_boolean (prop, "section_private");
+		    if (b.isNull())
+			return -1;
+		    s.setPrivate (b->value());
 		}
 
 		if (xi != xe)
```
