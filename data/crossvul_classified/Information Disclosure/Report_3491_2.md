# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in cpp
**Pair ID:** 3491_2
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3491_2`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```cpp
Lines 81-121 of the vulnerable file.

    }
    // no need to update if modified, we are changing value

    bool ok = false; // is the _path_ ok?
    // return value
    YCPBoolean b (true);

    if (0 == path->length ())
    {
	if (value->isString() && value->asString()->value() == "force")
	    parser.inifile.setDirty();
	else if (value->isString () && value->asString()->value() == "clean")
	    parser.inifile.clean ();
	if (0 != parser.write ())
	    b = false;
	ok = true;
    }
    else
    {
	if (( parser.repeatNames () && value->isList ()) ||
	    (!parser.repeatNames () &&  (value->isString () || value->isInteger())) ||
	    path->component_str(0) == "all"
	    )
	    {
		ok = true;
		if (parser.inifile.Write (path, value, parser.HaveRewrites ()))
		    b = false;
	    }
        else if (value->isVoid ())
	    {
		int wb  = -1;
		string del_sec = "";
		ok = true;
		if (2 == path->length ())
		{
		    string pc = path->component_str(0);
		    if ("s" == pc || "section" == pc)
		    {	// request to delete section. Find the file name
			del_sec = path->component_str (1);
			wb = parser.inifile.getSubSectionRewriteBy (del_sec.c_str());
		    }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -98,7 +98,7 @@
     else
     {
 	if (( parser.repeatNames () && value->isList ()) ||
-	    (!parser.repeatNames () &&  (value->isString () || value->isInteger())) ||
+	    (!parser.repeatNames () &&  (value->isString () || value->isBoolean() || value->isInteger())) ||
 	    path->component_str(0) == "all"
 	    )
 	    {
```
