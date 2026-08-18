# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in cpp
**Pair ID:** 3491_5
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3491_5`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```cpp
Lines 948-1000 of the vulnerable file.


	for (;ci != ce; ++ci)
	    {
		if (ci->t () == SECTION)
		    {
			IniSection&s = ci->s ();
			int wb = s.getRewriteBy (); // bug #19066 
			string filename = getFileName (s.getName (), wb);

			// This is the only place where we unmark a
			// section for deletion - when it is a file
			// that got some data again. We can do it
			// because we only erase the files afterwards.
			deleted_sections.erase (filename);

			if (!s.isDirty ()) {
			    y2debug ("Skipping file %s that was not changed.", filename.c_str());
			    continue;
			}
			s.initReadBy ();
			// ensure that the directories exist
			Pathname pn (filename);
			PathInfo::assert_dir (pn.dirname ());
			ofstream of(filename.c_str());
			if (!of.good())
			{
			    bugs++;
			    y2error ("Can not open file %s for write", filename.c_str());
			    continue;
			}
			write_helper (s, of, 0);
			s.clean();
			of.close ();
		    }
		else
		    {
			y2error ("Value %s encountered at multifile top level",
				 ci->e ().getName ());
		    }
	    }

	// FIXME: update time stamps of files...

	// erase removed files...
	for (set<string>::iterator i = deleted_sections.begin (); i!=deleted_sections.end();i++)
	    if (multi_files.find (*i) != multi_files.end ()) {
		y2debug ("Removing file %s\n", (*i).c_str());
		unlink ((*i).c_str());
	    }
    }
    else
    {
	// ensure that the directories exist
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -965,19 +965,7 @@
 			    continue;
 			}
 			s.initReadBy ();
-			// ensure that the directories exist
-			Pathname pn (filename);
-			PathInfo::assert_dir (pn.dirname ());
-			ofstream of(filename.c_str());
-			if (!of.good())
-			{
-			    bugs++;
-			    y2error ("Can not open file %s for write", filename.c_str());
-			    continue;
-			}
-			write_helper (s, of, 0);
-			s.clean();
-			of.close ();
+                        bugs += write_file(filename, s);
 		    }
 		else
 		    {
@@ -997,24 +985,37 @@
     }
     else
     {
-	// ensure that the directories exist
-	Pathname pn (file);
-	PathInfo::assert_dir (pn.dirname ());
-	ofstream of(file.c_str());
-	if (!of.good())
-	{
-	    y2error ("Can not open file %s for write", file.c_str());
-	    return -1;
-	}
-
-	write_helper (inifile, of, 0);
-
-	of.close();
+        bugs += write_file(file, inifile);
 	timestamp = getTimeStamp ();
     }
-    inifile.clean ();
     return bugs ? -1 : 0;
 }
+
+// return 0 on success, like write
+int IniParser::write_file(const string & filename, IniSection & section)
+{
+    // ensure that the directories exist
+    Pathname pn(filename);
+    PathInfo::assert_dir (pn.dirname ());
+
+    mode_t file_umask = section.isPrivate()? 0077: 0022;
+    mode_t orig_umask = umask(file_umask);
+    // rewriting an existing file wouldnt change its mode
+    unlink(filename.c_str());
+
+    ofstream of(filename.c_str());
+    if (!of.good()) {
+        y2error ("Can not open file %s for write", filename.c_str());
+        return -1;
+    }
+
+    write_helper (section, of, 0);
+
+    of.close();
+    umask(orig_umask);
+    return 0;
+}
+
 int IniParser::write_helper(IniSection&ini, ofstream&of, int depth)
 {
     char * out_buffer;
```
