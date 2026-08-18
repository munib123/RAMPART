# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in cpp
**Pair ID:** 3065_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3065_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```cpp
Lines 400-440 of the vulnerable file.

    else
    {
      message_out(ERROR, "ofx_proc_file(): FATAL: Missing DTD, aborting");
    }
  }
  else
  {
    message_out(ERROR, "ofx_proc_file():No input file specified");
  }
  return 0;
}


/**
   This function will strip all the OFX proprietary tags and SGML comments from the SGML string passed to it
*/

string sanitize_proprietary_tags(string input_string)
{
  unsigned int i;
  size_t input_string_size;
  bool strip = false;
  bool tag_open = false;
  int tag_open_idx = 0; //Are we within < > ?
  bool closing_tag_open = false; //Are we within </ > ?
  int orig_tag_open_idx = 0;
  bool proprietary_tag = false; //Are we within a proprietary element?
  bool proprietary_closing_tag = false;
  int crop_end_idx = 0;
  char buffer[READ_BUFFER_SIZE] = "";
  char tagname[READ_BUFFER_SIZE] = "";
  int tagname_idx = 0;
  char close_tagname[READ_BUFFER_SIZE] = "";

  for (i = 0; i < READ_BUFFER_SIZE; i++)
  {
    buffer[i] = 0;
    tagname[i] = 0;
    close_tagname[i] = 0;
  }

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -417,7 +417,6 @@
 string sanitize_proprietary_tags(string input_string)
 {
   unsigned int i;
-  size_t input_string_size;
   bool strip = false;
   bool tag_open = false;
   int tag_open_idx = 0; //Are we within < > ?
@@ -438,9 +437,17 @@
     close_tagname[i] = 0;
   }
 
-  input_string_size = input_string.size();
-
-  for (i = 0; i < input_string_size; i++)
+  size_t input_string_size = input_string.size();
+
+  // Minimum workaround to prevent buffer overflow: Stop iterating
+  // once the (fixed!) size of the output buffers is reached. In
+  // response to
+  // https://www.talosintelligence.com/vulnerability_reports/TALOS-2017-0317
+  //
+  // However, this code is a huge mess anyway and is in no way
+  // anything like up-to-date C++ code. Please, anyone, replace it
+  // with something more modern. Thanks. - cstim, 2017-09-17.
+  for (i = 0; i < std::min(input_string_size, size_t(READ_BUFFER_SIZE)); i++)
   {
     if (input_string.c_str()[i] == '<')
     {
```
