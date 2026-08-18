# CrossVul Fix Pair: Loop with Unreachable Exit Condition ('Infinite Loop') in cpp
**Pair ID:** 3008_1
**Vulnerability Class:** Loop with Unreachable Exit Condition ('Infinite Loop')
**CWE:** CWE-835
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3008_1`)

## Vulnerability Information & PoC

## Description
Loop with Unreachable Exit Condition ('Infinite Loop') - If the loop can be influenced by an attacker, this weakness could allow attackers to consume excessive resources such as CPU or memory.

## Vulnerable Code
```cpp
Lines 474-514 of the vulnerable file.

	// streams.

	throw QPDFExc(qpdf_e_damaged_pdf, this->m->file->getName(), "", 0,
		      "unable to find trailer "
		      "dictionary while recovering damaged file");
    }

    // We could iterate through the objects looking for streams and
    // try to find objects inside of them, but it's probably not worth
    // the trouble.  Acrobat can't recover files with any errors in an
    // xref stream, and this would be a real long shot anyway.  If we
    // wanted to do anything that involved looking at stream contents,
    // we'd also have to call initializeEncryption() here.  It's safe
    // to call it more than once.
}

void
QPDF::read_xref(qpdf_offset_t xref_offset)
{
    std::map<int, int> free_table;
    while (xref_offset)
    {
        char buf[7];
        memset(buf, 0, sizeof(buf));
	this->m->file->seek(xref_offset, SEEK_SET);
	this->m->file->read(buf, sizeof(buf) - 1);
        // The PDF spec says xref must be followed by a line
        // terminator, but files exist in the wild where it is
        // terminated by arbitrary whitespace.
        if ((strncmp(buf, "xref", 4) == 0) &&
            QUtil::is_space(buf[4]))
	{
            QTC::TC("qpdf", "QPDF xref space",
                    ((buf[4] == '\n') ? 0 :
                     (buf[4] == '\r') ? 1 :
                     (buf[4] == ' ') ? 2 : 9999));
            int skip = 4;
            // buf is null-terminated, and QUtil::is_space('\0') is
            // false, so this won't overrun.
            while (QUtil::is_space(buf[skip]))
            {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -491,8 +491,10 @@
 QPDF::read_xref(qpdf_offset_t xref_offset)
 {
     std::map<int, int> free_table;
+    std::set<qpdf_offset_t> visited;
     while (xref_offset)
     {
+        visited.insert(xref_offset);
         char buf[7];
         memset(buf, 0, sizeof(buf));
 	this->m->file->seek(xref_offset, SEEK_SET);
@@ -520,6 +522,10 @@
 	{
 	    xref_offset = read_xrefStream(xref_offset);
 	}
+        if (visited.count(xref_offset) != 0)
+        {
+            xref_offset = 0;
+        }
     }
 
     if (! this->m->trailer.isInitialized())
```
