# CrossVul Fix Pair: Improper Input Validation in cpp
**Pair ID:** 2611_2
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2611_2`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```cpp
Lines 866-907 of the vulnerable file.

    {
        return;
    }
    callbacks->handleEOF();
}

void
QPDFObjectHandle::parseContentStream_internal(PointerHolder<Buffer> stream_data,
                                              std::string const& description,
                                              ParserCallbacks* callbacks)
{
    size_t length = stream_data->getSize();
    PointerHolder<InputSource> input =
        new BufferInputSource(description, stream_data.getPointer());
    QPDFTokenizer tokenizer;
    tokenizer.allowEOF();
    bool empty = false;
    while (static_cast<size_t>(input->tell()) < length)
    {
        QPDFObjectHandle obj =
            parseInternal(input, "content", tokenizer, empty,
                          0, 0, false, false, true);
        if (! obj.isInitialized())
        {
            // EOF
            break;
        }

        callbacks->handleObject(obj);
        if (obj.isOperator() && (obj.getOperatorValue() == "ID"))
        {
            // Discard next character; it is the space after ID that
            // terminated the token.  Read until end of inline image.
            char ch;
            input->read(&ch, 1);
            char buf[4];
            memset(buf, '\0', sizeof(buf));
            bool done = false;
            std::string inline_image;
            while (! done)
            {
                if (input->read(&ch, 1) == 0)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -883,8 +883,7 @@
     while (static_cast<size_t>(input->tell()) < length)
     {
         QPDFObjectHandle obj =
-            parseInternal(input, "content", tokenizer, empty,
-                          0, 0, false, false, true);
+            parseInternal(input, "content", tokenizer, empty, 0, 0, true);
         if (! obj.isInitialized())
         {
             // EOF
@@ -945,7 +944,7 @@
                         StringDecrypter* decrypter, QPDF* context)
 {
     return parseInternal(input, object_description, tokenizer, empty,
-                         decrypter, context, false, false, false);
+                         decrypter, context, false);
 }
 
 QPDFObjectHandle
@@ -953,7 +952,6 @@
                                 std::string const& object_description,
                                 QPDFTokenizer& tokenizer, bool& empty,
                                 StringDecrypter* decrypter, QPDF* context,
-                                bool in_array, bool in_dictionary,
                                 bool content_stream)
 {
     // This method must take care not to resolve any objects. Don't
@@ -962,22 +960,23 @@
     // of reading the object and changing the file pointer.
 
     empty = false;
-    if (in_dictionary && in_array)
-    {
-	// Although dictionaries and arrays arbitrarily nest, these
-	// variables indicate what is at the top of the stack right
-	// now, so they can, by definition, never both be true.
-	throw std::logic_error(
-	    "INTERNAL ERROR: parseInternal: in_dict && in_array");
-    }
 
     QPDFObjectHandle object;
 
-    qpdf_offset_t offset = input->tell();
-    std::vector<QPDFObjectHandle> olist;
+    std::vector<std::vector<QPDFObjectHandle> > olist_stack;
+    olist_stack.push_back(std::vector<QPDFObjectHandle>());
+    enum state_e { st_top, st_start, st_stop, st_eof, st_dictionary, st_array };
+    std::vector<state_e> state_stack;
+    state_stack.push_back(st_top);
+    std::vector<qpdf_offset_t> offset_stack;
+    offset_stack.push_back(input->tell());
     bool done = false;
     while (! done)
     {
+        std::vector<QPDFObjectHandle>& olist = olist_stack.back();
+        state_e state = state_stack.back();
+        qpdf_offset_t offset = offset_stack.back();
+
 	object = QPDFObjectHandle();
 
 	QPDFTokenizer::Token token =
@@ -988,8 +987,7 @@
           case QPDFTokenizer::tt_eof:
             if (content_stream)
             {
-                // Return uninitialized object to indicate EOF
-                return object;
+                state = st_eof;
             }
             else
             {
@@ -1012,9 +1010,9 @@
 	    break;
 
 	  case QPDFTokenizer::tt_array_close:
-	    if (in_array)
+	    if (state == st_array)
 	    {
-		done = true;
+                state = st_stop;
 	    }
 	    else
 	    {
@@ -1029,9 +1027,9 @@
 	    break;
 
 	  case QPDFTokenizer::tt_dict_close:
-	    if (in_dictionary)
+	    if (state == st_dictionary)
 	    {
-		done = true;
+                state = st_stop;
 	    }
 	    else
 	    {
@@ -1046,15 +1044,13 @@
 	    break;
 
 	  case QPDFTokenizer::tt_array_open:
-	    object = parseInternal(
-		input, object_description, tokenizer, empty,
-                decrypter, context, true, false, content_stream);
-	    break;
-
 	  case QPDFTokenizer::tt_dict_open:
-	    object = parseInternal(
-		input, object_description, tokenizer, empty,
-                decrypter, context, false, true, content_stream);
+            olist_stack.push_back(std::vector<QPDFObjectHandle>());
+            state = st_start;
+            offset_stack.push_back(input->tell());
+            state_stack.push_back(
+                (token.getType() == QPDFTokenizer::tt_array_open) ?
+                st_array : st_dictionary);
 	    break;
 
 	  case QPDFTokenizer::tt_bool:
@@ -1084,12 +1080,12 @@
                 {
                     object = QPDFObjectHandle::newOperator(value);
                 }
-		else if ((value == "R") && (in_array || in_dictionary) &&
-		    (olist.size() >= 2) &&
-                    (! olist.at(olist.size() - 1).isIndirect()) &&
-		    (olist.at(olist.size() - 1).isInteger()) &&
-                    (! olist.at(olist.size() - 2).isIndirect()) &&
-		    (olist.at(olist.size() - 2).isInteger()))
+		else if ((value == "R") && (state != st_top) &&
+                         (olist.size() >= 2) &&
+                         (! olist.at(olist.size() - 1).isIndirect()) &&
+                         (olist.at(olist.size() - 1).isInteger()) &&
+                         (! olist.at(olist.size() - 2).isIndirect()) &&
+                         (olist.at(olist.size() - 2).isInteger()))
 		{
                     if (context == 0)
                     {
@@ -1106,8 +1102,7 @@
 		    olist.pop_back();
 		    olist.pop_back();
 		}
-		else if ((value == "endobj") &&
-			 (! (in_array || in_dictionary)))
+		else if ((value == "endobj") && (state == st_top))
 		{
 		    // We just saw endobj without having read
 		    // anything.  Treat this as a null and do not move
@@ -1153,93 +1148,132 @@
 	    break;
 	}
 
-	if (in_dictionary || in_array)
-	{
-	    if (! done)
-	    {
-		olist.push_back(object);
-	    }
-	}
-	else if (! object.isInitialized())
-	{
-            warn(context,
-                 QPDFExc(qpdf_e_damaged_pdf, input->getName(),
-                         object_description,
-                         input->getLastOffset(),
-                         "parse error while reading object"));
+        if ((! object.isInitialized()) &&
+            (! ((state == st_start) ||
+                (state == st_stop) ||
+                (state == st_eof))))
+        {
+            throw std::logic_error(
+                "QPDFObjectHandle::parseInternal: "
+                "unexpected uninitialized object");
             object = newNull();
-	}
-	else
-	{
-	    done = true;
-	}
-    }
-
-    if (in_array)
-    {
-	object = newArray(olist);
-    }
-    else if (in_dictionary)
-    {
-        // Convert list to map. Alternating elements are keys. Attempt
-        // to recover more or less gracefully from invalid
-        // dictionaries.
-        std::set<std::string> names;
-        for (std::vector<QPDFObjectHandle>::iterator iter = olist.begin();
-             iter != olist.end(); ++iter)
+        }
+
+        switch (state)
         {
-            if ((! (*iter).isIndirect()) && (*iter).isName())
+          case st_eof:
+            if (state_stack.size() > 1)
             {
-                names.insert((*iter).getName());
+                warn(context,
+                     QPDFExc(qpdf_e_damaged_pdf, input->getName(),
+                             object_description,
+                             input->getLastOffset(),
+                             "parse error while reading object"));
             }
-        }
-
-        std::map<std::string, QPDFObjectHandle> dict;
-        int next_fake_key = 1;
-        for (unsigned int i = 0; i < olist.size(); ++i)
-        {
-            QPDFObjectHandle key_obj = olist.at(i);
-            QPDFObjectHandle val;
-            if (key_obj.isIndirect() || (! key_obj.isName()))
+            done = true;
+            // Leave object uninitialized to indicate EOF
+            break;
+
+          case st_dictionary:
+          case st_array:
+            olist.push_back(object);
+            break;
+
+          case st_top:
+            done = true;
+            break;
+
+          case st_start:
+            break;
+
+          case st_stop:
+            if ((state_stack.size() < 2) || (olist_stack.size() < 2))
             {
-                bool found_fake = false;
-                std::string candidate;
-                while (! found_fake)
+                throw std::logic_error(
+                    "QPDFObjectHandle::parseInternal: st_stop encountered"
+                    " with insufficient elements in stack");
+            }
+            state_e old_state = state_stack.back();
+            state_stack.pop_back();
... (diff truncated)
```
