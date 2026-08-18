# CrossVul Fix Pair: Uncontrolled Recursion in cpp
**Pair ID:** 698_1
**Vulnerability Class:** Uncontrolled Recursion
**CWE:** CWE-674
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `698_1`)

## Vulnerability Information & PoC

## Description
Uncontrolled Recursion - The product does not properly control the amount of recursion that takes place, consuming excessive resources, such as allocated memory or the program stack.

## Vulnerable Code
```cpp
Lines 1470-1515 of the vulnerable file.


	  case QPDFTokenizer::tt_dict_close:
	    if (state == st_dictionary)
	    {
                state = st_stop;
	    }
	    else
	    {
		QTC::TC("qpdf", "QPDFObjectHandle bad dictionary close");
                warn(context,
                     QPDFExc(qpdf_e_damaged_pdf, input->getName(),
                             object_description,
                             input->getLastOffset(),
                             "unexpected dictionary close token"));
                object = newNull();
	    }
	    break;

	  case QPDFTokenizer::tt_array_open:
	  case QPDFTokenizer::tt_dict_open:
            olist_stack.push_back(std::vector<QPDFObjectHandle>());
            state = st_start;
            offset_stack.push_back(input->tell());
            state_stack.push_back(
                (token.getType() == QPDFTokenizer::tt_array_open) ?
                st_array : st_dictionary);
	    break;

	  case QPDFTokenizer::tt_bool:
	    object = newBool((token.getValue() == "true"));
	    break;

	  case QPDFTokenizer::tt_null:
	    object = newNull();
	    break;

	  case QPDFTokenizer::tt_integer:
	    object = newInteger(QUtil::string_to_ll(token.getValue().c_str()));
	    break;

	  case QPDFTokenizer::tt_real:
	    object = newReal(token.getValue());
	    break;

	  case QPDFTokenizer::tt_name:
	    object = newName(token.getValue());
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1487,12 +1487,26 @@
 
 	  case QPDFTokenizer::tt_array_open:
 	  case QPDFTokenizer::tt_dict_open:
-            olist_stack.push_back(std::vector<QPDFObjectHandle>());
-            state = st_start;
-            offset_stack.push_back(input->tell());
-            state_stack.push_back(
-                (token.getType() == QPDFTokenizer::tt_array_open) ?
-                st_array : st_dictionary);
+            if (olist_stack.size() > 500)
+            {
+		QTC::TC("qpdf", "QPDFObjectHandle too deep");
+                warn(context,
+                     QPDFExc(qpdf_e_damaged_pdf, input->getName(),
+                             object_description,
+                             input->getLastOffset(),
+                             "ignoring excessively deeply nested data structure"));
+                object = newNull();
+                state = st_top;
+            }
+            else
+            {
+                olist_stack.push_back(std::vector<QPDFObjectHandle>());
+                state = st_start;
+                offset_stack.push_back(input->tell());
+                state_stack.push_back(
+                    (token.getType() == QPDFTokenizer::tt_array_open) ?
+                    st_array : st_dictionary);
+            }
 	    break;
 
 	  case QPDFTokenizer::tt_bool:
```
