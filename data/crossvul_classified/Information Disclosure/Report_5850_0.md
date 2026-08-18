# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in cpp
**Pair ID:** 5850_0
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5850_0`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```cpp
Lines 187-227 of the vulnerable file.

    return false;
  }

  bool Messageheader::Parser::state_fieldbody_crlf(char ch)
  {
    if (ch == '\r')
      SET_STATE(state_end_cr);
    else if (ch == '\n')
    {
      log_debug("header " << fieldnamePtr << ": " << fieldbodyPtr);
      switch (header.onField(fieldnamePtr, fieldbodyPtr))
      {
        case OK:
        case END:  return true;
                   break;
        case FAIL: failedFlag = true;
                   log_warn("invalid character " << chartoprint(ch) << " in fieldbody");
                   break;
      }

      return true;
    }
    else if (std::isspace(ch))
    {
      // continuation line
      checkHeaderspace(1);
      *(headerdataPtr - 1) = '\n';
      *headerdataPtr++ = ch;
      SET_STATE(state_fieldbody);
    }
    else if (ch >= 33 && ch <= 126)
    {
      switch (header.onField(fieldnamePtr, fieldbodyPtr))
      {
        case OK:   SET_STATE(state_fieldname);
                   break;
        case FAIL: failedFlag = true;
                   log_warn("invalid character " << chartoprint(ch) << " in fieldbody");
                   break;
        case END:  return true;
                   break;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -204,6 +204,7 @@
                    break;
       }
 
+      *headerdataPtr = '\0';
       return true;
     }
     else if (std::isspace(ch))
@@ -259,7 +260,10 @@
   void Messageheader::Parser::checkHeaderspace(unsigned chars) const
   {
     if (headerdataPtr + chars >= header.rawdata + sizeof(header.rawdata))
+    {
+      header.rawdata[sizeof(header.rawdata) - 1] = '\0';
       throw HttpError(HTTP_REQUEST_ENTITY_TOO_LARGE, "header too large");
+    }
   }
 
   void Messageheader::Parser::reset()
```
