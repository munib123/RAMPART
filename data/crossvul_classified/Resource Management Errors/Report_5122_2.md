# CrossVul Fix Pair: Resource Management Errors in cpp
**Pair ID:** 5122_2
**Vulnerability Class:** Resource Management Errors
**CWE:** CWE-399
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5122_2`)

## Vulnerability Information & PoC

## Description
Resource Management Errors

## Vulnerable Code
```cpp
Lines 133-173 of the vulnerable file.

  if(!endsOn(*qname, domain))
    return false;

  if(toLower(*qname)==toLower(domain))
    *qname="@";
  else {
    if((*qname)[qname->size()-domain.size()-1]!='.')
      return false;

    qname->resize(qname->size()-domain.size()-1);
  }
  return true;
}

/** Chops off the start of a domain, so goes from 'www.ds9a.nl' to 'ds9a.nl' to 'nl' to ''. Return zero on the empty string */
bool chopOff(string &domain) 
{
  if(domain.empty())
    return false;

  string::size_type fdot=domain.find('.');

  if(fdot==string::npos) 
    domain="";
  else {
    string::size_type remain = domain.length() - (fdot + 1);
    char tmp[remain];
    memcpy(tmp, domain.c_str()+fdot+1, remain);
    domain.assign(tmp, remain); // don't dare to do this w/o tmp holder :-)
  }
  return true;
}

/** Chops off the start of a domain, so goes from 'www.ds9a.nl.' to 'ds9a.nl.' to 'nl.' to '.' Return zero on the empty string */
bool chopOffDotted(string &domain)
{
  if(domain.empty() || (domain.size()==1 && domain[0]=='.'))
    return false;

  string::size_type fdot=domain.find('.');
  if(fdot == string::npos)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -150,16 +150,27 @@
   if(domain.empty())
     return false;
 
-  string::size_type fdot=domain.find('.');
-
-  if(fdot==string::npos) 
-    domain="";
-  else {
-    string::size_type remain = domain.length() - (fdot + 1);
-    char tmp[remain];
-    memcpy(tmp, domain.c_str()+fdot+1, remain);
-    domain.assign(tmp, remain); // don't dare to do this w/o tmp holder :-)
-  }
+  bool escaped = false;
+  const string::size_type domainLen = domain.length();
+  for (size_t fdot = 0; fdot < domainLen; fdot++)
+  {
+    if (domain[fdot] == '.' && !escaped) {
+      string::size_type remain = domainLen - (fdot + 1);
+      char tmp[remain];
+      memcpy(tmp, domain.c_str()+fdot+1, remain);
+      domain.assign(tmp, remain); // don't dare to do this w/o tmp holder :-)
+
+      return true;
+    }
+    else if (domain[fdot] == '\\' && !escaped) {
+      escaped = true;
+    }
+    else {
+      escaped = false;
+    }
+  }
+
+  domain = "";
   return true;
 }
 
@@ -169,19 +180,31 @@
   if(domain.empty() || (domain.size()==1 && domain[0]=='.'))
     return false;
 
-  string::size_type fdot=domain.find('.');
-  if(fdot == string::npos)
-    return false;
-
-  if(fdot==domain.size()-1) 
-    domain=".";
-  else  {
-    string::size_type remain = domain.length() - (fdot + 1);
-    char tmp[remain];
-    memcpy(tmp, domain.c_str()+fdot+1, remain);
-    domain.assign(tmp, remain);
-  }
-  return true;
+  bool escaped = false;
+  const string::size_type domainLen = domain.length();
+  for (size_t fdot = 0; fdot < domainLen; fdot++)
+  {
+    if (domain[fdot] == '.' && !escaped) {
+      if (fdot==domain.size()-1) {
+        domain=".";
+      }
+      else {
+        string::size_type remain = domainLen - (fdot + 1);
+        char tmp[remain];
+        memcpy(tmp, domain.c_str()+fdot+1, remain);
+        domain.assign(tmp, remain); // don't dare to do this w/o tmp holder :-)
+      }
+      return true;
+    }
+    else if (domain[fdot] == '\\' && !escaped) {
+      escaped = true;
+    }
+    else {
+      escaped = false;
+    }
+  }
+
+  return false;
 }
 
 
```
