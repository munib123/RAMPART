# CrossVul Fix Pair: Resource Management Errors in cpp
**Pair ID:** 5122_0
**Vulnerability Class:** Resource Management Errors
**CWE:** CWE-399
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5122_0`)

## Vulnerability Information & PoC

## Description
Resource Management Errors

## Vulnerable Code
```cpp
Lines 385-425 of the vulnerable file.

}

uint16_t PacketReader::get16BitInt(const vector<unsigned char>&content, uint16_t& pos)
{
  uint16_t ret=0;
  ret+=content.at(pos++);
  ret<<=8;
  ret+=content.at(pos++);
  
  return ret;
}

uint8_t PacketReader::get8BitInt()
{
  return d_content.at(d_pos++);
}

string PacketReader::getLabel(unsigned int recurs)
{
  string ret;
  ret.reserve(40);
  getLabelFromContent(d_content, d_pos, ret, recurs++);
  return ret;
}

static string txtEscape(const string &name)
{
  string ret;
  char ebuf[5];

  for(string::const_iterator i=name.begin();i!=name.end();++i) {
    if((unsigned char) *i > 127 || (unsigned char) *i < 32) {
      snprintf(ebuf, sizeof(ebuf), "\\%03u", (unsigned char)*i);
      ret += ebuf;
    }
    else if(*i=='"' || *i=='\\'){
      ret += '\\';
      ret += *i;
    }
    else
      ret += *i;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -402,8 +402,9 @@
 string PacketReader::getLabel(unsigned int recurs)
 {
   string ret;
+  size_t wirelength = 0;
   ret.reserve(40);
-  getLabelFromContent(d_content, d_pos, ret, recurs++);
+  getLabelFromContent(d_content, d_pos, ret, recurs++, wirelength);
   return ret;
 }
 
@@ -453,7 +454,7 @@
 }
 
 
-void PacketReader::getLabelFromContent(const vector<uint8_t>& content, uint16_t& frompos, string& ret, int recurs) 
+void PacketReader::getLabelFromContent(const vector<uint8_t>& content, uint16_t& frompos, string& ret, int recurs, size_t& wirelength)
 {
   if(recurs > 100) // the forward reference-check below should make this test 100% obsolete
     throw MOADNSException("Loop");
@@ -462,6 +463,10 @@
   // it is tempting to call reserve on ret, but it turns out it creates a malloc/free storm in the loop
   for(;;) {
     unsigned char labellen=content.at(frompos++);
+    wirelength++;
+    if (wirelength > 255) {
+      throw MOADNSException("Overly long DNS name ("+lexical_cast<string>(wirelength)+")");
+    }
 
     if(!labellen) {
       if(ret.empty())
@@ -474,13 +479,17 @@
 
       if(offset >= pos)
         throw MOADNSException("forward reference during label decompression");
-      return getLabelFromContent(content, offset, ret, ++recurs);
+      /* the compression pointer does not count into the wire length */
+      return getLabelFromContent(content, offset, ret, ++recurs, --wirelength);
     }
     else if(labellen > 63) 
       throw MOADNSException("Overly long label during label decompression ("+lexical_cast<string>((unsigned int)labellen)+")");
     else {
+      if (wirelength + labellen > 255) {
+        throw MOADNSException("Overly long DNS name ("+lexical_cast<string>(wirelength)+")");
+      }
+      wirelength += labellen;
       // XXX FIXME THIS MIGHT BE VERY SLOW!
-
       for(string::size_type n = 0 ; n < labellen; ++n, frompos++) {
         if(content.at(frompos)=='.' || content.at(frompos)=='\\') {
           ret.append(1, '\\');
```
