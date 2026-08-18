# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in c
**Pair ID:** 1829_4
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1829_4`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```c
Lines 249-289 of the vulnerable file.

}

CAMLprim value caml_string_lessequal(value s1, value s2)
{
  return caml_string_compare(s1, s2) <= Val_int(0) ? Val_true : Val_false;
}

CAMLprim value caml_string_greaterthan(value s1, value s2)
{
  return caml_string_compare(s1, s2) > Val_int(0) ? Val_true : Val_false;
}

CAMLprim value caml_string_greaterequal(value s1, value s2)
{
  return caml_string_compare(s1, s2) >= Val_int(0) ? Val_true : Val_false;
}

CAMLprim value caml_blit_string(value s1, value ofs1, value s2, value ofs2,
                                value n)
{
  memmove(&Byte(s2, Long_val(ofs2)), &Byte(s1, Long_val(ofs1)), Int_val(n));
  return Val_unit;
}

CAMLprim value caml_fill_string(value s, value offset, value len, value init)
{
  memset(&Byte(s, Long_val(offset)), Int_val(init), Long_val(len));
  return Val_unit;
}

CAMLprim value caml_bitvect_test(value bv, value n)
{
  int pos = Int_val(n);
  return Val_int(Byte_u(bv, pos >> 3) & (1 << (pos & 7)));
}

CAMLexport value caml_alloc_sprintf(const char * format, ...)
{
  va_list args;
  char buf[64];
  int n;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -266,7 +266,7 @@
 CAMLprim value caml_blit_string(value s1, value ofs1, value s2, value ofs2,
                                 value n)
 {
-  memmove(&Byte(s2, Long_val(ofs2)), &Byte(s1, Long_val(ofs1)), Int_val(n));
+  memmove(&Byte(s2, Long_val(ofs2)), &Byte(s1, Long_val(ofs1)), Long_val(n));
   return Val_unit;
 }
 
@@ -278,7 +278,7 @@
 
 CAMLprim value caml_bitvect_test(value bv, value n)
 {
-  int pos = Int_val(n);
+  intnat pos = Long_val(n);
   return Val_int(Byte_u(bv, pos >> 3) & (1 << (pos & 7)));
 }
 
```
