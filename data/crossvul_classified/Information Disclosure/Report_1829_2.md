# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in c
**Pair ID:** 1829_2
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1829_2`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```c
Lines 136-176 of the vulnerable file.

{
  return caml_alloc_array(caml_copy_string, arr);
}

CAMLexport int caml_convert_flag_list(value list, int *flags)
{
  int res;
  res = 0;
  while (list != Val_int(0)) {
    res |= flags[Int_val(Field(list, 0))];
    list = Field(list, 1);
  }
  return res;
}

/* For compiling let rec over values */

/* [size] is a [value] representing number of words (fields) */
CAMLprim value caml_alloc_dummy(value size)
{
  mlsize_t wosize = Int_val(size);

  if (wosize == 0) return Atom(0);
  return caml_alloc (wosize, 0);
}

/* [size] is a [value] representing number of words (fields) */
CAMLprim value caml_alloc_dummy_function(value size,value arity)
{
  /* the arity argument is used by the js_of_ocaml runtime */
  return caml_alloc_dummy(size);
}

/* [size] is a [value] representing number of floats. */
CAMLprim value caml_alloc_dummy_float (value size)
{
  mlsize_t wosize = Int_val(size) * Double_wosize;

  if (wosize == 0) return Atom(0);
  return caml_alloc (wosize, 0);
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -153,7 +153,7 @@
 /* [size] is a [value] representing number of words (fields) */
 CAMLprim value caml_alloc_dummy(value size)
 {
-  mlsize_t wosize = Int_val(size);
+  mlsize_t wosize = Long_val(size);
 
   if (wosize == 0) return Atom(0);
   return caml_alloc (wosize, 0);
@@ -169,7 +169,7 @@
 /* [size] is a [value] representing number of floats. */
 CAMLprim value caml_alloc_dummy_float (value size)
 {
-  mlsize_t wosize = Int_val(size) * Double_wosize;
+  mlsize_t wosize = Long_val(size) * Double_wosize;
 
   if (wosize == 0) return Atom(0);
   return caml_alloc (wosize, 0);
```
