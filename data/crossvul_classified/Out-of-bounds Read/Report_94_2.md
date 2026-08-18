# CrossVul Fix Pair: Out-of-bounds Read in cpp
**Pair ID:** 94_2
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `94_2`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```cpp
Lines 6126-6166 of the vulnerable file.

{
  x3f_t *x3f = x3f_new_from_file(libraw_internal_data.internal_data.input);
  if (!x3f)
    return;
  _x3f_data = x3f;

  x3f_header_t *H = NULL;
  x3f_directory_section_t *DS = NULL;

  H = &x3f->header;
  // Parse RAW size from RAW section
  x3f_directory_entry_t *DE = x3f_get_raw(x3f);
  if (!DE)
    return;
  imgdata.sizes.flip = H->rotation;
  x3f_directory_entry_header_t *DEH = &DE->header;
  x3f_image_data_t *ID = &DEH->data_subsection.image_data;
  imgdata.sizes.raw_width = ID->columns;
  imgdata.sizes.raw_height = ID->rows;
  // Parse other params from property section
  DE = x3f_get_prop(x3f);
  if ((x3f_load_data(x3f, DE) == X3F_OK))
  {
    // Parse property list
    DEH = &DE->header;
    x3f_property_list_t *PL = &DEH->data_subsection.property_list;
    if (PL->property_table.size != 0)
    {
      int i;
      x3f_property_t *P = PL->property_table.element;
      for (i = 0; i < PL->num_properties; i++)
      {
        char name[100], value[100];
        utf2char(P[i].name, name,sizeof(name));
        utf2char(P[i].value, value,sizeof(value));
        if (!strcmp(name, "ISO"))
          imgdata.other.iso_speed = atoi(value);
        if (!strcmp(name, "CAMMANUF"))
          strcpy(imgdata.idata.make, value);
        if (!strcmp(name, "CAMMODEL"))
          strcpy(imgdata.idata.model, value);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -6143,12 +6143,15 @@
   imgdata.sizes.raw_width = ID->columns;
   imgdata.sizes.raw_height = ID->rows;
   // Parse other params from property section
+
   DE = x3f_get_prop(x3f);
   if ((x3f_load_data(x3f, DE) == X3F_OK))
   {
     // Parse property list
     DEH = &DE->header;
     x3f_property_list_t *PL = &DEH->data_subsection.property_list;
+    utf16_t *datap = (utf16_t*) PL->data;
+    uint32_t maxitems = PL->data_size/sizeof(utf16_t);
     if (PL->property_table.size != 0)
     {
       int i;
@@ -6156,8 +6159,14 @@
       for (i = 0; i < PL->num_properties; i++)
       {
         char name[100], value[100];
-        utf2char(P[i].name, name,sizeof(name));
-        utf2char(P[i].value, value,sizeof(value));
+        int noffset = (P[i].name - datap);
+        int voffset = (P[i].value - datap);
+        if(noffset < 0 || noffset>maxitems || voffset<0 || voffset>maxitems)
+           throw LIBRAW_EXCEPTION_IO_CORRUPT;
+        int maxnsize = maxitems - (P[i].name - datap);
+        int maxvsize = maxitems - (P[i].value - datap);
+        utf2char(P[i].name, name,MIN(maxnsize,sizeof(name)));
+        utf2char(P[i].value, value,MIN(maxvsize,sizeof(value)));
         if (!strcmp(name, "ISO"))
           imgdata.other.iso_speed = atoi(value);
         if (!strcmp(name, "CAMMANUF"))
```
