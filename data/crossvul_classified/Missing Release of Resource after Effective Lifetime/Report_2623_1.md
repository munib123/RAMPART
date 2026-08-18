# CrossVul Fix Pair: Missing Release of Resource after Effective Lifetime in c
**Pair ID:** 2623_1
**Vulnerability Class:** Missing Release of Resource after Effective Lifetime
**CWE:** CWE-772
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2623_1`)

## Vulnerability Information & PoC

## Description
Missing Release of Resource after Effective Lifetime - When a resource is not released after use, it can allow attackers to cause a denial of service by causing the allocation of resources without triggering their release.

## Vulnerable Code
```c
Lines 915-955 of the vulnerable file.

      */
      p=option;
      for (i=0; sscanf(p,"%f",&parameters.tcp_rates[i]) == 1; i++)
      {
        if (i > 100)
          break;
        while ((*p != '\0') && (*p != ','))
          p++;
        if (*p == '\0')
          break;
        p++;
      }
      parameters.tcp_numlayers=i+1;
      parameters.cp_disto_alloc=OPJ_TRUE;
    }
  if (image_info->sampling_factor != (const char *) NULL)
    (void) sscanf(image_info->sampling_factor,"%d,%d",
      &parameters.subsampling_dx,&parameters.subsampling_dy);
  property=GetImageProperty(image,"comment");
  if (property != (const char *) NULL)
    parameters.cp_comment=property;
  channels=3;
  jp2_colorspace=OPJ_CLRSPC_SRGB;
  if (image->colorspace == YUVColorspace)
    {
      jp2_colorspace=OPJ_CLRSPC_SYCC;
      parameters.subsampling_dx=2;
    }
  else
    {
      if (IsGrayColorspace(image->colorspace) != MagickFalse)
        {
          channels=1;
          jp2_colorspace=OPJ_CLRSPC_GRAY;
        }
      else
        (void) TransformImageColorspace(image,sRGBColorspace);
      if (image->matte != MagickFalse)
        channels++;
    }
  parameters.tcp_mct=channels == 3 ? 1 : 0;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -932,7 +932,7 @@
       &parameters.subsampling_dx,&parameters.subsampling_dy);
   property=GetImageProperty(image,"comment");
   if (property != (const char *) NULL)
-    parameters.cp_comment=property;
+    parameters.cp_comment=(char *) property;
   channels=3;
   jp2_colorspace=OPJ_CLRSPC_SRGB;
   if (image->colorspace == YUVColorspace)
```
