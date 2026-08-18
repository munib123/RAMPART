# CrossVul Fix Pair: NULL Pointer Dereference in c
**Pair ID:** 3198_0
**Vulnerability Class:** NULL Pointer Dereference
**CWE:** CWE-476
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3198_0`)

## Vulnerability Information & PoC

## Description
NULL Pointer Dereference - NULL pointer dereference issues can occur through a number of flaws, including race conditions, and simple programming omissions.

## Vulnerable Code
```c
Lines 1433-1473 of the vulnerable file.

      /* read in the layer */
      channel = xcf_load_channel (info, gimage);
      if (channel == 0)
        goto error;

      num_successful_elements++;

      /* add the channel to the image if its not the selection */
      if (channel != gimage->selection_mask)
        gimp_image_add_channel (gimage, channel, -1);

      /* restore the saved position so we'll be ready to
      *  read the next offset.
      */
      xcf_seek_pos (info, saved_pos);
    }
#endif
  }

  (void) CloseBlob(image);
  DestroyImage(RemoveFirstImageFromList(&image));
  if (image_type == GIMP_GRAY)
    image->type=GrayscaleType;
  return(GetFirstImageInList(image));
}


/*
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%                                                                             %
%                                                                             %
%                                                                             %
%   R e g i s t e r X C F I m a g e                                           %
%                                                                             %
%                                                                             %
%                                                                             %
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%
%  RegisterXCFImage() adds attributes for the XCF image format to
%  the list of supported formats.  The attributes include the image format
%  tag, a method to read and/or write the format, whether the format
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1450,7 +1450,8 @@
   }
 
   (void) CloseBlob(image);
-  DestroyImage(RemoveFirstImageFromList(&image));
+  if (GetNextImageInList(image) != (Image *) NULL)
+    DestroyImage(RemoveFirstImageFromList(&image));
   if (image_type == GIMP_GRAY)
     image->type=GrayscaleType;
   return(GetFirstImageInList(image));
```
