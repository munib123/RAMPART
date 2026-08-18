# CrossVul Fix Pair: Integer Overflow or Wraparound in c
**Pair ID:** 222_0
**Vulnerability Class:** Integer Overflow
**CWE:** CWE-190
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `222_0`)

## Vulnerability Information & PoC

## Description
Integer Overflow or Wraparound - An integer overflow or wraparound occurs when an integer value is incremented to a value that is too large to store in the associated representation.

## Vulnerable Code
```c
Lines 1027-1067 of the vulnerable file.

				(red   << info->var.red.offset)   |
				(green << info->var.green.offset) |
				(blue  << info->var.blue.offset);
			break;
		}
	}
	return err;
}

static int uvesafb_setcmap(struct fb_cmap *cmap, struct fb_info *info)
{
	struct uvesafb_pal_entry *entries;
	int shift = 16 - dac_width;
	int i, err = 0;

	if (info->var.bits_per_pixel == 8) {
		if (cmap->start + cmap->len > info->cmap.start +
		    info->cmap.len || cmap->start < info->cmap.start)
			return -EINVAL;

		entries = kmalloc(sizeof(*entries) * cmap->len, GFP_KERNEL);
		if (!entries)
			return -ENOMEM;

		for (i = 0; i < cmap->len; i++) {
			entries[i].red   = cmap->red[i]   >> shift;
			entries[i].green = cmap->green[i] >> shift;
			entries[i].blue  = cmap->blue[i]  >> shift;
			entries[i].pad   = 0;
		}
		err = uvesafb_setpalette(entries, cmap->len, cmap->start, info);
		kfree(entries);
	} else {
		/*
		 * For modes with bpp > 8, we only set the pseudo palette in
		 * the fb_info struct. We rely on uvesafb_setcolreg to do all
		 * sanity checking.
		 */
		for (i = 0; i < cmap->len; i++) {
			err |= uvesafb_setcolreg(cmap->start + i, cmap->red[i],
						cmap->green[i], cmap->blue[i],
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1044,7 +1044,8 @@
 		    info->cmap.len || cmap->start < info->cmap.start)
 			return -EINVAL;
 
-		entries = kmalloc(sizeof(*entries) * cmap->len, GFP_KERNEL);
+		entries = kmalloc_array(cmap->len, sizeof(*entries),
+					GFP_KERNEL);
 		if (!entries)
 			return -ENOMEM;
 
```
