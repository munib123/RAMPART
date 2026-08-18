# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in c
**Pair ID:** 5258_0
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5258_0`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```c
Lines 3751-3791 of the vulnerable file.

					}
				}
				/* If we had a thumbnail in a SUB_IFD we have ANOTHER image in NEXT IFD */
				if (next_offset && section_index != SECTION_THUMBNAIL) {
					/* this should be a thumbnail IFD */
					/* the thumbnail itself is stored at Tag=StripOffsets */
#ifdef EXIF_DEBUG
					exif_error_docref(NULL EXIFERR_CC, ImageInfo, E_NOTICE, "Read next IFD (THUMBNAIL) at x%04X", next_offset);
#endif
					ImageInfo->ifd_nesting_level++;
					exif_process_IFD_in_TIFF(ImageInfo, next_offset, SECTION_THUMBNAIL TSRMLS_CC);
#ifdef EXIF_DEBUG
					exif_error_docref(NULL EXIFERR_CC, ImageInfo, E_NOTICE, "%s THUMBNAIL @0x%04X + 0x%04X", ImageInfo->Thumbnail.data ? "Ignore" : "Read", ImageInfo->Thumbnail.offset, ImageInfo->Thumbnail.size);
#endif
					if (!ImageInfo->Thumbnail.data && ImageInfo->Thumbnail.offset && ImageInfo->Thumbnail.size && ImageInfo->read_thumbnail) {
						ImageInfo->Thumbnail.data = safe_emalloc(ImageInfo->Thumbnail.size, 1, 0);
						php_stream_seek(ImageInfo->infile, ImageInfo->Thumbnail.offset, SEEK_SET);
						fgot = php_stream_read(ImageInfo->infile, ImageInfo->Thumbnail.data, ImageInfo->Thumbnail.size);
						if (fgot < ImageInfo->Thumbnail.size) {
							EXIF_ERRLOG_THUMBEOF(ImageInfo)
						}
						exif_thumbnail_build(ImageInfo TSRMLS_CC);
					}
#ifdef EXIF_DEBUG
					exif_error_docref(NULL EXIFERR_CC, ImageInfo, E_NOTICE, "Read next IFD (THUMBNAIL) done");
#endif
				}
				return TRUE;
			} else {
				exif_error_docref(NULL EXIFERR_CC, ImageInfo, E_WARNING, "Error in TIFF: filesize(x%04X) less than size of IFD(x%04X)", ImageInfo->FileSize, dir_offset+ImageInfo->file.list[sn].size);
				return FALSE;
			}
		} else {
			exif_error_docref(NULL EXIFERR_CC, ImageInfo, E_WARNING, "Error in TIFF: filesize(x%04X) less than size of IFD dir(x%04X)", ImageInfo->FileSize, dir_offset+dir_size);
			return FALSE;
		}
	} else {
		exif_error_docref(NULL EXIFERR_CC, ImageInfo, E_WARNING, "Error in TIFF: filesize(x%04X) less than start of IFD dir(x%04X)", ImageInfo->FileSize, dir_offset+2);
		return FALSE;
	}
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -3768,8 +3768,11 @@
 						fgot = php_stream_read(ImageInfo->infile, ImageInfo->Thumbnail.data, ImageInfo->Thumbnail.size);
 						if (fgot < ImageInfo->Thumbnail.size) {
 							EXIF_ERRLOG_THUMBEOF(ImageInfo)
+							efree(ImageInfo->Thumbnail.data);
+							ImageInfo->Thumbnail.data = NULL;
+						} else {
+							exif_thumbnail_build(ImageInfo TSRMLS_CC);
 						}
-						exif_thumbnail_build(ImageInfo TSRMLS_CC);
 					}
 #ifdef EXIF_DEBUG
 					exif_error_docref(NULL EXIFERR_CC, ImageInfo, E_NOTICE, "Read next IFD (THUMBNAIL) done");
```
