# CrossVul Fix Pair: Out-of-bounds Write in c
**Pair ID:** 95_1
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-787
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `95_1`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Write - Typically, this can result in corruption of data, a crash, or code execution.

## Vulnerable Code
```c
Lines 36-76 of the vulnerable file.


#define Wave64ChunkHeaderFormat "88D"

static const unsigned char riff_guid [16] = { 'r','i','f','f', 0x2e,0x91,0xcf,0x11,0xa5,0xd6,0x28,0xdb,0x04,0xc1,0x00,0x00 };
static const unsigned char wave_guid [16] = { 'w','a','v','e', 0xf3,0xac,0xd3,0x11,0x8c,0xd1,0x00,0xc0,0x4f,0x8e,0xdb,0x8a };
static const unsigned char  fmt_guid [16] = { 'f','m','t',' ', 0xf3,0xac,0xd3,0x11,0x8c,0xd1,0x00,0xc0,0x4f,0x8e,0xdb,0x8a };
static const unsigned char data_guid [16] = { 'd','a','t','a', 0xf3,0xac,0xd3,0x11,0x8c,0xd1,0x00,0xc0,0x4f,0x8e,0xdb,0x8a };

#define WAVPACK_NO_ERROR    0
#define WAVPACK_SOFT_ERROR  1
#define WAVPACK_HARD_ERROR  2

extern int debug_logging_mode;

int ParseWave64HeaderConfig (FILE *infile, char *infilename, char *fourcc, WavpackContext *wpc, WavpackConfig *config)
{
    int64_t total_samples = 0, infilesize;
    Wave64ChunkHeader chunk_header;
    Wave64FileHeader filehdr;
    WaveHeader WaveHeader;
    uint32_t bcount;

    infilesize = DoGetFileSize (infile);
    memcpy (&filehdr, fourcc, 4);

    if (!DoReadFile (infile, ((char *) &filehdr) + 4, sizeof (Wave64FileHeader) - 4, &bcount) ||
        bcount != sizeof (Wave64FileHeader) - 4 || memcmp (filehdr.ckID, riff_guid, sizeof (riff_guid)) ||
        memcmp (filehdr.formType, wave_guid, sizeof (wave_guid))) {
            error_line ("%s is not a valid .W64 file!", infilename);
            return WAVPACK_SOFT_ERROR;
    }
    else if (!(config->qmode & QMODE_NO_STORE_WRAPPER) &&
        !WavpackAddWrapper (wpc, &filehdr, sizeof (filehdr))) {
            error_line ("%s", WavpackGetErrorMessage (wpc));
            return WAVPACK_SOFT_ERROR;
    }

#if 1   // this might be a little too picky...
    WavpackLittleEndianToNative (&filehdr, Wave64ChunkHeaderFormat);

    if (infilesize && !(config->qmode & QMODE_IGNORE_LENGTH) &&
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -53,6 +53,7 @@
     Wave64ChunkHeader chunk_header;
     Wave64FileHeader filehdr;
     WaveHeader WaveHeader;
+    int format_chunk = 0;
     uint32_t bcount;
 
     infilesize = DoGetFileSize (infile);
@@ -103,6 +104,11 @@
 
         if (!memcmp (chunk_header.ckID, fmt_guid, sizeof (fmt_guid))) {
             int supported = TRUE, format;
+
+            if (format_chunk++) {
+                error_line ("%s is not a valid .W64 file!", infilename);
+                return WAVPACK_SOFT_ERROR;
+            }
 
             chunk_header.ckSize = (chunk_header.ckSize + 7) & ~7L;
 
```
