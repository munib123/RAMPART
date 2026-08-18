# CrossVul Fix Pair: Out-of-bounds Write in c
**Pair ID:** 95_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-787
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `95_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Write - Typically, this can result in corruption of data, a crash, or code execution.

## Vulnerable Code
```c
Lines 36-76 of the vulnerable file.


typedef struct {
    char ckID [4];
    uint32_t ckSize;
    char junk [28];
} JunkChunk;

#pragma pack(pop)

#define CS64ChunkFormat "4D"
#define DS64ChunkFormat "DDDL"

#define WAVPACK_NO_ERROR    0
#define WAVPACK_SOFT_ERROR  1
#define WAVPACK_HARD_ERROR  2

extern int debug_logging_mode;

int ParseRiffHeaderConfig (FILE *infile, char *infilename, char *fourcc, WavpackContext *wpc, WavpackConfig *config)
{
    int is_rf64 = !strncmp (fourcc, "RF64", 4), got_ds64 = 0;
    int64_t total_samples = 0, infilesize;
    RiffChunkHeader riff_chunk_header;
    ChunkHeader chunk_header;
    WaveHeader WaveHeader;
    DS64Chunk ds64_chunk;
    uint32_t bcount;

    CLEAR (WaveHeader);
    CLEAR (ds64_chunk);
    infilesize = DoGetFileSize (infile);

    if (!is_rf64 && infilesize >= 4294967296LL && !(config->qmode & QMODE_IGNORE_LENGTH)) {
        error_line ("can't handle .WAV files larger than 4 GB (non-standard)!");
        return WAVPACK_SOFT_ERROR;
    }

    memcpy (&riff_chunk_header, fourcc, 4);

    if ((!DoReadFile (infile, ((char *) &riff_chunk_header) + 4, sizeof (RiffChunkHeader) - 4, &bcount) ||
        bcount != sizeof (RiffChunkHeader) - 4 || strncmp (riff_chunk_header.formType, "WAVE", 4))) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -53,7 +53,7 @@
 
 int ParseRiffHeaderConfig (FILE *infile, char *infilename, char *fourcc, WavpackContext *wpc, WavpackConfig *config)
 {
-    int is_rf64 = !strncmp (fourcc, "RF64", 4), got_ds64 = 0;
+    int is_rf64 = !strncmp (fourcc, "RF64", 4), got_ds64 = 0, format_chunk = 0;
     int64_t total_samples = 0, infilesize;
     RiffChunkHeader riff_chunk_header;
     ChunkHeader chunk_header;
@@ -139,6 +139,11 @@
         }
         else if (!strncmp (chunk_header.ckID, "fmt ", 4)) {     // if it's the format chunk, we want to get some info out of there and
             int supported = TRUE, format;                        // make sure it's a .wav file we can handle
+
+            if (format_chunk++) {
+                error_line ("%s is not a valid .WAV file!", infilename);
+                return WAVPACK_SOFT_ERROR;
+            }
 
             if (chunk_header.ckSize < 16 || chunk_header.ckSize > sizeof (WaveHeader) ||
                 !DoReadFile (infile, &WaveHeader, chunk_header.ckSize, &bcount) ||
```
