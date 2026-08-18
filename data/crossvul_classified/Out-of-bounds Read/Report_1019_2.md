# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 1019_2
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1019_2`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 29-69 of the vulnerable file.



extern void PrintGPMF(GPMF_stream *ms);

int main(int argc, char *argv[])
{
	int32_t ret = GPMF_OK;
	GPMF_stream metadata_stream, *ms = &metadata_stream;
	double metadatalength;
	uint32_t *payload = NULL; //buffer to store GPMF samples from the MP4.


	// get file return data
	if (argc != 2)
	{
		printf("usage: %s <file_with_GPMF>\n", argv[0]);
		return -1;
	}

	size_t mp4 = OpenMP4Source(argv[1], MOV_GPMF_TRAK_TYPE, MOV_GPMF_TRAK_SUBTYPE);
//	size_t mp4 = OpenMP4SourceUDTA(argv[1]);  //Search for GPMF payload with MP4's udta 

	metadatalength = GetDuration(mp4);

	if (metadatalength > 0.0)
	{
		uint32_t index, payloads = GetNumberPayloads(mp4);
//		printf("found %.2fs of metadata, from %d payloads, within %s\n", metadatalength, payloads, argv[1]);

#if 1
		if (payloads == 1) // Printf the contents of the single payload
		{
			uint32_t payloadsize = GetPayloadSize(mp4,0);
			payload = GetPayload(mp4, payload, 0);
			if(payload == NULL)
				goto cleanup;

			ret = GPMF_Init(ms, payload, payloadsize);
			if (ret != GPMF_OK)
				goto cleanup;

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -46,6 +46,12 @@
 	}
 
 	size_t mp4 = OpenMP4Source(argv[1], MOV_GPMF_TRAK_TYPE, MOV_GPMF_TRAK_SUBTYPE);
+	if (mp4 == 0)
+	{
+		printf("error: %s is an invalid MP4/MOV\n", argv[1]);
+		return -1;
+	}
+
 //	size_t mp4 = OpenMP4SourceUDTA(argv[1]);  //Search for GPMF payload with MP4's udta 
 
 	metadatalength = GetDuration(mp4);
@@ -90,7 +96,7 @@
 		for (index = 0; index < payloads; index++)
 		{
 			uint32_t payloadsize = GetPayloadSize(mp4, index);
-			float in = 0.0, out = 0.0; //times
+			double in = 0.0, out = 0.0; //times
 			payload = GetPayload(mp4, payload, index);
 			if (payload == NULL)
 				goto cleanup;
@@ -238,9 +244,10 @@
 		{
 			if (GPMF_OK == GPMF_SeekToSamples(ms)) //find the last FOURCC within the stream
 			{
+				double in = 0.0, out = 0.0;
 				uint32_t fourcc = GPMF_Key(ms);
-				double rate = GetGPMFSampleRate(mp4, fourcc, GPMF_SAMPLE_RATE_PRECISE);// GPMF_SAMPLE_RATE_FAST);
-				printf("%c%c%c%c sampling rate = %f Hz\n", PRINTF_4CC(fourcc), rate);
+				double rate = GetGPMFSampleRate(mp4, fourcc, GPMF_SAMPLE_RATE_PRECISE, &in, &out);// GPMF_SAMPLE_RATE_FAST);
+				printf("%c%c%c%c sampling rate = %f Hz (from %f to %f)\n", PRINTF_4CC(fourcc), rate, in, out);
 			}
 		}
 #endif
```
