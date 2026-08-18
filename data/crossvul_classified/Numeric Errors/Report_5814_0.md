# CrossVul Fix Pair: Numeric Errors in c
**Pair ID:** 5814_0
**Vulnerability Class:** Numeric Errors
**CWE:** CWE-189
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5814_0`)

## Vulnerability Information & PoC

## Description
Numeric Errors

## Vulnerable Code
```c
Lines 1914-1954 of the vulnerable file.

            break;
        case FF_CMP_NSSE:
            cmp[i]= c->nsse[i];
            break;
#if CONFIG_DWT
        case FF_CMP_W53:
            cmp[i]= c->w53[i];
            break;
        case FF_CMP_W97:
            cmp[i]= c->w97[i];
            break;
#endif
        default:
            av_log(NULL, AV_LOG_ERROR,"internal error in cmp function selection\n");
        }
    }
}

static void add_bytes_c(uint8_t *dst, uint8_t *src, int w){
    long i;
    for(i=0; i<=w-sizeof(long); i+=sizeof(long)){
        long a = *(long*)(src+i);
        long b = *(long*)(dst+i);
        *(long*)(dst+i) = ((a&pb_7f) + (b&pb_7f)) ^ ((a^b)&pb_80);
    }
    for(; i<w; i++)
        dst[i+0] += src[i+0];
}

static void diff_bytes_c(uint8_t *dst, const uint8_t *src1, const uint8_t *src2, int w){
    long i;
#if !HAVE_FAST_UNALIGNED
    if((long)src2 & (sizeof(long)-1)){
        for(i=0; i+7<w; i+=8){
            dst[i+0] = src1[i+0]-src2[i+0];
            dst[i+1] = src1[i+1]-src2[i+1];
            dst[i+2] = src1[i+2]-src2[i+2];
            dst[i+3] = src1[i+3]-src2[i+3];
            dst[i+4] = src1[i+4]-src2[i+4];
            dst[i+5] = src1[i+5]-src2[i+5];
            dst[i+6] = src1[i+6]-src2[i+6];
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1931,7 +1931,7 @@
 
 static void add_bytes_c(uint8_t *dst, uint8_t *src, int w){
     long i;
-    for(i=0; i<=w-sizeof(long); i+=sizeof(long)){
+    for(i=0; i<=w-(int)sizeof(long); i+=sizeof(long)){
         long a = *(long*)(src+i);
         long b = *(long*)(dst+i);
         *(long*)(dst+i) = ((a&pb_7f) + (b&pb_7f)) ^ ((a^b)&pb_80);
@@ -1956,7 +1956,7 @@
         }
     }else
 #endif
-    for(i=0; i<=w-sizeof(long); i+=sizeof(long)){
+    for(i=0; i<=w-(int)sizeof(long); i+=sizeof(long)){
         long a = *(long*)(src1+i);
         long b = *(long*)(src2+i);
         *(long*)(dst+i) = ((a|pb_80) - (b&pb_7f)) ^ ((a^b^pb_80)&pb_80);
```
