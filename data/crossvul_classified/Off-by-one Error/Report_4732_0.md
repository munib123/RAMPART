# CrossVul Fix Pair: Off-by-one Error in c
**Pair ID:** 4732_0
**Vulnerability Class:** Off-by-one Error
**CWE:** CWE-193
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4732_0`)

## Vulnerability Information & PoC

## Description
Off-by-one Error - A product calculates or uses an incorrect maximum or minimum value that is 1 more, or 1 less, than the correct value.

## Vulnerable Code
```c
Lines 2895-2935 of the vulnerable file.

typedef struct _ATOM_ANALOG_TV_INFO
{
  ATOM_COMMON_TABLE_HEADER sHeader;  
  UCHAR                    ucTV_SupportedStandard;
  UCHAR                    ucTV_BootUpDefaultStandard; 
  UCHAR                    ucExt_TV_ASIC_ID;
  UCHAR                    ucExt_TV_ASIC_SlaveAddr;
  /*ATOM_DTD_FORMAT          aModeTimings[MAX_SUPPORTED_TV_TIMING];*/
  ATOM_MODE_TIMING         aModeTimings[MAX_SUPPORTED_TV_TIMING];
}ATOM_ANALOG_TV_INFO;

#define MAX_SUPPORTED_TV_TIMING_V1_2    3

typedef struct _ATOM_ANALOG_TV_INFO_V1_2
{
  ATOM_COMMON_TABLE_HEADER sHeader;  
  UCHAR                    ucTV_SupportedStandard;
  UCHAR                    ucTV_BootUpDefaultStandard; 
  UCHAR                    ucExt_TV_ASIC_ID;
  UCHAR                    ucExt_TV_ASIC_SlaveAddr;
  ATOM_DTD_FORMAT          aModeTimings[MAX_SUPPORTED_TV_TIMING];
}ATOM_ANALOG_TV_INFO_V1_2;

typedef struct _ATOM_DPCD_INFO
{
  UCHAR   ucRevisionNumber;        //10h : Revision 1.0; 11h : Revision 1.1   
  UCHAR   ucMaxLinkRate;           //06h : 1.62Gbps per lane; 0Ah = 2.7Gbps per lane
  UCHAR   ucMaxLane;               //Bits 4:0 = MAX_LANE_COUNT (1/2/4). Bit 7 = ENHANCED_FRAME_CAP 
  UCHAR   ucMaxDownSpread;         //Bit0 = 0: No Down spread; Bit0 = 1: 0.5% (Subject to change according to DP spec)
}ATOM_DPCD_INFO;

#define ATOM_DPCD_MAX_LANE_MASK    0x1F

/**************************************************************************/
// VRAM usage and their defintions

// One chunk of VRAM used by Bios are for HWICON surfaces,EDID data.
// Current Mode timing and Dail Timing and/or STD timing data EACH device. They can be broken down as below.
// All the addresses below are the offsets from the frame buffer start.They all MUST be Dword aligned!
// To driver: The physical address of this memory portion=mmFB_START(4K aligned)+ATOMBIOS_VRAM_USAGE_START_ADDR+ATOM_x_ADDR
// To Bios:  ATOMBIOS_VRAM_USAGE_START_ADDR+ATOM_x_ADDR->MM_INDEX 
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2912,7 +2912,7 @@
   UCHAR                    ucTV_BootUpDefaultStandard; 
   UCHAR                    ucExt_TV_ASIC_ID;
   UCHAR                    ucExt_TV_ASIC_SlaveAddr;
-  ATOM_DTD_FORMAT          aModeTimings[MAX_SUPPORTED_TV_TIMING];
+  ATOM_DTD_FORMAT          aModeTimings[MAX_SUPPORTED_TV_TIMING_V1_2];
 }ATOM_ANALOG_TV_INFO_V1_2;
 
 typedef struct _ATOM_DPCD_INFO
```
