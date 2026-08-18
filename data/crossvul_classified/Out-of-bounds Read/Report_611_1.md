# CrossVul Fix Pair: Out-of-bounds Read in cpp
**Pair ID:** 611_1
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `611_1`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```cpp
Lines 3-43 of the vulnerable file.

 * ------------
 * Purpose: STP (Soundtracker Pro II) module loader
 * Notes  : A few exotic effects aren't supported.
 *          Multiple sample loops are supported, but only the first 10 can be used as cue points
 *          (with 16xx and 18xx).
 *          Fractional speed values and combined auto effects are handled whenever possible,
 *          but some effects may be omitted (and there may be tempo accuracy issues).
 * Authors: Devin Acker
 *          OpenMPT Devs
 * The OpenMPT source code is released under the BSD license. Read LICENSE for more details.
 *
 * Wisdom from the Soundtracker Pro II manual:
 * "To create shorter patterns, simply create shorter patterns."
 */

#include "stdafx.h"
#include "Loaders.h"

OPENMPT_NAMESPACE_BEGIN

// File header (except for "STP3" magic)
struct STPFileHeader
{
	char     magic[4];
	uint16be version;
	uint8be  numOrders;
	uint8be  patternLength;
	uint8be  orderList[128];
	uint16be speed;
	uint16be speedFrac;
	uint16be timerCount;
	uint16be flags;
	uint32be reserved;
	uint16be midiCount; // always 50
	uint8be  midi[50];
	uint16be numSamples;
	uint16be sampleStructSize;
};

MPT_BINARY_STRUCT(STPFileHeader, 204)

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -20,7 +20,7 @@
 
 OPENMPT_NAMESPACE_BEGIN
 
-// File header (except for "STP3" magic)
+// File header
 struct STPFileHeader
 {
 	char     magic[4];
@@ -108,10 +108,14 @@
 
 static void ConvertLoopSlice(ModSample &src, ModSample &dest, SmpLength start, SmpLength len, bool loop)
 {
-	if(!src.HasSampleData()) return;
+	if(!src.HasSampleData()
+		|| start >= src.nLength
+		|| src.nLength - start < len)
+	{
+		return;
+	}
 
 	dest.FreeSample();
-
 	dest = src;
 	dest.nLength = len;
 	dest.pSample = nullptr;
@@ -150,16 +154,16 @@
 
 	size_t numLoops = loopList.size();
 
-	// get the total length of the sample after combining all looped sections
+	// Get the total length of the sample after combining all looped sections
 	for(size_t i = 0; i < numLoops; i++)
 	{
 		STPLoopInfo &info = loopList[i];
 
-		// if adding this loop would cause the sample length to exceed maximum,
+		// If adding this loop would cause the sample length to exceed maximum,
 		// then limit and bail out
-		if((newSmp.nLength + info.loopLength > MAX_SAMPLE_LENGTH) ||
-		   (info.loopLength > MAX_SAMPLE_LENGTH) ||
-		   (info.loopStart + info.loopLength > smp.nLength))
+		if(info.loopStart >= smp.nLength
+			|| smp.nLength - info.loopStart < info.loopLength
+			|| newSmp.nLength > MAX_SAMPLE_LENGTH - info.loopLength)
 		{
 			numLoops = i;
 			break;
@@ -264,7 +268,7 @@
 	ReadOrderFromArray(Order(), fileHeader.orderList, fileHeader.numOrders);
 
 	std::vector<STPLoopList> loopInfo;
-	// non-looped versions of samples with loops (when needed)
+	// Non-looped versions of samples with loops (when needed)
 	std::vector<SAMPLEINDEX> nonLooped;
 
 	// Load sample headers
@@ -380,6 +384,7 @@
 	};
 	std::vector<ChannelMemory> channelMemory(m_nChannels);
 	uint8 globalVolSlide = 0;
+	uint8 speedFrac = static_cast<uint8>(fileHeader.speedFrac);
 
 	for(uint16 pat = 0; pat < numPatterns; pat++)
 	{
@@ -409,7 +414,7 @@
 
 			// if a fractional speed value is in use then determine if we should stick a fine pattern delay somewhere
 			bool shouldDelay;
-			switch(fileHeader.speedFrac & 3)
+			switch(speedFrac & 3)
 			{
 			default: shouldDelay = false; break;
 			// 1/4
@@ -475,7 +480,7 @@
 					chnMem.autoPortaDown = 0;
 					chnMem.autoTonePorta = 0;
 
-					m.command = m.param = 0;
+					m.command = CMD_NONE;
 					break;
 
 				case 0x04: // auto fine portamento down
@@ -484,7 +489,7 @@
 					chnMem.autoPortaDown = 0;
 					chnMem.autoTonePorta = 0;
 
-					m.command = m.param = 0;
+					m.command = CMD_NONE;
 					break;
 
 				case 0x05: // auto portamento up
@@ -493,7 +498,7 @@
 					chnMem.autoPortaDown = 0;
 					chnMem.autoTonePorta = 0;
 
-					m.command = m.param = 0;
+					m.command = CMD_NONE;
 					break;
 
 				case 0x06: // auto portamento down
@@ -502,7 +507,7 @@
 					chnMem.autoPortaDown = m.param;
 					chnMem.autoTonePorta = 0;
 
-					m.command = m.param = 0;
+					m.command = CMD_NONE;
 					break;
 
 				case 0x07: // set global volume
@@ -512,7 +517,7 @@
 
 				case 0x08: // auto global fine volume slide
 					globalVolSlide = swapped;
-					m.command = m.param = 0;
+					m.command = CMD_NONE;
 					break;
 
 				case 0x09: // fine portamento up
@@ -527,14 +532,14 @@
 
 				case 0x0B: // auto fine volume slide
 					chnMem.autoVolSlide = swapped;
-					m.command = m.param = 0;
+					m.command = CMD_NONE;
 					break;
 
 				case 0x0C: // set volume
 					m.volcmd = VOLCMD_VOLUME;
 					m.vol = m.param;
 					chnMem.autoVolSlide = 0;
-					m.command = m.param = 0;
+					m.command = CMD_NONE;
 					break;
 
 				case 0x0D: // volume slide (param is swapped compared to .mod)
@@ -548,7 +553,7 @@
 						m.vol = m.param & 0xF;
 					}
 					chnMem.autoVolSlide = 0;
-					m.command = m.param = 0;
+					m.command = CMD_NONE;
 					break;
 
 				case 0x0E: // set filter (also uses opposite value compared to .mod)
@@ -558,14 +563,14 @@
 
 				case 0x0F: // set speed
 					m.command = CMD_SPEED;
-					fileHeader.speedFrac = m.param & 0xF;
+					speedFrac = m.param & 0x0F;
 					m.param >>= 4;
 					break;
 
 				case 0x10: // auto vibrato
 					chnMem.autoVibrato = m.param;
 					chnMem.vibratoMem = 0;
-					m.command = m.param = 0;
+					m.command = CMD_NONE;
 					break;
 
 				case 0x11: // auto tremolo
@@ -573,7 +578,7 @@
 						chnMem.autoTremolo = m.param;
 					else
 						chnMem.autoTremolo = 0;
-					m.command = m.param = 0;
+					m.command = CMD_NONE;
 					break;
 
 				case 0x12: // pattern break
@@ -587,7 +592,7 @@
 					chnMem.autoTonePorta = m.param;
 
 					chnMem.tonePortaMem = 0;
-					m.command = m.param = 0;
+					m.command = CMD_NONE;
 					break;
 
 				case 0x14: // position jump
@@ -607,7 +612,7 @@
 						}
 					}
 
-					m.command = m.param = 0;
+					m.command = CMD_NONE;
 					break;
 
 				case 0x17: // play only loop nn
@@ -624,7 +629,7 @@
 						}
 					}
 
-					m.command = m.param = 0;
+					m.command = CMD_NONE;
 					break;
 
 				case 0x18: // play sequence without loop
@@ -644,7 +649,7 @@
 						m.instr = static_cast<ModCommand::INSTR>(nonLooped[m.instr - 1]);
 					}
 
-					m.command = m.param = 0;
+					m.command = CMD_NONE;
 					break;
 
 				case 0x19: // play only loop nn without loop
@@ -661,7 +666,7 @@
 						}
 					}
 
-					m.command = m.param = 0;
+					m.command = CMD_NONE;
 					break;
 
 				case 0x1D: // fine volume slide (nibble order also swapped)
@@ -679,7 +684,7 @@
 					if(m.param & 0xF0)
 					{
 						chnMem.autoVolSlide = m.param >> 4;
-						m.command = m.param = 0;
+						m.command = CMD_NONE;
 					} else
 					{
 						m.command = CMD_MODCMDEX;
@@ -705,14 +710,14 @@
 					if((m.param & 0xF0) == 0x60 || (m.param & 0xF0) == 0xE0)
 						m.command = CMD_MODCMDEX;
 					else
-						m.command = m.param = 0;
+						m.command = CMD_NONE;
 					break;
 
 				case 0x4F: // set speed/tempo
 					if(m.param < 0x20)
 					{
 						m.command = CMD_SPEED;
-						fileHeader.speedFrac = 0;
+						speedFrac = 0;
 					} else
 					{
 						m.command = CMD_TEMPO;
@@ -727,7 +732,7 @@
 				bool didVolSlide = false;
 
 				// try to put volume slide in volume command
-				if(chnMem.autoVolSlide && !m.volcmd)
+				if(chnMem.autoVolSlide && m.volcmd == VOLCMD_NONE)
 				{
 					if(chnMem.autoVolSlide & 0xF0)
 					{
```
