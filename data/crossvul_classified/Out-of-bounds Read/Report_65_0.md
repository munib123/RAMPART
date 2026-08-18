# CrossVul Fix Pair: Out-of-bounds Read in cpp
**Pair ID:** 65_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `65_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```cpp
Lines 1187-1227 of the vulnerable file.

			{
				memory.elapsedTime += (memory.elapsedTime - i.first) * (double)(i.second - 1);
				for(CHANNELINDEX nChn = 0; nChn < GetNumChannels(); nChn++, pChn++)
				{
					if(memory.chnSettings[nChn].patLoop == i.first)
					{
						playState.m_lTotalSampleCount += (playState.m_lTotalSampleCount - memory.chnSettings[nChn].patLoopSmp) * (i.second - 1);
						if(m_playBehaviour[kITPatternLoopTargetReset] || (GetType() == MOD_TYPE_S3M))
						{
							memory.chnSettings[nChn].patLoop = memory.elapsedTime;
							memory.chnSettings[nChn].patLoopSmp = playState.m_lTotalSampleCount;
							memory.chnSettings[nChn].patLoopStart = playState.m_nRow + 1;
						}
						break;
					}
				}
			}
			if(GetType() == MOD_TYPE_IT)
			{
				// IT pattern loop start row update - at the end of a pattern loop, set pattern loop start to next row (for upcoming pattern loops with missing SB0)
				for(CHANNELINDEX nChn = 0; nChn < GetNumChannels(); nChn++)
				{
					if((pChn->rowCommand.command == CMD_S3MCMDEX && pChn->rowCommand.param >= 0xB1 && pChn->rowCommand.param <= 0xBF))
					{
						memory.chnSettings[nChn].patLoop = memory.elapsedTime;
						memory.chnSettings[nChn].patLoopSmp = playState.m_lTotalSampleCount;
					}
				}
			}
		}
	}

	// Now advance the sample positions for sample seeking on channels that are still playing
	if(adjustSamplePos)
	{
		for(CHANNELINDEX nChn = 0; nChn < GetNumChannels(); nChn++)
		{
			if(memory.chnSettings[nChn].ticksToRender != GetLengthMemory::IGNORE_CHANNEL)
			{
				memory.RenderChannel(nChn, oldTickDuration);
			}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1204,7 +1204,8 @@
 			if(GetType() == MOD_TYPE_IT)
 			{
 				// IT pattern loop start row update - at the end of a pattern loop, set pattern loop start to next row (for upcoming pattern loops with missing SB0)
-				for(CHANNELINDEX nChn = 0; nChn < GetNumChannels(); nChn++)
+				pChn = playState.Chn;
+				for(CHANNELINDEX nChn = 0; nChn < GetNumChannels(); nChn++, pChn++)
 				{
 					if((pChn->rowCommand.command == CMD_S3MCMDEX && pChn->rowCommand.param >= 0xB1 && pChn->rowCommand.param <= 0xBF))
 					{
```
