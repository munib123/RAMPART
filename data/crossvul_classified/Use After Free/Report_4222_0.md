# CrossVul Fix Pair: Use After Free in cpp
**Pair ID:** 4222_0
**Vulnerability Class:** Use After Free
**CWE:** CWE-416
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4222_0`)

## Vulnerability Information & PoC

## Description
Use After Free - The use of previously-freed memory can have any number of adverse consequences, ranging from the corruption of valid data to the execution of arbitrary code, depending on the instantiation and timi...

## Vulnerable Code
```cpp
Lines 185-226 of the vulnerable file.

	masterVolume = panningSeparation = numMaxVirChannels = 256;
	resetMainVolumeOnStartPlayFlag = true;
	playMode = PlayMode_Auto;

	// Special playmode settings
	options[PlayModeOptionPanning8xx] = true;
	options[PlayModeOptionPanningE8x] = false;
	options[PlayModeOptionForcePTPitchLimit] = true;

	AudioDriverManager audioDriverManager;
	const char* defaultName = audioDriverManager.getPreferredAudioDriver()->getDriverID();
	if (defaultName)
	{
		audioDriverName = new char[strlen(defaultName)+1];
		strcpy(audioDriverName, defaultName);
	}
}
	
PlayerGeneric::~PlayerGeneric()
{
	if (mixer)
		delete mixer;

	if (player)
	{
		if (mixer->isActive() && !mixer->isDeviceRemoved(player))
			mixer->removeDevice(player);
		delete player;
	}

	delete[] audioDriverName;
	
	delete listener;
}

// -- wrapping mixer specific stuff ----------------------
void PlayerGeneric::setResamplerType(ResamplerTypes type)
{
	resamplerType = type;
	if (player)
		player->setResamplerType(type);
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -202,15 +202,16 @@
 	
 PlayerGeneric::~PlayerGeneric()
 {
-	if (mixer)
-		delete mixer;
-
-	if (player)
-	{
-		if (mixer->isActive() && !mixer->isDeviceRemoved(player))
+
+	if (player)
+	{
+		if (mixer && mixer->isActive() && !mixer->isDeviceRemoved(player))
 			mixer->removeDevice(player);
 		delete player;
 	}
+	
+	if (mixer)
+		delete mixer;
 
 	delete[] audioDriverName;
 	
```
