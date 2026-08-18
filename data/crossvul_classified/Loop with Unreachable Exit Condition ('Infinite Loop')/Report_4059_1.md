# CrossVul Fix Pair: Loop with Unreachable Exit Condition ('Infinite Loop') in c
**Pair ID:** 4059_1
**Vulnerability Class:** Loop with Unreachable Exit Condition ('Infinite Loop')
**CWE:** CWE-835
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4059_1`)

## Vulnerability Information & PoC

## Description
Loop with Unreachable Exit Condition ('Infinite Loop') - If the loop can be influenced by an attacker, this weakness could allow attackers to consume excessive resources such as CPU or memory.

## Vulnerable Code
```c
Lines 255-295 of the vulnerable file.

  if(!client) {
    rfbClientErr("Couldn't allocate client structure!\n");
    return NULL;
  }
#ifdef WIN32
  if((errno = WSAStartup(MAKEWORD(2,0), &unused)) != 0) {
      rfbClientErr("Could not init Windows Sockets: %s\n", strerror(errno));
      return NULL;
  }
#endif
  initAppData(&client->appData);
  client->endianTest = 1;
  client->programName="";
  client->serverHost=strdup("");
  client->serverPort=5900;

  client->destHost = NULL;
  client->destPort = 5900;
  
  client->connectTimeout = DEFAULT_CONNECT_TIMEOUT;

  client->CurrentKeyboardLedState = 0;
  client->HandleKeyboardLedState = (HandleKeyboardLedStateProc)DummyPoint;

  /* default: use complete frame buffer */ 
  client->updateRect.x = -1;
 
  client->frameBuffer = NULL;
  client->outputWindow = 0;
 
  client->format.bitsPerPixel = bytesPerPixel*8;
  client->format.depth = bitsPerSample*samplesPerPixel;
  client->appData.requestedDepth=client->format.depth;
  client->format.bigEndian = *(char *)&client->endianTest?FALSE:TRUE;
  client->format.trueColour = 1;

  if (client->format.bitsPerPixel == 8) {
    client->format.redMax = 7;
    client->format.greenMax = 7;
    client->format.blueMax = 3;
    client->format.redShift = 0;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -272,6 +272,7 @@
   client->destPort = 5900;
   
   client->connectTimeout = DEFAULT_CONNECT_TIMEOUT;
+  client->readTimeout = DEFAULT_READ_TIMEOUT;
 
   client->CurrentKeyboardLedState = 0;
   client->HandleKeyboardLedState = (HandleKeyboardLedStateProc)DummyPoint;
```
