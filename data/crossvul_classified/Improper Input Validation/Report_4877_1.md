# CrossVul Fix Pair: Improper Input Validation in cpp
**Pair ID:** 4877_1
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4877_1`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```cpp
Lines 19-59 of the vulnerable file.

bool WebSocketProtocol<isServer>::refusePayloadLength(void *user, int length) {
    return length > 16777216;
}

template <const bool isServer>
void WebSocketProtocol<isServer>::forceClose(void *user) {
    WebSocket<isServer>((uv_poll_t *) user).terminate();
}

template <const bool isServer>
bool WebSocketProtocol<isServer>::handleFragment(char *data, size_t length, unsigned int remainingBytes, int opCode, bool fin, void *user) {
    uS::Socket s((uv_poll_t *) user);
    typename WebSocket<isServer>::Data *webSocketData = (typename WebSocket<isServer>::Data *) s.getSocketData();

    if (opCode < 3) {
        if (!remainingBytes && fin && !webSocketData->fragmentBuffer.length()) {
            if (webSocketData->compressionStatus == WebSocket<isServer>::Data::CompressionStatus::COMPRESSED_FRAME) {
                webSocketData->compressionStatus = WebSocket<isServer>::Data::CompressionStatus::ENABLED;
                Hub *hub = ((Group<isServer> *) s.getSocketData()->nodeData)->hub;
                data = hub->inflate(data, length);
            }

            if (opCode == 1 && !isValidUtf8((unsigned char *) data, length)) {
                forceClose(user);
                return true;
            }

            ((Group<isServer> *) s.getSocketData()->nodeData)->messageHandler(WebSocket<isServer>(s), data, length, (OpCode) opCode);
            if (s.isClosed() || s.isShuttingDown()) {
                return true;
            }
        } else {
            webSocketData->fragmentBuffer.append(data, length);
            if (!remainingBytes && fin) {
                length = webSocketData->fragmentBuffer.length();
                if (webSocketData->compressionStatus == WebSocket<isServer>::Data::CompressionStatus::COMPRESSED_FRAME) {
                    webSocketData->compressionStatus = WebSocket<isServer>::Data::CompressionStatus::ENABLED;
                    Hub *hub = ((Group<isServer> *) s.getSocketData()->nodeData)->hub;
                    webSocketData->fragmentBuffer.append("....");
                    data = hub->inflate((char *) webSocketData->fragmentBuffer.data(), length);
                } else {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -36,6 +36,10 @@
                 webSocketData->compressionStatus = WebSocket<isServer>::Data::CompressionStatus::ENABLED;
                 Hub *hub = ((Group<isServer> *) s.getSocketData()->nodeData)->hub;
                 data = hub->inflate(data, length);
+                if (!data) {
+                    forceClose(user);
+                    return true;
+                }
             }
 
             if (opCode == 1 && !isValidUtf8((unsigned char *) data, length)) {
@@ -56,6 +60,10 @@
                     Hub *hub = ((Group<isServer> *) s.getSocketData()->nodeData)->hub;
                     webSocketData->fragmentBuffer.append("....");
                     data = hub->inflate((char *) webSocketData->fragmentBuffer.data(), length);
+                    if (!data) {
+                        forceClose(user);
+                        return true;
+                    }
                 } else {
                     data = (char *) webSocketData->fragmentBuffer.data();
                 }
```
