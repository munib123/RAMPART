# CrossVul Fix Pair: Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') in java
**Pair ID:** 1678_2
**Vulnerability Class:** Code Injection
**CWE:** CWE-74
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1678_2`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') - Software or other automated logic has certain assumptions about what constitutes data and control respectively.

## Vulnerable Code
```java
Lines 69-109 of the vulnerable file.

        stream.setVersion(version);
        stream.writeLong(requestId);
        byte status = 0;
        status = TransportStatus.setResponse(status);
        stream.writeByte(status); // 0 for request, 1 for response.
        response.writeTo(stream);
        stream.close();
        final byte[] data = bStream.bytes().toBytes();
        targetTransport.workers().execute(new Runnable() {
            @Override
            public void run() {
                targetTransport.messageReceived(data, action, sourceTransport, version, null);
            }
        });
        sourceTransportServiceAdapter.onResponseSent(requestId, action, response, options);
    }

    @Override
    public void sendResponse(Throwable error) throws IOException {
        BytesStreamOutput stream = new BytesStreamOutput();
        try {
            writeResponseExceptionHeader(stream);
            RemoteTransportException tx = new RemoteTransportException(targetTransport.nodeName(), targetTransport.boundAddress().boundAddress(), action, error);
            ThrowableObjectOutputStream too = new ThrowableObjectOutputStream(stream);
            too.writeObject(tx);
            too.close();
        } catch (NotSerializableException e) {
            stream.reset();
            writeResponseExceptionHeader(stream);
            RemoteTransportException tx = new RemoteTransportException(targetTransport.nodeName(), targetTransport.boundAddress().boundAddress(), action, new NotSerializableTransportException(error));
            ThrowableObjectOutputStream too = new ThrowableObjectOutputStream(stream);
            too.writeObject(tx);
            too.close();
        }
        final byte[] data = stream.bytes().toBytes();
        targetTransport.workers().execute(new Runnable() {
            @Override
            public void run() {
                targetTransport.messageReceived(data, action, sourceTransport, version, null);
            }
        });
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -86,6 +86,10 @@
     @Override
     public void sendResponse(Throwable error) throws IOException {
         BytesStreamOutput stream = new BytesStreamOutput();
+        if (ThrowableObjectOutputStream.canSerialize(error) == false) {
+            assert false : "Can not serialize exception: " + error; // make sure tests fail
+            error = new NotSerializableTransportException(error);
+        }
         try {
             writeResponseExceptionHeader(stream);
             RemoteTransportException tx = new RemoteTransportException(targetTransport.nodeName(), targetTransport.boundAddress().boundAddress(), action, error);
```
