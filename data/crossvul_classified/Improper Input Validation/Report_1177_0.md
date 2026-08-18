# CrossVul Fix Pair: Improper Input Validation in java
**Pair ID:** 1177_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1177_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```java
Lines 139-179 of the vulnerable file.

    }
    InetSocketAddress remoteAddress = (InetSocketAddress) channel.remoteAddress();
    InetSocketAddress socketAddress = (InetSocketAddress) channel.localAddress();

    ConnectionIdleTimeout connectionIdleTimeout = ConnectionIdleTimeout.of(channel);

    DefaultRequest request = new DefaultRequest(
      clock.instant(),
      requestHeaders,
      nettyRequest.method(),
      nettyRequest.protocolVersion(),
      nettyRequest.uri(),
      remoteAddress,
      socketAddress,
      serverRegistry.get(ServerConfig.class),
      requestBody,
      connectionIdleTimeout,
      channel.attr(CLIENT_CERT_KEY).get()
    );

    HttpHeaders nettyHeaders = new DefaultHttpHeaders(false);
    MutableHeaders responseHeaders = new NettyHeadersBackedMutableHeaders(nettyHeaders);
    AtomicBoolean transmitted = new AtomicBoolean(false);

    DefaultResponseTransmitter responseTransmitter = new DefaultResponseTransmitter(transmitted, channel, clock, nettyRequest, request, nettyHeaders, requestBody);

    ctx.channel().attr(DefaultResponseTransmitter.ATTRIBUTE_KEY).set(responseTransmitter);

    Action<Action<Object>> subscribeHandler = thing -> {
      transmitted.set(true);
      ctx.channel().attr(CHANNEL_SUBSCRIBER_ATTRIBUTE_KEY).set(thing);
    };

    DefaultContext.RequestConstants requestConstants = new DefaultContext.RequestConstants(
      applicationConstants,
      request,
      channel,
      responseTransmitter,
      subscribeHandler
    );

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -156,7 +156,7 @@
       channel.attr(CLIENT_CERT_KEY).get()
     );
 
-    HttpHeaders nettyHeaders = new DefaultHttpHeaders(false);
+    HttpHeaders nettyHeaders = new DefaultHttpHeaders();
     MutableHeaders responseHeaders = new NettyHeadersBackedMutableHeaders(nettyHeaders);
     AtomicBoolean transmitted = new AtomicBoolean(false);
 
```
