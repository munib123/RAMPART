# CrossVul Fix Pair: Improper Input Validation in cpp
**Pair ID:** 600_2
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `600_2`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```cpp
Lines 3551-3570 of the vulnerable file.

  flushRequestsAndLoop();
  gracefulShutdown();
}

TEST_F(HTTP2DownstreamSessionTest, TestSetEgressSettings) {
  SettingsList settings = {{ SettingsId::HEADER_TABLE_SIZE, 5555 },
                           { SettingsId::MAX_FRAME_SIZE, 16384 },
                           { SettingsId::ENABLE_PUSH, 1 }};

  const HTTPSettings* codecSettings = rawCodec_->getEgressSettings();
  for (const auto& setting: settings) {
    const HTTPSetting* currSetting = codecSettings->getSetting(setting.id);
    if (currSetting) {
      EXPECT_EQ(setting.value, currSetting->value);
    }
  }

  flushRequestsAndLoop();
  gracefulShutdown();
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -3568,3 +3568,35 @@
   flushRequestsAndLoop();
   gracefulShutdown();
 }
+
+TEST_F(HTTP2DownstreamSessionTest, TestDuplicateRequestStream) {
+  // Send the following:
+  // HEADERS id=1
+  // HEADERS id=2
+  // HEADERS id=1 (trailers)
+  // HEADERS id=2 -> contains pseudo-headers after EOM so ignored
+  auto handler2 = addSimpleStrictHandler();
+  auto handler1 = addSimpleStrictHandler();
+  auto streamID1 = sendRequest("/withtrailers", 0, false);
+  auto streamID2 = sendRequest();
+  HTTPHeaders trailers;
+  trailers.add("Foo", "Bar");
+  clientCodec_->generateTrailers(requests_, streamID1, trailers);
+  clientCodec_->generateEOM(requests_, streamID1);
+
+  clientCodec_->generateHeader(requests_, streamID2, getGetRequest(), false);
+  handler1->expectHeaders();
+  handler2->expectHeaders();
+  handler2->expectEOM();
+  handler1->expectTrailers();
+  handler1->expectEOM([&] {
+      handler1->sendReplyWithBody(200, 100);
+      // 2 got an error after EOM, which gets ignored - need a response to
+      // cleanly terminate it
+      handler2->sendReplyWithBody(200, 100);
+    });
+  handler1->expectDetachTransaction();
+  handler2->expectDetachTransaction();
+  flushRequestsAndLoop();
+  gracefulShutdown();
+}
```
