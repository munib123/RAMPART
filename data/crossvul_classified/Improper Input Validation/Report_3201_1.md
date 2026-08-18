# CrossVul Fix Pair: Improper Input Validation in cpp
**Pair ID:** 3201_1
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3201_1`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```cpp
Lines 86-126 of the vulnerable file.

    : Http::ResponseBuilder(parent)
    , session_(0)
{
    QTimer *timer = new QTimer(this);
    timer->setInterval(60000); // 1 min.
    connect(timer, SIGNAL(timeout()), SLOT(removeInactiveSessions()));
}

AbstractWebApplication::~AbstractWebApplication()
{
    // cleanup sessions data
    qDeleteAll(sessions_);
}

Http::Response AbstractWebApplication::processRequest(const Http::Request &request, const Http::Environment &env)
{
    session_ = 0;
    request_ = request;
    env_ = env;

    clear(); // clear response

    sessionInitialize();
    if (!sessionActive() && !isAuthNeeded())
        sessionStart();

    if (isBanned()) {
        status(403, "Forbidden");
        print(QObject::tr("Your IP address has been banned after too many failed authentication attempts."), Http::CONTENT_TYPE_TXT);
    }
    else {
        processRequest();
    }

    return response();
}

void AbstractWebApplication::UnbanTimerEvent()
{
    UnbanTimer* ubantimer = static_cast<UnbanTimer*>(sender());
    qDebug("Ban period has expired for %s", qPrintable(ubantimer->peerIp().toString()));
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -103,7 +103,11 @@
     request_ = request;
     env_ = env;
 
-    clear(); // clear response
+    // clear response
+    clear();
+
+    // avoid clickjacking attacks
+    header(Http::HEADER_X_FRAME_OPTIONS, "SAMEORIGIN");
 
     sessionInitialize();
     if (!sessionActive() && !isAuthNeeded())
```
