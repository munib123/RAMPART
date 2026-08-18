# CrossVul Fix Pair: Improper Restriction of XML External Entity Reference in java
**Pair ID:** 1910_7
**Vulnerability Class:** XML External Entities (XXE)
**CWE:** CWE-611
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1910_7`)

## Vulnerability Information & PoC

## Description
Improper Restriction of XML External Entity Reference - XML documents optionally contain a Document Type Definition (DTD), which, among other features, enables the definition of XML entities.

## Vulnerable Code
```java
Lines 65-106 of the vulnerable file.

    static final int TYPE_INFO = 1;
    static final int TYPE_WARNING = 2;
    static final int TYPE_ERROR = 3;
    private final Map<String, @Nullable String> channels = new ConcurrentHashMap<>();
    private final String host;
    private boolean power;
    private String channel = "";
    private String title = "";
    private String description = "";
    private String answer = "";
    private int volume = 0;
    private boolean mute;
    private boolean online;
    private boolean initialized;
    private boolean asking;
    private LocalDateTime lastAnswerTime = LocalDateTime.of(2020, 1, 1, 0, 0); // Date in the past
    private final Enigma2HttpClient enigma2HttpClient;
    private final DocumentBuilderFactory factory;

    public Enigma2Client(String host, @Nullable String user, @Nullable String password, int requestTimeout) {
        this.enigma2HttpClient = new Enigma2HttpClient(requestTimeout);
        this.factory = DocumentBuilderFactory.newInstance();
        if (StringUtils.isNotEmpty(user) && StringUtils.isNotEmpty(password)) {
            this.host = "http://" + user + ":" + password + "@" + host;
        } else {
            this.host = "http://" + host;
        }
    }

    public boolean refresh() {
        boolean wasOnline = online;
        refreshPower();
        if (!wasOnline && online) {
            // Only refresh all services if the box changed from offline to online and power is on
            // because it is a performance intensive action.
            refreshAllServices();
        }
        refreshChannel();
        refreshEpg();
        refreshVolume();
        refreshAnswer();
        return online;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -82,8 +82,18 @@
     private final DocumentBuilderFactory factory;
 
     public Enigma2Client(String host, @Nullable String user, @Nullable String password, int requestTimeout) {
-        this.enigma2HttpClient = new Enigma2HttpClient(requestTimeout);
-        this.factory = DocumentBuilderFactory.newInstance();
+        enigma2HttpClient = new Enigma2HttpClient(requestTimeout);
+        factory = DocumentBuilderFactory.newInstance();
+        // see https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html
+        try {
+            factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
+            factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
+            factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
+            factory.setXIncludeAware(false);
+            factory.setExpandEntityReferences(false);
+        } catch (ParserConfigurationException e) {
+            logger.warn("Failed setting parser features against XXE attacks!", e);
+        }
         if (StringUtils.isNotEmpty(user) && StringUtils.isNotEmpty(password)) {
             this.host = "http://" + user + ":" + password + "@" + host;
         } else {
```
