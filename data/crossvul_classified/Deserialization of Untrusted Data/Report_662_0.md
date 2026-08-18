# CrossVul Fix Pair: Deserialization of Untrusted Data in java
**Pair ID:** 662_0
**Vulnerability Class:** Deserialization of Untrusted Data
**CWE:** CWE-502
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `662_0`)

## Vulnerability Information & PoC

## Description
Deserialization of Untrusted Data - It is often convenient to serialize objects for communication or to save them for later use.

## Vulnerable Code
```java
Lines 23-63 of the vulnerable file.

 *
 */
package org.slf4j.ext;

import java.io.Serializable;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.beans.XMLDecoder;
import java.beans.XMLEncoder;
import java.beans.ExceptionListener;

/**
 * Base class for Event Data. Event Data contains data to be logged about an
 * event. Users may extend this class for each EventType they want to log.
 * 
 * @author Ralph Goers
 */
public class EventData implements Serializable {

    private static final long serialVersionUID = 153270778642103985L;

    private Map<String, Object> eventData = new HashMap<String, Object>();
    public static final String EVENT_MESSAGE = "EventMessage";
    public static final String EVENT_TYPE = "EventType";
    public static final String EVENT_DATETIME = "EventDateTime";
    public static final String EVENT_ID = "EventId";

    /**
     * Default Constructor
     */
    public EventData() {
    }

    /**
     * Constructor to create event data from a Map.
     * 
     * @param map
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -40,6 +40,8 @@
  * event. Users may extend this class for each EventType they want to log.
  * 
  * @author Ralph Goers
+ * 
+ * @deprecated Due to a security vulnerability, this class will be removed without replacement.
  */
 public class EventData implements Serializable {
 
```
