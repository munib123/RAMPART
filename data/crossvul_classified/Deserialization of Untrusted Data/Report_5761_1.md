# CrossVul Fix Pair: Deserialization of Untrusted Data in java
**Pair ID:** 5761_1
**Vulnerability Class:** Deserialization of Untrusted Data
**CWE:** CWE-502
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5761_1`)

## Vulnerability Information & PoC

## Description
Deserialization of Untrusted Data - It is often convenient to serialize objects for communication or to save them for later use.

## Vulnerable Code
```java
Lines 357-398 of the vulnerable file.

		if (matcher.find()) {
			if (log.isDebugEnabled()) {
				log.debug(Messages.getMessage(
						Messages.RESTORE_DATA_FROM_RESOURCE_URI_INFO, key,
						dataString));
			}
			int dataStart = matcher.end();
			dataString = key.substring(dataStart);
			byte[] objectArray = null;
			byte[] dataArray;
			try {
				dataArray = dataString.getBytes("ISO-8859-1");
				objectArray = decrypt(dataArray);
			} catch (UnsupportedEncodingException e1) {
				// default encoding always presented.
			}
			if ("B".equals(matcher.group(1))) {
				data = objectArray;
			} else {
				try {
					ObjectInputStream in = new ObjectInputStream(
							new ByteArrayInputStream(objectArray));
					data = in.readObject();
				} catch (StreamCorruptedException e) {
					log.error(Messages
							.getMessage(Messages.STREAM_CORRUPTED_ERROR), e);
				} catch (IOException e) {
					log.error(Messages
							.getMessage(Messages.DESERIALIZE_DATA_INPUT_ERROR),
							e);
				} catch (ClassNotFoundException e) {
					log
							.error(
									Messages
											.getMessage(Messages.DATA_CLASS_NOT_FOUND_ERROR),
									e);
				}
			}
		}

		return data;
	}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -374,8 +374,7 @@
 				data = objectArray;
 			} else {
 				try {
-					ObjectInputStream in = new ObjectInputStream(
-							new ByteArrayInputStream(objectArray));
+					ObjectInputStream in = new LookAheadObjectInputStream(new ByteArrayInputStream(objectArray));
 					data = in.readObject();
 				} catch (StreamCorruptedException e) {
 					log.error(Messages
```
