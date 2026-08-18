# CrossVul Fix Pair: Deserialization of Untrusted Data in java
**Pair ID:** 5761_3
**Vulnerability Class:** Deserialization of Untrusted Data
**CWE:** CWE-502
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5761_3`)

## Vulnerability Information & PoC

## Description
Deserialization of Untrusted Data - It is often convenient to serialize objects for communication or to save them for later use.

## Vulnerable Code
```java
Lines 139-175 of the vulnerable file.

			// Send headers
			ELContext elContext = facesContext.getELContext();
			if(data.expires != null){
			ValueExpression binding = (ValueExpression) UIComponentBase.restoreAttachedState(facesContext,data.expires);
			Date expires = (Date) binding.getValue(elContext);
			if (null != expires) {
				return expires.getTime()-System.currentTimeMillis();
			}
		}
		}
		return super.getExpired(resourceContext);
	}
	/* (non-Javadoc)
	 * @see org.ajax4jsf.resource.InternetResourceBase#requireFacesContext()
	 */
	public boolean requireFacesContext() {
		// TODO Auto-generated method stub
		return true;
	}
	
	public static class UriData implements Serializable {

		/**
		 * 
		 */
		private static final long serialVersionUID = 1258987L;
		
		private Object value;
		
		private Object createContent;
		
		private Object expires;
		
		private Object modified;
	}

}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -156,7 +156,7 @@
 		return true;
 	}
 	
-	public static class UriData implements Serializable {
+	public static class UriData implements SerializableResource {
 
 		/**
 		 * 
```
