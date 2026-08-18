# CrossVul Fix Pair: Data Processing Errors in java
**Pair ID:** 4952_0
**Vulnerability Class:** Data Processing Errors
**CWE:** CWE-19
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4952_0`)

## Vulnerability Information & PoC

## Description
Data Processing Errors

## Vulnerable Code
```java
Lines 101-141 of the vulnerable file.

			interfaces.put( hashKey, interf );
		}

		return interf;
	}

	/**
		This is the invocation handler for the dynamic proxy.
		<p>

		Notes:
		Inner class for the invocation handler seems to shield this unavailable
		interface from JDK1.2 VM...

		I don't understand this.  JThis works just fine even if those
		classes aren't there (doesn't it?)  This class shouldn't be loaded
		if an XThis isn't instantiated in NameSpace.java, should it?
	*/
	class Handler implements InvocationHandler
	{
		public Object invoke( Object proxy, Method method, Object[] args )
			throws Throwable
		{
			try {
				return invokeImpl( proxy, method, args );
			} catch ( TargetError te ) {
				// Unwrap target exception.  If the interface declares that
				// it throws the ex it will be delivered.  If not it will be
				// wrapped in an UndeclaredThrowable
				throw te.getTarget();
			} catch ( EvalError ee ) {
				// Ease debugging...
				// XThis.this refers to the enclosing class instance
				if ( Interpreter.DEBUG )
					Interpreter.debug( "EvalError in scripted interface: "
					+ XThis.this.toString() + ": "+ ee );
				throw ee;
			}
		}

		public Object invokeImpl( Object proxy, Method method, Object[] args )
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -118,6 +118,10 @@
 	*/
 	class Handler implements InvocationHandler
 	{
+		private Object readResolve() throws ObjectStreamException {
+			throw new NotSerializableException();
+		}
+
 		public Object invoke( Object proxy, Method method, Object[] args )
 			throws Throwable
 		{
```
