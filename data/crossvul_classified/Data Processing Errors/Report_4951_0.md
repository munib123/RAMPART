# CrossVul Fix Pair: Data Processing Errors in java
**Pair ID:** 4951_0
**Vulnerability Class:** Data Processing Errors
**CWE:** CWE-19
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4951_0`)

## Vulnerability Information & PoC

## Description
Data Processing Errors

## Vulnerable Code
```java
Lines 17-59 of the vulnerable file.

 * under the License.                                                        *
 *                                                                           *
 *                                                                           *
 * This file is part of the BeanShell Java Scripting distribution.           *
 * Documentation and updates may be found at http://www.beanshell.org/       *
 * Patrick Niemeyer (pat@pat.net)                                            *
 * Author of Learning Java, O'Reilly & Associates                            *
 *                                                                           *
 *****************************************************************************/



package bsh;

import java.lang.reflect.*;
import java.lang.reflect.InvocationHandler;
import java.io.*;
import java.util.Hashtable;

/**
	XThis is a dynamically loaded extension which extends This.java and adds 
	support for the generalized interface proxy mechanism introduced in 
	JDK1.3.  XThis allows bsh scripted objects to implement arbitrary 
	interfaces (be arbitrary event listener types).

	Note: This module relies on new features of JDK1.3 and will not compile
	with JDK1.2 or lower.  For those environments simply do not compile this
	class.

	Eventually XThis should become simply This, but for backward compatibility
	we will maintain This without requiring support for the proxy mechanism.

	XThis stands for "eXtended This" (I had to call it something).
	
	@see JThis	 See also JThis with explicit JFC support for compatibility.
	@see This	
*/
public class XThis extends This 
	{
	/**
		A cache of proxy interface handlers.
		Currently just one per interface.
	*/
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -34,9 +34,9 @@
 import java.util.Hashtable;
 
 /**
-	XThis is a dynamically loaded extension which extends This.java and adds 
-	support for the generalized interface proxy mechanism introduced in 
-	JDK1.3.  XThis allows bsh scripted objects to implement arbitrary 
+	XThis is a dynamically loaded extension which extends This.java and adds
+	support for the generalized interface proxy mechanism introduced in
+	JDK1.3.  XThis allows bsh scripted objects to implement arbitrary
 	interfaces (be arbitrary event listener types).
 
 	Note: This module relies on new features of JDK1.3 and will not compile
@@ -47,11 +47,11 @@
 	we will maintain This without requiring support for the proxy mechanism.
 
 	XThis stands for "eXtended This" (I had to call it something).
-	
+
 	@see JThis	 See also JThis with explicit JFC support for compatibility.
-	@see This	
+	@see This
 */
-public class XThis extends This 
+public class XThis extends This
 	{
 	/**
 		A cache of proxy interface handlers.
@@ -59,10 +59,10 @@
 	*/
 	Hashtable interfaces;
 
-	InvocationHandler invocationHandler = new Handler();
+	transient InvocationHandler invocationHandler = new Handler();
 
-	public XThis( NameSpace namespace, Interpreter declaringInterp ) { 
-		super( namespace, declaringInterp ); 
+	public XThis( NameSpace namespace, Interpreter declaringInterp ) {
+		super( namespace, declaringInterp );
 	}
 
 	public String toString() {
@@ -72,7 +72,7 @@
 	/**
 		Get dynamic proxy for interface, caching those it creates.
 	*/
-	public Object getInterface( Class clas ) 
+	public Object getInterface( Class clas )
 	{
 		return getInterface( new Class[] { clas } );
 	}
@@ -80,7 +80,7 @@
 	/**
 		Get dynamic proxy for interface, caching those it creates.
 	*/
-	public Object getInterface( Class [] ca ) 
+	public Object getInterface( Class [] ca )
 	{
 		if ( interfaces == null )
 			interfaces = new Hashtable();
@@ -93,10 +93,10 @@
 
 		Object interf = interfaces.get( hashKey );
 
-		if ( interf == null ) 
+		if ( interf == null )
 		{
 			ClassLoader classLoader = ca[0].getClassLoader(); // ?
-			interf = Proxy.newProxyInstance( 
+			interf = Proxy.newProxyInstance(
 				classLoader, ca, invocationHandler );
 			interfaces.put( hashKey, interf );
 		}
@@ -110,51 +110,51 @@
 
 		Notes:
 		Inner class for the invocation handler seems to shield this unavailable
-		interface from JDK1.2 VM...  
-		
+		interface from JDK1.2 VM...
+
 		I don't understand this.  JThis works just fine even if those
 		classes aren't there (doesn't it?)  This class shouldn't be loaded
 		if an XThis isn't instantiated in NameSpace.java, should it?
 	*/
-	class Handler implements InvocationHandler, java.io.Serializable 
+	class Handler implements InvocationHandler
 	{
-		public Object invoke( Object proxy, Method method, Object[] args ) 
+		public Object invoke( Object proxy, Method method, Object[] args )
 			throws Throwable
 		{
-			try { 
+			try {
 				return invokeImpl( proxy, method, args );
 			} catch ( TargetError te ) {
-				// Unwrap target exception.  If the interface declares that 
-				// it throws the ex it will be delivered.  If not it will be 
+				// Unwrap target exception.  If the interface declares that
+				// it throws the ex it will be delivered.  If not it will be
 				// wrapped in an UndeclaredThrowable
 				throw te.getTarget();
 			} catch ( EvalError ee ) {
 				// Ease debugging...
 				// XThis.this refers to the enclosing class instance
-				if ( Interpreter.DEBUG ) 
+				if ( Interpreter.DEBUG )
 					Interpreter.debug( "EvalError in scripted interface: "
 					+ XThis.this.toString() + ": "+ ee );
 				throw ee;
 			}
 		}
 
-		public Object invokeImpl( Object proxy, Method method, Object[] args ) 
-			throws EvalError 
+		public Object invokeImpl( Object proxy, Method method, Object[] args )
+			throws EvalError
 		{
 			String methodName = method.getName();
 			CallStack callstack = new CallStack( namespace );
 
 			/*
-				If equals() is not explicitly defined we must override the 
+				If equals() is not explicitly defined we must override the
 				default implemented by the This object protocol for scripted
-				object.  To support XThis equals() must test for equality with 
+				object.  To support XThis equals() must test for equality with
 				the generated proxy object, not the scripted bsh This object;
-				otherwise callers from outside in Java will not see a the 
+				otherwise callers from outside in Java will not see a the
 				proxy object as equal to itself.
 			*/
 			BshMethod equalsMethod = null;
 			try {
-				equalsMethod = namespace.getMethod( 
+				equalsMethod = namespace.getMethod(
 					"equals", new Class [] { Object.class } );
 			} catch ( UtilEvalError e ) {/*leave null*/ }
 			if ( methodName.equals("equals" ) && equalsMethod == null ) {
@@ -163,12 +163,12 @@
 			}
 
 			/*
-				If toString() is not explicitly defined override the default 
+				If toString() is not explicitly defined override the default
 				to show the proxy interfaces.
 			*/
 			BshMethod toStringMethod = null;
 			try {
-				toStringMethod = 
+				toStringMethod =
 					namespace.getMethod( "toString", new Class [] { } );
 			} catch ( UtilEvalError e ) {/*leave null*/ }
 
@@ -176,20 +176,17 @@
 			{
 				Class [] ints = proxy.getClass().getInterfaces();
 				// XThis.this refers to the enclosing class instance
-				StringBuffer sb = new StringBuffer( 
+				StringBuffer sb = new StringBuffer(
 					XThis.this.toString() + "\nimplements:" );
 				for(int i=0; i<ints.length; i++)
-					sb.append( " "+ ints[i].getName() 
+					sb.append( " "+ ints[i].getName()
 						+ ((ints.length > 1)?",":"") );
 				return sb.toString();
 			}
 
 			Class [] paramTypes = method.getParameterTypes();
-			return Primitive.unwrap( 
+			return Primitive.unwrap(
 				invokeMethod( methodName, Primitive.wrap(args, paramTypes) ) );
 		}
 	};
 }
-
-
-
```
