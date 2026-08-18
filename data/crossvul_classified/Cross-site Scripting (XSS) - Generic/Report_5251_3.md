# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in xml
**Pair ID:** 5251_3
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** xml
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5251_3`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```xml
Lines 66-106 of the vulnerable file.

					expected.
				</para>

				<para>
					This event is the first point in page execution where all registered plugins are
					guaranteed to be enabled (assuming dependencies and such are met).  At any point
					before this event, any or all plugins may not yet be loaded.  Note that the core
					system has not yet completed the bootstrap process when this event is signalled.
				</para>

				<para>
					Suggested uses for the event include:
					<itemizedlist>
						<listitem><para>Checking for plugins that aren't require for normal usage.</para></listitem>
						<listitem><para>Interacting with other plugins outside the context of pages or events.</para></listitem>
					</itemizedlist>
				</para>
			</blockquote>
		</blockquote>

		<blockquote id="dev.eventref.system.coreready">
			<title>EVENT_CORE_READY (Execute)</title>

			<blockquote>
				<para>
					This event is triggered by the MantisBT bootstrap process after all core APIs have
					been initialized, including the plugin system, but before control is relinquished
					from the bootstrap process back to the originating page.  No parameters are passed
					to hooked functions, and no return values are expected.
				</para>

				<para>
					This event is the first point in page execution where the entire system is considered
					loaded and ready.
				</para>
			</blockquote>
		</blockquote>

		<blockquote id="dev.eventref.system.log">
			<title>EVENT_LOG (Execute)</title>

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -83,6 +83,19 @@
 			</blockquote>
 		</blockquote>
 
+		<blockquote id="dev.eventref.system.coreheaders">
+			<title>EVENT_CORE_HEADERS (Execute)</title>
+
+			<blockquote>
+				<para>
+					This event is triggered by the MantisBT bootstrap process just before emitting the
+					headers.  This enables plugins to emit their own headers or use API that enables
+					tweaking values of headers emitted by core.  An example, of headers that can be
+					tweaked is Content-Security-Policy header which can be tweaked using http_csp_*() APIs.
+				</para>
+			</blockquote>
+		</blockquote>
+
 		<blockquote id="dev.eventref.system.coreready">
 			<title>EVENT_CORE_READY (Execute)</title>
 
```
