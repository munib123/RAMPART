# CrossVul Fix Pair: Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') in xml
**Pair ID:** 1907_1
**Vulnerability Class:** Code Injection
**CWE:** CWE-74
**Language:** xml
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1907_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') - Software or other automated logic has certain assumptions about what constitutes data and control respectively.

## Vulnerable Code
```xml
Lines 270-310 of the vulnerable file.

            <varlistentry>
                <term><option>--remove-policy=SUBSYSTEM.KEY=VALUE</option></term>

                <listitem><para>
                    Remove generic policy option. This option can be used multiple times.
                </para></listitem>
            </varlistentry>

            <varlistentry>
                <term><option>--env=VAR=VALUE</option></term>

                <listitem><para>
                    Set an environment variable in the application.
                    This updates the [Environment] group in the metadata.
                    This overrides to the Context section from the application metadata.
                    This option can be used multiple times.
                </para></listitem>
            </varlistentry>

            <varlistentry>
                <term><option>--own-name=NAME</option></term>

                <listitem><para>
                    Allow the application to own the well known name <arg choice="plain">NAME</arg> on the session bus.
                    If <arg choice="plain">NAME</arg> ends with .*, it allows the application to own all matching names.

                    This updates the [Session Bus Policy] group in the metadata.
                    This option can be used multiple times.
                </para></listitem>
            </varlistentry>

            <varlistentry>
                <term><option>--talk-name=NAME</option></term>

                <listitem><para>
                    Allow the application to talk to the well known name <arg choice="plain">NAME</arg> on the session bus.
                    If <arg choice="plain">NAME</arg> ends with .*, it allows the application to talk to all matching names.
                    This updates the [Session Bus Policy] group in the metadata.
                    This option can be used multiple times.
                </para></listitem>
            </varlistentry>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -287,6 +287,24 @@
             </varlistentry>
 
             <varlistentry>
+                <term><option>--env-fd=<replaceable>FD</replaceable></option></term>
+
+                <listitem><para>
+                    Read environment variables from the file descriptor
+                    <replaceable>FD</replaceable>, and set them as if
+                    via <option>--env</option>. This can be used to avoid
+                    environment variables and their values becoming visible
+                    to other users.
+                </para><para>
+                    Each environment variable is in the form
+                    <replaceable>VAR</replaceable>=<replaceable>VALUE</replaceable>
+                    followed by a zero byte. This is the same format used by
+                    <literal>env -0</literal> and
+                    <filename>/proc/*/environ</filename>.
+                </para></listitem>
+            </varlistentry>
+
+            <varlistentry>
                 <term><option>--own-name=NAME</option></term>
 
                 <listitem><para>
```
