# CrossVul Fix Pair: Allocation of Resources Without Limits or Throttling in xml
**Pair ID:** 3878_5
**Vulnerability Class:** Allocation of Resources Without Limits or Throttling
**CWE:** CWE-770
**Language:** xml
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3878_5`)

## Vulnerability Information & PoC

## Description
Allocation of Resources Without Limits or Throttling - Code frequently has to work with limited resources, so programmers must be careful to ensure that resources are not consumed too quickly, or too easily.

## Vulnerable Code
```xml
Lines 11-52 of the vulnerable file.

  ~ the License, or (at your option) any later version.
  ~
  ~ This software is distributed in the hope that it will be useful,
  ~ but WITHOUT ANY WARRANTY; without even the implied warranty of
  ~ MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  ~ Lesser General Public License for more details.
  ~
  ~ You should have received a copy of the GNU Lesser General Public
  ~ License along with this software; if not, write to the Free
  ~ Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
  ~ 02110-1301 USA, or see the FSF site: http://www.fsf.org.
  -->

<!--  See src/resources/configuration/ReadMe.txt for how the configuration assembly works -->
<config>
    <extension-module>org.wildfly.extension.undertow</extension-module>
    <subsystem xmlns="urn:jboss:domain:undertow:10.0" default-server="default-server" default-virtual-host="default-host" default-servlet-container="default" default-security-domain="other" statistics-enabled="${wildfly.undertow.statistics-enabled:${wildfly.statistics-enabled:false}}">
        <buffer-cache name="default"/>
        <server name="default-server">
            <?AJP?>
            <http-listener name="default" socket-binding="http" redirect-socket="https" enable-http2="true"/>
            <https-listener name="https" socket-binding="https" security-realm="ApplicationRealm" enable-http2="true"/>
            <host name="default-host" alias="localhost">
                <location name="/" handler="welcome-content"/>
                <http-invoker security-realm="ApplicationRealm"/>
            </host>
        </server>
        <servlet-container name="default">
            <jsp-config/>
            <websockets/>
        </servlet-container>
        <handlers>
            <file name="welcome-content" path="${jboss.home.dir}/welcome-content"/>
        </handlers>
    </subsystem>
    <supplement name="ha">
        <replacement placeholder="AJP">
            <ajp-listener name="ajp" socket-binding="ajp" />
        </replacement>
    </supplement>
    <socket-binding name="http" port="${jboss.http.port:8080}"/>
    <socket-binding name="https" port="${jboss.https.port:8443}"/>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -28,8 +28,8 @@
         <buffer-cache name="default"/>
         <server name="default-server">
             <?AJP?>
-            <http-listener name="default" socket-binding="http" redirect-socket="https" enable-http2="true"/>
-            <https-listener name="https" socket-binding="https" security-realm="ApplicationRealm" enable-http2="true"/>
+            <http-listener name="default" socket-binding="http" redirect-socket="https" enable-http2="true" read-timeout="30000"/>
+            <https-listener name="https" socket-binding="https" security-realm="ApplicationRealm" enable-http2="true" read-timeout="30000"/>
             <host name="default-host" alias="localhost">
                 <location name="/" handler="welcome-content"/>
                 <http-invoker security-realm="ApplicationRealm"/>
```
