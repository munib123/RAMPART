# CrossVul Fix Pair: Use of a Broken or Risky Cryptographic Algorithm in xml
**Pair ID:** 4415_0
**Vulnerability Class:** Use of a Broken or Risky Cryptographic Algorithm
**CWE:** CWE-327
**Language:** xml
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4415_0`)

## Vulnerability Information & PoC

## Description
Use of a Broken or Risky Cryptographic Algorithm - Cryptographic algorithms are the methods by which data is scrambled to prevent observation or influence by unauthorized actors.

## Vulnerable Code
```xml
Lines 8-48 of the vulnerable file.

This program is free software; you can redistribute it and/or modify it under the
terms of the GNU Lesser General Public License as published by the Free Software
Foundation; either version 3.0 of the License, or (at your option) any later
version.

BigBlueButton is distributed in the hope that it will be useful, but WITHOUT ANY
WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
PARTICULAR PURPOSE. See the GNU Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public License along
with BigBlueButton; if not, see <http://www.gnu.org/licenses/>.

-->
<beans xmlns="http://www.springframework.org/schema/beans"
    xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
    xsi:schemaLocation="http://www.springframework.org/schema/beans
            http://www.springframework.org/schema/beans/spring-beans-2.5.xsd
            ">

    <bean id="stun1" class="org.bigbluebutton.web.services.turn.StunServer">
        <constructor-arg index="0" value="stun:stun.freeswitch.org"/>
    </bean>

    <!--bean id="stun2" class="org.bigbluebutton.web.services.turn.StunServer">
        <constructor-arg index="0" value="stun:stun2.example.com"/>
    </bean-->

    <!--bean id="iceCandidate1" class="org.bigbluebutton.web.services.turn.RemoteIceCandidate">
        <constructor-arg index="0" value="192.168.0.1"/>
    </bean-->

    <!-- Turn servers are configured with a secret that's compatible with
         http://tools.ietf.org/html/draft-uberti-behave-turn-rest-00
         as supported by the coturn and rfc5766-turn-server turn servers -->

    <!--bean id="turn1" class="org.bigbluebutton.web.services.turn.TurnServer">
        Secret:
        <constructor-arg index="0" value="secret"/>
        TURN server URL, use turn: or turns:
        <constructor-arg index="1" value="turn:turn1.example.com"/>
        TTL in seconds for shared secret
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -25,7 +25,7 @@
             ">
 
     <bean id="stun1" class="org.bigbluebutton.web.services.turn.StunServer">
-        <constructor-arg index="0" value="stun:stun.freeswitch.org"/>
+        <constructor-arg index="0" value="stun:stun.l.google.com:19302"/>
     </bean>
 
     <!--bean id="stun2" class="org.bigbluebutton.web.services.turn.StunServer">
```
