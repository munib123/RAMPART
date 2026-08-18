# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in xml
**Pair ID:** 3049_7
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** xml
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3049_7`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```xml
Lines 28-68 of the vulnerable file.

-->
<?jelly escape-by-default='true'?>
<j:jelly xmlns:j="jelly:core" xmlns:st="jelly:stapler" xmlns:d="jelly:define"
	xmlns:l="/lib/layout" xmlns:t="/lib/hudson" xmlns:f="/lib/form"
	xmlns:i="jelly:fmt" xmlns:p="/lib/hudson/project">
  <!--
    send back 4xx code so that machine agents don't confuse this form with successful build triggering
    405 is "Method Not Allowed" and this fits here because we need POST.
  -->
  <st:statusCode value="405" />
  <l:layout title="${it.displayName}" norefresh="true">
    <st:include page="sidepanel.jelly" it="${it.job}"/>
    <l:main-panel>
      <div class="behavior-loading">${%LOADING}</div>
      <h1>${it.job.pronoun} ${it.job.displayName}</h1>
      <p>${%description}</p>
      <j:set var="delay" value="${request.getParameter('delay')}" />
      <f:form method="post" action="build${empty(delay)?'':'?delay='+delay}" name="parameters"
              tableClass="parameters">
        <j:forEach var="parameterDefinition" items="${it.parameterDefinitions}">
          <tbody>
            <st:include it="${parameterDefinition}"
                        page="${parameterDefinition.descriptor.valuePage}" />
          </tbody>
        </j:forEach>
        <f:block>
          <!--
            When used from the UI, use 303 redirect and send back to the job top page.
            When neither of those options are given, we'll report "201 Created".

            We can't use XHR for submitting this as there might be file parameters,
            and submitting to IFRAME won't work either because 201 can't have HTML response.

            So I think all we can do is this somewhat clunky workaround.
           -->
          <input type="hidden" name="statusCode" value="303" />
          <input type="hidden" name="redirectTo" value="." />
          <f:submit value="${%Build}" />
        </f:block>
      </f:form>
    </l:main-panel>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -45,6 +45,7 @@
       <f:form method="post" action="build${empty(delay)?'':'?delay='+delay}" name="parameters"
               tableClass="parameters">
         <j:forEach var="parameterDefinition" items="${it.parameterDefinitions}">
+          <j:set var="escapeEntryTitleAndDescription" value="true"/> <!-- SECURITY-353 defense unless overridden -->
           <tbody>
             <st:include it="${parameterDefinition}"
                         page="${parameterDefinition.descriptor.valuePage}" />
```
