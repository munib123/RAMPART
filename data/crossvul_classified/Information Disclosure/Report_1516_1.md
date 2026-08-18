# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in html
**Pair ID:** 1516_1
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** html
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1516_1`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```html
Lines 1-25 of the vulnerable file.

## mako
<%! from django.core.urlresolvers import reverse %>
<%! from django.utils.translation import ugettext as _ %>
<%namespace name='static' file='static_content.html'/>

## WARNING: These files are specific to edx.org and are not used in installations outside of that domain. Open edX users will want to use the file "footer.html" for any changes or overrides.
<div class="wrapper wrapper-footer edx-footer edx-footer-new">
  <footer id="footer-global" class="footer-global" role="contentinfo" aria-label="Footer">

    <div class="footer-about">
      <h2 class="sr footer-about-title">${_("About edX")}</h2>

      <div class="footer-about-logo">
        <img alt="edX logo" src="${static.url('images/edx-theme/edx-header-logo.png')}">
      </div>

      <div class="footer-about-copy">
        <p>
          ${_(
            "{EdX} offers interactive online classes and MOOCs from the world's best universities. "
            "Online courses from {MITx}, {HarvardX}, {BerkeleyX}, {UTx} and many other universities. "
            "Topics include biology, business, chemistry, computer science, economics, finance, "
            "electronics, engineering, food and nutrition, history, humanities, law, literature, "
            "math, medicine, music, philosophy, physics, science, statistics and more. {EdX} is a "
            "non-profit online initiative created by founding partners {Harvard} and {MIT}."
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2,7 +2,6 @@
 <%! from django.core.urlresolvers import reverse %>
 <%! from django.utils.translation import ugettext as _ %>
 <%namespace name='static' file='static_content.html'/>
-
 ## WARNING: These files are specific to edx.org and are not used in installations outside of that domain. Open edX users will want to use the file "footer.html" for any changes or overrides.
 <div class="wrapper wrapper-footer edx-footer edx-footer-new">
   <footer id="footer-global" class="footer-global" role="contentinfo" aria-label="Footer">
@@ -65,31 +64,31 @@
       <div class="footer-follow-links">
         ## Translators: This is the website name of www.twitter.com. Please
         ## translate this the way that Twitter advertises in your language.
-        <a href="${settings.PLATFORM_TWITTER_URL}" title="${_("Twitter")}">
+        <a href="${settings.PLATFORM_TWITTER_URL}" title="${_("Twitter")}" rel="noreferrer">
           <i class="icon fa fa-twitter element-invisible"></i>
           <span class="copy">${_("Twitter")}</span>
         </a>
         ## Translators: This is the website name of www.facebook.com. Please
         ## translate this the way that Facebook advertises in your language.
-        <a href="${settings.PLATFORM_FACEBOOK_ACCOUNT}" title="${_("Facebook")}">
+        <a href="${settings.PLATFORM_FACEBOOK_ACCOUNT}" title="${_("Facebook")}" rel="noreferrer">
           <i class="icon fa fa-facebook element-invisible"></i>
           <span class="copy">${_("Facebook")}</span>
         </a>
         ## Translators: This is the website name of www.meetup.com. Please
         ## translate this the way that Meetup advertises in your language.
-        <a href="${settings.PLATFORM_MEETUP_URL}" title="${_("Meetup")}">
+        <a href="${settings.PLATFORM_MEETUP_URL}" title="${_("Meetup")}" rel="noreferrer">
           <i class="icon fa fa-calendar element-invisible"></i>
           <span class="copy">${_("Meetup")}</span>
         </a>
         ## Translators: This is the website name of www.linked.com. Please
         ## translate this the way that LinkedIn advertises in your language.
-        <a href="${settings.PLATFORM_LINKEDIN_URL}" title="${_("LinkedIn")}">
+        <a href="${settings.PLATFORM_LINKEDIN_URL}" title="${_("LinkedIn")}" rel="noreferrer">
           <i class="icon fa fa-linkedin element-invisible"></i>
           <span class="copy">${_("LinkedIn")}</span>
         </a>
         ## Translators: This is the website name of plus.google.com. Please
         ## translate this the way that Google+ advertises in your language.
-        <a href="${settings.PLATFORM_GOOGLE_PLUS_URL}" title="${_("Google+")}">
+        <a href="${settings.PLATFORM_GOOGLE_PLUS_URL}" title="${_("Google+")}" rel="noreferrer">
           <i class="icon fa fa-google-plus element-invisible"></i>
           <span class="copy">${_("Google+")}</span>
         </a>
@@ -113,3 +112,6 @@
     </div>
   </footer>
 </div>
+
+<script type="text/javascript" src="/static/js/vendor/noreferrer.js" charset="utf-8"></script>
+
```
