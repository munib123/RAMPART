# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in yaml
**Pair ID:** 1051_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** yaml
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1051_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```yaml
Lines 466-506 of the vulnerable file.

  node_style      : filled
  #edge_style      : setlinewidth(10)

  # ---- Node Maps ----
  # variable:matching pattern:node attribute:attribute value:key:key name
  #node_map:
  #  - 'label:cat(?!-g):fillcolor:blue:cat:Blue Box - Catalyst Device'
  #  - 'label:-g:fillcolor:darkgreen:dev-g:Green Box - Gateway / Router'
  #  - 'ip:^192.168\.:color:yellow:dev:Yellow Border - ResNet'

# ---------------
# DANCER INTERNAL
# ---------------

charset: 'UTF-8'
warnings: false
show_errors: false
logger: 'console'
engines:
  netdisco_template_toolkit:
    encoding: 'utf8'
    start_tag: '[%'
    end_tag: '%]'
    PRE_CHOMP: 1
    INCLUDE_PATH: []
layout: 'main'
plugins:
  Swagger:
     main_api_module: 'App::Netdisco'
     ui_url: '/swagger-ui'
  Auth::Extensible:
    no_api_change_warning: true
    no_default_pages: true
    no_login_handler: true
    realms:
      users:
        provider: 'App::Netdisco::Web::Auth::Provider::DBIC'
        schema_name: 'netdisco'
session: 'cookie'
session_cookie_key: 'this_will_be_overridden_on_webapp_startup'
template: 'netdisco_template_toolkit'
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -483,11 +483,15 @@
 logger: 'console'
 engines:
   netdisco_template_toolkit:
+    subclass: 'Template::AutoFilter'
     encoding: 'utf8'
     start_tag: '[%'
     end_tag: '%]'
+    ANYCASE: 1
+    ABSOLUTE: 1
     PRE_CHOMP: 1
     INCLUDE_PATH: []
+    AUTO_FILTER: 'html_entity'
 layout: 'main'
 plugins:
   Swagger:
```
