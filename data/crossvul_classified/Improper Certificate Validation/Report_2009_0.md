# CrossVul Fix Pair: Improper Certificate Validation in javascript
**Pair ID:** 2009_0
**Vulnerability Class:** Improper Certificate Validation
**CWE:** CWE-295
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2009_0`)

## Vulnerability Information & PoC

## Description
Improper Certificate Validation - When a certificate is invalid or malicious, it might allow an attacker to spoof a trusted entity by interfering in the communication path between the host and client.

## Vulnerable Code
```javascript
Lines 2-42 of the vulnerable file.

import util from 'util';
import Bunyan from 'bunyan';
import {log_debug, log_info, log_warn, log_error} from './logger';


export default class LDAP {
  constructor() {
    this.ldapjs = ldapjs;

    this.connected = false;

    this.options = {
      host                               : this.constructor.settings_get('LDAP_HOST'),
      port                               : this.constructor.settings_get('LDAP_PORT'),
      Reconnect                          : this.constructor.settings_get('LDAP_RECONNECT'),
      timeout                            : this.constructor.settings_get('LDAP_TIMEOUT'),
      connect_timeout                    : this.constructor.settings_get('LDAP_CONNECT_TIMEOUT'),
      idle_timeout                       : this.constructor.settings_get('LDAP_IDLE_TIMEOUT'),
      encryption                         : this.constructor.settings_get('LDAP_ENCRYPTION'),
      ca_cert                            : this.constructor.settings_get('LDAP_CA_CERT'),
      reject_unauthorized                : this.constructor.settings_get('LDAP_REJECT_UNAUTHORIZED') || false,
      Authentication                     : this.constructor.settings_get('LDAP_AUTHENTIFICATION'),
      Authentication_UserDN              : this.constructor.settings_get('LDAP_AUTHENTIFICATION_USERDN'),
      Authentication_Password            : this.constructor.settings_get('LDAP_AUTHENTIFICATION_PASSWORD'),
      Authentication_Fallback            : this.constructor.settings_get('LDAP_LOGIN_FALLBACK'),
      BaseDN                             : this.constructor.settings_get('LDAP_BASEDN'),
      Internal_Log_Level                 : this.constructor.settings_get('INTERNAL_LOG_LEVEL'),
      User_Authentication                : this.constructor.settings_get('LDAP_USER_AUTHENTICATION'),
      User_Authentication_Field          : this.constructor.settings_get('LDAP_USER_AUTHENTICATION_FIELD'),
      User_Attributes                    : this.constructor.settings_get('LDAP_USER_ATTRIBUTES'),
      User_Search_Filter                 : this.constructor.settings_get('LDAP_USER_SEARCH_FILTER'),
      User_Search_Scope                  : this.constructor.settings_get('LDAP_USER_SEARCH_SCOPE'),
      User_Search_Field                  : this.constructor.settings_get('LDAP_USER_SEARCH_FIELD'),
      Search_Page_Size                   : this.constructor.settings_get('LDAP_SEARCH_PAGE_SIZE'),
      Search_Size_Limit                  : this.constructor.settings_get('LDAP_SEARCH_SIZE_LIMIT'),
      group_filter_enabled               : this.constructor.settings_get('LDAP_GROUP_FILTER_ENABLE'),
      group_filter_object_class          : this.constructor.settings_get('LDAP_GROUP_FILTER_OBJECTCLASS'),
      group_filter_group_id_attribute    : this.constructor.settings_get('LDAP_GROUP_FILTER_GROUP_ID_ATTRIBUTE'),
      group_filter_group_member_attribute: this.constructor.settings_get('LDAP_GROUP_FILTER_GROUP_MEMBER_ATTRIBUTE'),
      group_filter_group_member_format   : this.constructor.settings_get('LDAP_GROUP_FILTER_GROUP_MEMBER_FORMAT'),
      group_filter_group_name            : this.constructor.settings_get('LDAP_GROUP_FILTER_GROUP_NAME'),
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -19,7 +19,7 @@
       idle_timeout                       : this.constructor.settings_get('LDAP_IDLE_TIMEOUT'),
       encryption                         : this.constructor.settings_get('LDAP_ENCRYPTION'),
       ca_cert                            : this.constructor.settings_get('LDAP_CA_CERT'),
-      reject_unauthorized                : this.constructor.settings_get('LDAP_REJECT_UNAUTHORIZED') || false,
+      reject_unauthorized                : this.constructor.settings_get('LDAP_REJECT_UNAUTHORIZED') || true,
       Authentication                     : this.constructor.settings_get('LDAP_AUTHENTIFICATION'),
       Authentication_UserDN              : this.constructor.settings_get('LDAP_AUTHENTIFICATION_USERDN'),
       Authentication_Password            : this.constructor.settings_get('LDAP_AUTHENTIFICATION_PASSWORD'),
```
