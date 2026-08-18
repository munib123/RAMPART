# CrossVul Fix Pair: Cryptographic Issues in html
**Pair ID:** 546_2
**Vulnerability Class:** Cryptographic Issues - Generic
**CWE:** CWE-310
**Language:** html
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `546_2`)

## Vulnerability Information & PoC

## Description
Cryptographic Issues

## Vulnerable Code
```html
Lines 697-737 of the vulnerable file.

      <div style="position: absolute; left: 0; bottom: 0;">
        <button onclick='javascript:_fpa.next("profile-add-security");'
                class="button-info" id="fpa-gotit" type="button">{{_("Got it")}} ...</button>
      </div>
    </div>

    <p class="message paragraph-important"
       onclick='javascript:_fpa.next("profile-add-security");'>
      <span class="icon-lock-closed"></span> {{_("Security and Privacy")}}
      <span class="icon-checkmark right hide" style="padding: 5px; color: #5f5;"></span>
    </p>
    <div class="section profile-add-security  {% if ui_open != 'security' %}hide{% endif %}"
         style="position: relative;">
      <div class="left" style="margin-right: 0; width: 100%;">
        <label>{{_("Encryption key")}}</label>
        <select class='fpa-pgp-key' style="width: 100%"
                onchange="javascript:_fpa.select(this, 'security-opt');"
                name="security-pgp-key">
          <option value="!CREATE:RSA2048">{{_("Create a new 2048 bit RSA key")}}</option>
          <option value="!CREATE:RSA3072" class="fpa-pgp-key-default">{{_("Create a new 3072 bit RSA key")}}</option>
        {%- set pgp_keys = mailpile('crypto/gpg/keylist/secret').result %}
        {%- for fingerprint in pgp_keys -%}
          {%- set key = pgp_keys[fingerprint] -%}
          {%- for uid in key.uids %}
          <option value="{{fingerprint}}" data-uid="{{ uid.email }}"
                  {%- if (fingerprint == result['security-pgp-key']) and (uid.email == result.email) %} selected{% endif %}
                  {%- if (uid.email != result.email) %} class="hide"{% endif %}>
            {{key.creation_date}}/{{key.keytype_name}}{{key.keysize}}:
            {{uid.name}} &lt;{{uid.email}}&gt;
            ({% if uid.comment %}{{uid.comment}}{% else %}0x{{ fingerprint[-8:] }}{% endif %})
          </option>
          {%- endfor %}
        {%- endfor %}
          <option value="!CREATE:RSA4096">{{_("Create a new 4096 bit RSA key (slow)")}}</option>
          <option {% if not result['security-pgp-key'] %}selected {% endif -%}
                  value="">{{_("Disable encryption for this account")}}</option>
        </select>
        <div class="security-opt any text-right
             {%- if not result['security-pgp-key'] %} hide{% endif %}"
             style="margin: -13px 0 13px 0;">
          <a class="more-crypto-show" onclick="javascript:_fpa.more('more-crypto');">
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -714,7 +714,7 @@
                 name="security-pgp-key">
           <option value="!CREATE:RSA2048">{{_("Create a new 2048 bit RSA key")}}</option>
           <option value="!CREATE:RSA3072" class="fpa-pgp-key-default">{{_("Create a new 3072 bit RSA key")}}</option>
-        {%- set pgp_keys = mailpile('crypto/gpg/keylist/secret').result %}
+        {%- set pgp_keys = mailpile('crypto/gpg/keylist/secret','True').result %}
         {%- for fingerprint in pgp_keys -%}
           {%- set key = pgp_keys[fingerprint] -%}
           {%- for uid in key.uids %}
```
