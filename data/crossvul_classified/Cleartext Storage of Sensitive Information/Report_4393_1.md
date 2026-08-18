# CrossVul Fix Pair: Cleartext Storage of Sensitive Information in javascript
**Pair ID:** 4393_1
**Vulnerability Class:** Cleartext Storage of Sensitive Information
**CWE:** CWE-312
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4393_1`)

## Vulnerability Information & PoC

## Description
Cleartext Storage of Sensitive Information - Because the information is stored in cleartext (i.

## Vulnerable Code
```javascript
Lines 6-46 of the vulnerable file.

    return new Promise((_, reject) => {
      reject(
        new Parse.Error(
          Parse.Error.INTERNAL_SERVER_ERROR,
          'LDAP auth configuration missing'
        )
      );
    });
  }
  const clientOptions = (options.url.startsWith("ldaps://")) ?
    { url: options.url, tlsOptions: options.tlsOptions } : { url: options.url };

  const client = ldapjs.createClient(clientOptions);
  const userCn =
    typeof options.dn === 'string'
      ? options.dn.replace('{{id}}', authData.id)
      : `uid=${authData.id},${options.suffix}`;

  return new Promise((resolve, reject) => {
    client.bind(userCn, authData.password, ldapError => {
      if (ldapError) {
        let error;
        switch (ldapError.code) {
          case 49:
            error = new Parse.Error(Parse.Error.OBJECT_NOT_FOUND, 'LDAP: Wrong username or password');
            break;
          case "DEPTH_ZERO_SELF_SIGNED_CERT":
            error = new Parse.Error(Parse.Error.OBJECT_NOT_FOUND, 'LDAPS: Certificate mismatch');
            break;
          default:
            error = new Parse.Error(Parse.Error.OBJECT_NOT_FOUND, 'LDAP: Somthing went wrong (' + ldapError.code + ')');
        }
        reject(error);
        client.destroy(ldapError);
        return;
      }

      if (
        typeof options.groupCn === 'string' &&
        typeof options.groupFilter === 'string'
      ) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -23,6 +23,7 @@
 
   return new Promise((resolve, reject) => {
     client.bind(userCn, authData.password, ldapError => {
+      delete(authData.password);
       if (ldapError) {
         let error;
         switch (ldapError.code) {
```
