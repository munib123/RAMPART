# CrossVul Fix Pair: Cryptographic Issues in javascript
**Pair ID:** 1430_3
**Vulnerability Class:** Cryptographic Issues - Generic
**CWE:** CWE-310
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1430_3`)

## Vulnerability Information & PoC

## Description
Cryptographic Issues

## Vulnerable Code
```javascript
Lines 286-326 of the vulnerable file.

=/7PI
-----END PGP PRIVATE KEY BLOCK-----`;

const passphrase = 'hello world';
const plaintext = input.createSomeMessage();
const password1 = 'I am a password';
const password2 = 'I am another password';
const password3 = 'I am a third password';

const twoPasswordGPGFail = ['-----BEGIN PGP MESSAGE-----',
'Version: OpenPGP.js v3.0.0',
'Comment: https://openpgpjs.org',
'',
'wy4ECQMIWjj3WEfWxGpgrfb3vXu0TS9L8UNTBvNZFIjltGjMVkLFD+/afgs5',
'aXt0wy4ECQMIrFo3TFN5xqtgtB+AaAjBcWJrA4bvIPBpJ38PbMWeF0JQgrqg',
'j3uehxXy0mUB5i7B61g0ho+YplyFGM0s9XayJCnu40tWmr5LqqsRxuwrhJKR',
'migslOF/l6Y9F0F9xGIZWGhxp3ugQPjVKjj8fOH7ap14mLm60C8q8AOxiSmL',
'ubsd/hL7FPZatUYAAZVA0a6hmQ==',
'=cHCV',
'-----END PGP MESSAGE-----'].join('\n');

function withCompression(tests) {
  const compressionTypes = Object.keys(openpgp.enums.compression).map(k => openpgp.enums.compression[k]);

  compressionTypes.forEach(function (compression) {
    const compressionName = openpgp.enums.read(openpgp.enums.compression, compression);
    if (compressionName === 'bzip2') {
      return; // bzip2 compression is not supported.
    }
    const group = `compression - ${compressionName}`;

    describe(group, function() {
      let compressSpy;
      let decompressSpy;

      beforeEach(function () {
        compressSpy = spy(openpgp.packet.Compressed.prototype, 'compress');
        decompressSpy = spy(openpgp.packet.Compressed.prototype, 'decompress');
      });

      afterEach(function () {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -304,6 +304,37 @@
 '=cHCV',
 '-----END PGP MESSAGE-----'].join('\n');
 
+const ecdh_msg_bad = `-----BEGIN PGP MESSAGE-----
+Version: ProtonMail
+Comment: https://protonmail.com
+
+wV4DlF328rtCW+wSAQdA9FsAz4rCdoxY/oZaa68WMPMXbO+wtHs4ZXtAOJOs
+SlwwDaABXYC2dt0hUS2zRAL3gBGf4udH/CKJ1vPE58sNeh0ERYLxPHgwrpqI
+oNVWOWH50kUBIdqd7by8RwLOk9GyV6008iFOlOG90mfjvt2g5DsnSB4wEeMg
+pVu3fXj8iAKvFxvihwv1M7gNtP14StP6CngvyGVVEHQ=
+=mvcB
+-----END PGP MESSAGE-----`;
+
+const ecdh_dec_key = `-----BEGIN PGP PRIVATE KEY BLOCK-----
+Version: OpenPGP.js v4.4.6
+Comment: https://openpgpjs.org
+
+xYYEXEBTPxYJKwYBBAHaRw8BAQdAbXBY+2lpOatB+ZLokS/JIWqrVOseja9S
+ewQxMKN6ueT+CQMIuUXr0XofC6VgJvFLyLwDlyyvT4I1HWGKZ6W9HUaslKvS
+rw362rbMZKKfUtfjRJvpqiIU3Dr7iDkHB5vT7Tp5S7AZ2tNKoh/bwfTKdHsT
+1803InFhX3Rlc3RlcjJAcHJvdG9ubWFpbC5jb20iIDxxYV90ZXN0ZXIyQHBy
+b3Rvbm1haWwuY29tPsJ3BBAWCgAfBQJcQFM/BgsJBwgDAgQVCAoCAxYCAQIZ
+AQIbAwIeAQAKCRClzcrGJTMHyTpjAQCJZ7p0TJBZyPQ8m64N24glaM6oM78q
+2Ogpc0e9LcrPowD6AssY2YfUwJNzVFVzR+Lulzu6XVPjn0pXGMhOl03SrQ3H
+iwRcQFM/EgorBgEEAZdVAQUBAQdAAgJJUhKvjGWMq1sDhrJgvqbHK1t1W5RF
+Xoet5noIlAADAQgH/gkDCOFdJ7Yv2cTZYETRT5+ak/ntmslcAqtk3ebd7Ok3
+tQIjO3TYUbkV1eqrpA4I42kGCUkU4Dy26wxuaLRSsO1u/RgXjExZLP9FlWFI
+h6lLS1bCYQQYFggACQUCXEBTPwIbDAAKCRClzcrGJTMHyfNBAP9sdyU3GHNR
+7+QdwYvQp7wN+2VUd8vIf7iwAHOK1Cj4ywD+NhzjFfGYESJ68nnkrYlYdf+u
+OBqYz6mzZAWQZqsjbg4=
+=zrks
+-----END PGP PRIVATE KEY BLOCK-----`;
+
 function withCompression(tests) {
   const compressionTypes = Object.keys(openpgp.enums.compression).map(k => openpgp.enums.compression[k]);
 
@@ -2262,6 +2293,14 @@
         expect(decrypted.data).to.equal('Hello world');
       });
 
+      it('should decrypt broken ECC message from old OpenPGP.js', async function() {
+        const { keys: [key] } = await openpgp.key.readArmored(ecdh_dec_key);
+        const message = await openpgp.message.readArmored(ecdh_msg_bad);
+        await key.decrypt('12345');
+        const decrypted = await openpgp.decrypt({ message, privateKeys: [key] });
+        expect(decrypted.data).to.equal('\n');
+      });
+
     });
 
     describe('Errors', function() {
```
