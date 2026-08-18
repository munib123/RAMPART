# CrossVul Fix Pair: Data Processing Errors in javascript
**Pair ID:** 5247_0
**Vulnerability Class:** Data Processing Errors
**CWE:** CWE-19
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5247_0`)

## Vulnerability Information & PoC

## Description
Data Processing Errors

## Vulnerable Code
```javascript
Lines 49-89 of the vulnerable file.

exports.convertNPNProtocols = function(protocols, out) {
  // If protocols is Array - translate it into buffer
  if (Array.isArray(protocols)) {
    out.NPNProtocols = convertProtocols(protocols);
  } else if (protocols instanceof Buffer) {
    // Copy new buffer not to be modified by user.
    out.NPNProtocols = Buffer.from(protocols);
  }
};

exports.convertALPNProtocols = function(protocols, out) {
  // If protocols is Array - translate it into buffer
  if (Array.isArray(protocols)) {
    out.ALPNProtocols = convertProtocols(protocols);
  } else if (protocols instanceof Buffer) {
    // Copy new buffer not to be modified by user.
    out.ALPNProtocols = Buffer.from(protocols);
  }
};

exports.checkServerIdentity = function checkServerIdentity(host, cert) {
  // Create regexp to much hostnames
  function regexpify(host, wildcards) {
    // Add trailing dot (make hostnames uniform)
    if (!host || !host.endsWith('.')) host += '.';

    // The same applies to hostname with more than one wildcard,
    // if hostname has wildcard when wildcards are not allowed,
    // or if there are less than two dots after wildcard (i.e. *.com or *d.com)
    //
    // also
    //
    // "The client SHOULD NOT attempt to match a presented identifier in
    // which the wildcard character comprises a label other than the
    // left-most label (e.g., do not match bar.*.example.net)."
    // RFC6125
    if (!wildcards && /\*/.test(host) || /[\.\*].*\*/.test(host) ||
        /\*/.test(host) && !/\*.*\..+\..+/.test(host)) {
      return /$./;
    }

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -66,134 +66,137 @@
   }
 };
 
+function unfqdn(host) {
+  return host.replace(/[.]$/, '');
+}
+
+function splitHost(host) {
+  // String#toLowerCase() is locale-sensitive so we use
+  // a conservative version that only lowercases A-Z.
+  const replacer = (c) => String.fromCharCode(32 + c.charCodeAt(0));
+  return unfqdn(host).replace(/[A-Z]/g, replacer).split('.');
+}
+
+function check(hostParts, pattern, wildcards) {
+  // Empty strings, null, undefined, etc. never match.
+  if (!pattern)
+    return false;
+
+  const patternParts = splitHost(pattern);
+
+  if (hostParts.length !== patternParts.length)
+    return false;
+
+  // Pattern has empty components, e.g. "bad..example.com".
+  if (patternParts.includes(''))
+    return false;
+
+  // RFC 6125 allows IDNA U-labels (Unicode) in names but we have no
+  // good way to detect their encoding or normalize them so we simply
+  // reject them.  Control characters and blanks are rejected as well
+  // because nothing good can come from accepting them.
+  const isBad = (s) => /[^\u0021-\u007F]/u.test(s);
+  if (patternParts.some(isBad))
+    return false;
+
+  // Check host parts from right to left first.
+  for (let i = hostParts.length - 1; i > 0; i -= 1)
+    if (hostParts[i] !== patternParts[i])
+      return false;
+
+  const hostSubdomain = hostParts[0];
+  const patternSubdomain = patternParts[0];
+  const patternSubdomainParts = patternSubdomain.split('*');
+
+  // Short-circuit when the subdomain does not contain a wildcard.
+  // RFC 6125 does not allow wildcard substitution for components
+  // containing IDNA A-labels (Punycode) so match those verbatim.
+  if (patternSubdomainParts.length === 1 || patternSubdomain.includes('xn--'))
+    return hostSubdomain === patternSubdomain;
+
+  if (!wildcards)
+    return false;
+
+  // More than one wildcard is always wrong.
+  if (patternSubdomainParts.length > 2)
+    return false;
+
+  // *.tld wildcards are not allowed.
+  if (patternParts.length <= 2)
+    return false;
+
+  const [prefix, suffix] = patternSubdomainParts;
+
+  if (prefix.length + suffix.length > hostSubdomain.length)
+    return false;
+
+  if (!hostSubdomain.startsWith(prefix))
+    return false;
+
+  if (!hostSubdomain.endsWith(suffix))
+    return false;
+
+  return true;
+}
+
 exports.checkServerIdentity = function checkServerIdentity(host, cert) {
-  // Create regexp to much hostnames
-  function regexpify(host, wildcards) {
-    // Add trailing dot (make hostnames uniform)
-    if (!host || !host.endsWith('.')) host += '.';
-
-    // The same applies to hostname with more than one wildcard,
-    // if hostname has wildcard when wildcards are not allowed,
-    // or if there are less than two dots after wildcard (i.e. *.com or *d.com)
-    //
-    // also
-    //
-    // "The client SHOULD NOT attempt to match a presented identifier in
-    // which the wildcard character comprises a label other than the
-    // left-most label (e.g., do not match bar.*.example.net)."
-    // RFC6125
-    if (!wildcards && /\*/.test(host) || /[\.\*].*\*/.test(host) ||
-        /\*/.test(host) && !/\*.*\..+\..+/.test(host)) {
-      return /$./;
-    }
-
-    // Replace wildcard chars with regexp's wildcard and
-    // escape all characters that have special meaning in regexps
-    // (i.e. '.', '[', '{', '*', and others)
-    var re = host.replace(
-        /\*([a-z0-9\\-_\.])|[\.,\-\\\^\$+?*\[\]\(\):!\|{}]/g,
-        function(all, sub) {
-          if (sub) return '[a-z0-9\\-_]*' + (sub === '-' ? '\\-' : sub);
-          return '\\' + all;
-        });
-
-    return new RegExp('^' + re + '$', 'i');
-  }
-
-  var dnsNames = [];
-  var uriNames = [];
+  const subject = cert.subject;
+  const altNames = cert.subjectaltname;
+  const dnsNames = [];
+  const uriNames = [];
   const ips = [];
-  var matchCN = true;
-  var valid = false;
-  var reason = 'Unknown reason';
-
-  // There're several names to perform check against:
-  // CN and altnames in certificate extension
-  // (DNS names, IP addresses, and URIs)
-  //
-  // Walk through altnames and generate lists of those names
-  if (cert.subjectaltname) {
-    cert.subjectaltname.split(/, /g).forEach(function(altname) {
-      var option = altname.match(/^(DNS|IP Address|URI):(.*)$/);
-      if (!option)
-        return;
-      if (option[1] === 'DNS') {
-        dnsNames.push(option[2]);
-      } else if (option[1] === 'IP Address') {
-        ips.push(option[2]);
-      } else if (option[1] === 'URI') {
-        var uri = url.parse(option[2]);
-        if (uri) uriNames.push(uri.hostname);
-      }
-    });
-  }
-
-  // If hostname is an IP address, it should be present in the list of IP
-  // addresses.
-  if (net.isIP(host)) {
-    valid = ips.some(function(ip) {
-      return ip === host;
-    });
-    if (!valid) {
-      reason = `IP: ${host} is not in the cert's list: ${ips.join(', ')}`;
-    }
-  } else if (cert.subject) {
-    // Transform hostname to canonical form
-    if (!host || !host.endsWith('.')) host += '.';
-
-    // Otherwise check all DNS/URI records from certificate
-    // (with allowed wildcards)
-    dnsNames = dnsNames.map(function(name) {
-      return regexpify(name, true);
-    });
-
-    // Wildcards ain't allowed in URI names
-    uriNames = uriNames.map(function(name) {
-      return regexpify(name, false);
-    });
-
-    dnsNames = dnsNames.concat(uriNames);
-
-    if (dnsNames.length > 0) matchCN = false;
-
-    // Match against Common Name (CN) only if no supported identifiers are
-    // present.
-    //
-    // "As noted, a client MUST NOT seek a match for a reference identifier
-    //  of CN-ID if the presented identifiers include a DNS-ID, SRV-ID,
-    //  URI-ID, or any application-specific identifier types supported by the
-    //  client."
-    // RFC6125
-    if (matchCN) {
-      var commonNames = cert.subject.CN;
-      if (Array.isArray(commonNames)) {
-        for (var i = 0, k = commonNames.length; i < k; ++i) {
-          dnsNames.push(regexpify(commonNames[i], true));
-        }
-      } else {
-        dnsNames.push(regexpify(commonNames, true));
+
+  host = '' + host;
+
+  if (altNames) {
+    for (const name of altNames.split(', ')) {
+      if (name.startsWith('DNS:')) {
+        dnsNames.push(name.slice(4));
+      } else if (name.startsWith('URI:')) {
+        const uri = url.parse(name.slice(4));
+        uriNames.push(uri.hostname);  // TODO(bnoordhuis) Also use scheme.
+      } else if (name.startsWith('IP Address:')) {
+        ips.push(name.slice(11));
       }
     }
-
-    valid = dnsNames.some(function(re) {
-      return re.test(host);
-    });
-
-    if (!valid) {
-      if (cert.subjectaltname) {
-        reason =
-            `Host: ${host} is not in the cert's altnames: ` +
-            `${cert.subjectaltname}`;
-      } else {
-        reason = `Host: ${host} is not cert's CN: ${cert.subject.CN}`;
-      }
+  }
+
+  let valid = false;
+  let reason = 'Unknown reason';
+
+  if (net.isIP(host)) {
+    valid = ips.includes(host);
+    if (!valid)
+      reason = `IP: ${host} is not in the cert's list: ${ips.join(', ')}`;
+    // TODO(bnoordhuis) Also check URI SANs that are IP addresses.
+  } else if (subject) {
+    host = unfqdn(host);  // Remove trailing dot for error messages.
+    const hostParts = splitHost(host);
+    const wildcard = (pattern) => check(hostParts, pattern, true);
+    const noWildcard = (pattern) => check(hostParts, pattern, false);
+
+    // Match against Common Name only if no supported identifiers are present.
+    if (dnsNames.length === 0 && ips.length === 0 && uriNames.length === 0) {
+      const cn = subject.CN;
+
+      if (Array.isArray(cn))
+        valid = cn.some(wildcard);
+      else if (cn)
+        valid = wildcard(cn);
+
+      if (!valid)
+        reason = `Host: ${host}. is not cert's CN: ${cn}`;
+    } else {
+      valid = dnsNames.some(wildcard) || uriNames.some(noWildcard);
+      if (!valid)
... (diff truncated)
```
