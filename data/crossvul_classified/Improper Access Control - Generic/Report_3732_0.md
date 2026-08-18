# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in ruby
**Pair ID:** 3732_0
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3732_0`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```ruby
Lines 283-323 of the vulnerable file.

    # Save the now-signed cert.  This should get routed correctly depending
    # on the certificate type.
    cert.save

    # And remove the CSR if this wasn't self signed.
    Puppet::SSL::CertificateRequest.destroy(csr.name) unless self_signing_csr

    cert
  end

  def check_internal_signing_policies(hostname, csr, allow_dns_alt_names)
    # Reject unknown request extensions.
    unknown_req = csr.request_extensions.
      reject {|x| RequestExtensionWhitelist.include? x["oid"] }

    if unknown_req and not unknown_req.empty?
      names = unknown_req.map {|x| x["oid"] }.sort.uniq.join(", ")
      raise CertificateSigningError.new(hostname), "CSR has request extensions that are not permitted: #{names}"
    end

    # Wildcards: we don't allow 'em at any point.
    #
    # The stringification here makes the content visible, and saves us having
    # to scrobble through the content of the CSR subject field to make sure it
    # is what we expect where we expect it.
    if csr.content.subject.to_s.include? '*'
      raise CertificateSigningError.new(hostname), "CSR subject contains a wildcard, which is not allowed: #{csr.content.subject.to_s}"
    end

    unless csr.subject_alt_names.empty?
      # If you alt names are allowed, they are required. Otherwise they are
      # disallowed. Self-signed certs are implicitly trusted, however.
      unless allow_dns_alt_names
        raise CertificateSigningError.new(hostname), "CSR '#{csr.name}' contains subject alternative names (#{csr.subject_alt_names.join(', ')}), which are disallowed. Use `puppet cert --allow-dns-alt-names sign #{csr.name}` to sign this request."
      end

      # If subjectAltNames are present, validate that they are only for DNS
      # labels, not any other kind.
      unless csr.subject_alt_names.all? {|x| x =~ /^DNS:/ }
        raise CertificateSigningError.new(hostname), "CSR '#{csr.name}' contains a subjectAltName outside the DNS label space: #{csr.subject_alt_names.join(', ')}.  To continue, this CSR needs to be cleaned."
      end
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -300,6 +300,17 @@
       raise CertificateSigningError.new(hostname), "CSR has request extensions that are not permitted: #{names}"
     end
 
+    # Do not sign misleading CSRs
+    cn = csr.content.subject.to_a.assoc("CN")[1]
+    if hostname != cn
+      raise CertificateSigningError.new(hostname), "CSR subject common name #{cn.inspect} does not match expected certname #{hostname.inspect}"
+    end
+
+    # Only allow printing ascii characters, excluding /
+    if hostname !~ /\A[ -.0-~]+\Z/
+      raise CertificateSigningError.new(hostname), "CSR #{hostname.inspect} subject contains unprintable or non-ASCII characters"
+    end
+
     # Wildcards: we don't allow 'em at any point.
     #
     # The stringification here makes the content visible, and saves us having
```
