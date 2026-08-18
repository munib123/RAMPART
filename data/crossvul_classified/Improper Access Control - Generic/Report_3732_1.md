# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in ruby
**Pair ID:** 3732_1
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3732_1`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```ruby
Lines 229-269 of the vulnerable file.

      Puppet::SSL::CertificateAuthority.any_instance.stubs(:password?).returns true

      stub_ca_host

      Puppet::SSL::Host.expects(:new).with(Puppet::SSL::Host.ca_name).returns @host

      @ca = Puppet::SSL::CertificateAuthority.new

      @name = "myhost"
      @real_cert = stub 'realcert', :sign => nil
      @cert = stub 'certificate', :content => @real_cert

      Puppet::SSL::Certificate.stubs(:new).returns @cert

      @cert.stubs(:content=)
      @cert.stubs(:save)

      # Stub out the factory
      Puppet::SSL::CertificateFactory.stubs(:build).returns "my real cert"

      @request_content = stub "request content stub", :subject => @name
      @request = stub 'request', :name => @name, :request_extensions => [], :subject_alt_names => [], :content => @request_content

      # And the inventory
      @inventory = stub 'inventory', :add => nil
      @ca.stubs(:inventory).returns @inventory

      Puppet::SSL::CertificateRequest.stubs(:destroy)
    end

    describe "and calculating the next certificate serial number" do
      before do
        @path = "/path/to/serial"
        Puppet.settings.stubs(:value).with(:serial).returns @path

        @filehandle = stub 'filehandle', :<< => @filehandle
        Puppet.settings.stubs(:readwritelock).with(:serial).yields @filehandle
      end

      it "should default to 0x1 for the first serial number" do
        @ca.next_serial.should == 0x1
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -246,7 +246,7 @@
       # Stub out the factory
       Puppet::SSL::CertificateFactory.stubs(:build).returns "my real cert"
 
-      @request_content = stub "request content stub", :subject => @name
+      @request_content = stub "request content stub", :subject => OpenSSL::X509::Name.new([['CN', @name]])
       @request = stub 'request', :name => @name, :request_extensions => [], :subject_alt_names => [], :content => @request_content
 
       # And the inventory
@@ -303,28 +303,28 @@
 
       it "should use a certificate type of :ca" do
         Puppet::SSL::CertificateFactory.expects(:build).with do |*args|
-          args[0] == :ca
+          args[0].should == :ca
         end.returns "my real cert"
         @ca.sign(@name, :ca, @request)
       end
 
       it "should pass the provided CSR as the CSR" do
         Puppet::SSL::CertificateFactory.expects(:build).with do |*args|
-          args[1] == @request
+          args[1].should == @request
         end.returns "my real cert"
         @ca.sign(@name, :ca, @request)
       end
 
       it "should use the provided CSR's content as the issuer" do
         Puppet::SSL::CertificateFactory.expects(:build).with do |*args|
-          args[2].subject == "myhost"
+          args[2].subject.to_s.should == "/CN=myhost"
         end.returns "my real cert"
         @ca.sign(@name, :ca, @request)
       end
 
       it "should pass the next serial as the serial number" do
         Puppet::SSL::CertificateFactory.expects(:build).with do |*args|
-          args[3] == @serial
+          args[3].should == @serial
         end.returns "my real cert"
         @ca.sign(@name, :ca, @request)
       end
@@ -452,11 +452,76 @@
         @cert.stubs :save
       end
 
+      it "should reject CSRs whose CN doesn't match the name for which we're signing them" do
+        # Shorten this so the test doesn't take too long
+        Puppet[:keylength] = 1024
+        key = Puppet::SSL::Key.new('the_certname')
+        key.generate
+
+        csr = Puppet::SSL::CertificateRequest.new('the_certname')
+        csr.generate(key)
+
+        expect do
+          @ca.check_internal_signing_policies('not_the_certname', csr, false)
+        end.to raise_error(
+          Puppet::SSL::CertificateAuthority::CertificateSigningError,
+          /common name "the_certname" does not match expected certname "not_the_certname"/
+        )
+      end
+
+      describe "when validating the CN" do
+        before :all do
+          Puppet[:keylength] = 1024
+          @signing_key = Puppet::SSL::Key.new('my_signing_key')
+          @signing_key.generate
+        end
+
+        [
+         'completely_okay',
+         'sure, why not? :)',
+         'so+many(things)-are=allowed.',
+         'this"is#just&madness%you[see]',
+         'and even a (an?) \\!',
+         'waltz, nymph, for quick jigs vex bud.',
+         '{552c04ca-bb1b-11e1-874b-60334b04494e}'
+        ].each do |name|
+          it "should accept #{name.inspect}" do
+            csr = Puppet::SSL::CertificateRequest.new(name)
+            csr.generate(@signing_key)
+
+            @ca.check_internal_signing_policies(name, csr, false)
+          end
+        end
+
+        [
+         'super/bad',
+         "not\neven\tkind\rof",
+         "ding\adong\a",
+         "hidden\b\b\b\b\b\bmessage",
+         "☃ :("
+        ].each do |name|
+          it "should reject #{name.inspect}" do
+            # We aren't even allowed to make objects with these names, so let's
+            # stub that to simulate an invalid one coming from outside Puppet
+            Puppet::SSL::CertificateRequest.stubs(:validate_certname)
+            csr = Puppet::SSL::CertificateRequest.new(name)
+            csr.generate(@signing_key)
+
+            expect do
+              @ca.check_internal_signing_policies(name, csr, false)
+            end.to raise_error(
+              Puppet::SSL::CertificateAuthority::CertificateSigningError,
+              /subject contains unprintable or non-ASCII characters/
+            )
+          end
+        end
+      end
+
       it "should reject a critical extension that isn't on the whitelist" do
         @request.stubs(:request_extensions).returns [{ "oid" => "banana",
                                                        "value" => "yumm",
                                                        "critical" => true }]
-        expect { @ca.sign(@name) }.to raise_error(
+        expect { @ca.check_internal_signing_policies(@name, @request, false) }.to raise_error(
           Puppet::SSL::CertificateAuthority::CertificateSigningError,
           /request extensions that are not permitted/
         )
@@ -466,7 +531,7 @@
         @request.stubs(:request_extensions).returns [{ "oid" => "peach",
                                                        "value" => "meh",
                                                        "critical" => false }]
-        expect { @ca.sign(@name) }.to raise_error(
+        expect { @ca.check_internal_signing_policies(@name, @request, false) }.to raise_error(
           Puppet::SSL::CertificateAuthority::CertificateSigningError,
           /request extensions that are not permitted/
         )
@@ -479,7 +544,7 @@
                                                      { "oid" => "subjectAltName",
                                                        "value" => "DNS:foo",
                                                        "critical" => true }]
-        expect { @ca.sign(@name) }.to raise_error(
+        expect { @ca.check_internal_signing_policies(@name, @request, false) }.to raise_error(
           Puppet::SSL::CertificateAuthority::CertificateSigningError,
           /request extensions that are not permitted/
         )
@@ -487,7 +552,7 @@
 
       it "should reject a subjectAltName for a non-DNS value" do
         @request.stubs(:subject_alt_names).returns ['DNS:foo', 'email:bar@example.com']
-        expect { @ca.sign(@name, true) }.to raise_error(
+        expect { @ca.check_internal_signing_policies(@name, @request, true) }.to raise_error(
           Puppet::SSL::CertificateAuthority::CertificateSigningError,
           /subjectAltName outside the DNS label space/
         )
@@ -497,7 +562,7 @@
         @request.content.stubs(:subject).
           returns(OpenSSL::X509::Name.new([["CN", "*.local"]]))
 
-        expect { @ca.sign(@name) }.to raise_error(
+        expect { @ca.check_internal_signing_policies('*.local', @request, false) }.to raise_error(
           Puppet::SSL::CertificateAuthority::CertificateSigningError,
           /subject contains a wildcard/
         )
@@ -505,7 +570,7 @@
 
       it "should reject a wildcard subjectAltName" do
         @request.stubs(:subject_alt_names).returns ['DNS:foo', 'DNS:*.bar']
-        expect { @ca.sign(@name, true) }.to raise_error(
+        expect { @ca.check_internal_signing_policies(@name, @request, true) }.to raise_error(
           Puppet::SSL::CertificateAuthority::CertificateSigningError,
           /subjectAltName contains a wildcard/
         )
```
