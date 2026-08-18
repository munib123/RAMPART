# CrossVul Fix Pair: Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') in ruby
**Pair ID:** 4525_1
**Vulnerability Class:** Code Injection
**CWE:** CWE-74
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4525_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') - Software or other automated logic has certain assumptions about what constitutes data and control respectively.

## Vulnerable Code
```ruby
Lines 12-52 of the vulnerable file.

        report_uri: %w(/csp_report)
      }
    end

    describe "#name" do
      context "when in report-only mode" do
        specify { expect(ContentSecurityPolicy.new(default_opts.merge(report_only: true)).name).to eq(ContentSecurityPolicyReportOnlyConfig::HEADER_NAME) }
      end

      context "when in enforce mode" do
        specify { expect(ContentSecurityPolicy.new(default_opts).name).to eq(ContentSecurityPolicyConfig::HEADER_NAME) }
      end
    end

    describe "#value" do
      it "uses a safe but non-breaking default value" do
        expect(ContentSecurityPolicy.new.value).to eq("default-src https:; form-action 'self'; img-src https: data: 'self'; object-src 'none'; script-src https:; style-src 'self' 'unsafe-inline' https:")
      end

      it "deprecates and escapes semicolons in directive source lists" do
        expect(Kernel).to receive(:warn).with("frame_ancestors contains a ; in 'google.com;script-src *;.;' which will raise an error in future versions. It has been replaced with a blank space.")
        expect(ContentSecurityPolicy.new(frame_ancestors: %w(https://google.com;script-src https://*;.;)).value).to eq("frame-ancestors google.com script-src * .")
      end

      it "discards 'none' values if any other source expressions are present" do
        csp = ContentSecurityPolicy.new(default_opts.merge(child_src: %w('self' 'none')))
        expect(csp.value).not_to include("'none'")
      end

      it "discards source expressions (besides unsafe-* and non-host source values) when * is present" do
        csp = ContentSecurityPolicy.new(default_src: %w(* 'unsafe-inline' 'unsafe-eval' http: https: example.org data: blob:))
        expect(csp.value).to eq("default-src * 'unsafe-inline' 'unsafe-eval' data: blob:")
      end

      it "minifies source expressions based on overlapping wildcards" do
        config = {
          default_src: %w(a.example.org b.example.org *.example.org https://*.example.org)
        }
        csp = ContentSecurityPolicy.new(config)
        expect(csp.value).to eq("default-src *.example.org")
      end
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -29,8 +29,13 @@
       end
 
       it "deprecates and escapes semicolons in directive source lists" do
-        expect(Kernel).to receive(:warn).with("frame_ancestors contains a ; in 'google.com;script-src *;.;' which will raise an error in future versions. It has been replaced with a blank space.")
+        expect(Kernel).to receive(:warn).with(%(frame_ancestors contains a ; in "google.com;script-src *;.;" which will raise an error in future versions. It has been replaced with a blank space.))
         expect(ContentSecurityPolicy.new(frame_ancestors: %w(https://google.com;script-src https://*;.;)).value).to eq("frame-ancestors google.com script-src * .")
+      end
+
+      it "deprecates and escapes semicolons in directive source lists" do
+        expect(Kernel).to receive(:warn).with(%(frame_ancestors contains a \n in "\\nfoo.com\\nhacked" which will raise an error in future versions. It has been replaced with a blank space.))
+        expect(ContentSecurityPolicy.new(frame_ancestors: ["\nfoo.com\nhacked"]).value).to eq("frame-ancestors  foo.com hacked")
       end
 
       it "discards 'none' values if any other source expressions are present" do
```
