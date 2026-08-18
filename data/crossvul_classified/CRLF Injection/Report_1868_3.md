# CrossVul Fix Pair: Improper Neutralization of CRLF Sequences ('CRLF Injection') in ruby
**Pair ID:** 1868_3
**Vulnerability Class:** CRLF Injection
**CWE:** CWE-93
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1868_3`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of CRLF Sequences ('CRLF Injection') - The product uses CRLF (carriage return line feeds) as a special element, e.

## Vulnerable Code
```ruby
Lines 92-132 of the vulnerable file.

        end
      end
      errors.should be_false
    end

    it "should be able to parse a large email without raising an exception" do
      m = Mail.new
      m.add_file(:filename => "attachment.data", :content => "a" * (8 * 1024 * 1024))
      raw_email = "From jamis_buck@byu.edu Mon May  2 16:07:05 2005\r\n#{m.to_s}"

      doing { Mail::Message.new(raw_email) }.should_not raise_error
    end

    it "should not raise a warning on having non US-ASCII characters in the header (should just handle it)" do
      STDERR.should_not_receive(:puts)
      Mail.read(fixture('emails', 'plain_emails', 'raw_email_string_in_date_field.eml'))
    end

    it "should raise a warning (and keep parsing) on having an incorrectly formatted header" do
      STDERR.should_receive(:puts).with("WARNING: Could not parse (and so ignoring) 'quite Delivered-To: xxx@xxx.xxx'")
      Mail.read(fixture('emails', 'plain_emails', 'raw_email_incorrect_header.eml'))
    end

    it "should read in an email message and basically parse it" do
      mail = Mail.read(fixture('emails', 'plain_emails', 'basic_email.eml'))
      mail.to.should eq ["raasdnil@gmail.com"]
    end

    it "should not fail parsing message with caps in content_type" do
      mail = Mail.read(fixture('emails', 'plain_emails', 'mix_caps_content_type.eml'))
      mail.content_type.should eq 'text/plain; charset=iso-8859-1'
      mail.main_type.should eq 'text'
      mail.sub_type.should eq 'plain'
    end

    it "should be able to pass an empty reply-to header" do
      mail = Mail.read(fixture('emails', 'error_emails', 'empty_in_reply_to.eml'))
      mail.in_reply_to.should be_blank
    end

    describe "YAML serialization" do
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -109,7 +109,7 @@
 
     it "should raise a warning (and keep parsing) on having an incorrectly formatted header" do
       STDERR.should_receive(:puts).with("WARNING: Could not parse (and so ignoring) 'quite Delivered-To: xxx@xxx.xxx'")
-      Mail.read(fixture('emails', 'plain_emails', 'raw_email_incorrect_header.eml'))
+      Mail.read(fixture('emails', 'plain_emails', 'raw_email_incorrect_header.eml')).to_s
     end
 
     it "should read in an email message and basically parse it" do
```
