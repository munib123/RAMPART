# CrossVul Fix Pair: Cross-Site Request Forgery (CSRF) in ruby
**Pair ID:** 4873_1
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)
**CWE:** CWE-352
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4873_1`)

## Vulnerability Information & PoC

## Description
Cross-Site Request Forgery (CSRF) - When a web server is designed to receive a request from a client without any mechanism for verifying that it was intentionally sent, then it might be possible for an attacker to trick a client into...

## Vulnerable Code
```ruby
Lines 131-151 of the vulnerable file.

      visit dashboard_path
      is_expected.not_to have_selector('ul.nav.pull-right li img')
    end

    it 'does not cause error when email is nil' do
      allow_any_instance_of(User).to receive(:email).and_return(nil)
      visit dashboard_path
      is_expected.to have_selector('body.rails_admin')
    end

    it 'shows a log out link' do
      visit dashboard_path
      is_expected.to have_content 'Log out'
    end

    it 'has label-danger class on log out link' do
      visit dashboard_path
      is_expected.to have_selector('.label-danger')
    end
  end
end
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -148,4 +148,17 @@
       is_expected.to have_selector('.label-danger')
     end
   end
+
+  describe 'CSRF protection' do
+    before do
+      allow_any_instance_of(ActionController::Base).to receive(:protect_against_forgery?).and_return(true)
+    end
+
+    it 'is enforced' do
+      visit new_path(model_name: 'league')
+      fill_in 'league[name]', with: 'National league'
+      find('input[name="authenticity_token"]', visible: false).set("invalid token")
+      expect { click_button 'Save' }.to raise_error ActionController::InvalidAuthenticityToken
+    end
+  end
 end
```
