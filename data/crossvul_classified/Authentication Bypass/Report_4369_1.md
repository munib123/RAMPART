# CrossVul Fix Pair: Authentication Bypass by Spoofing in ruby
**Pair ID:** 4369_1
**Vulnerability Class:** Authentication Bypass
**CWE:** CWE-290
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4369_1`)

## Vulnerability Information & PoC

## Description
Authentication Bypass by Spoofing - This attack-focused weakness is caused by incorrectly implemented authentication schemes that are subject to spoofing attacks.

## Vulnerable Code
```ruby
Lines 235-275 of the vulnerable file.

    it 'should return name' do
      # https://github.com/omniauth/omniauth/wiki/Auth-Hash-Schema
      # schema lists 'name' as required property
      expect(subject.info[:name]).to eq 'first last'
    end

    context 'fails nonce' do
      before(:each) do
        expect(subject).to receive(:fail!).with(:nonce_mismatch, instance_of(OmniAuth::Strategies::OAuth2::CallbackError))
      end
      it 'when differs from session' do
        subject.session['omniauth.nonce'] = 'abc'
        subject.info
      end
      it 'when missing from session' do
        subject.session.delete('omniauth.nonce')
        subject.info
      end
    end

  end

  describe '#extra' do
    before(:each) do
      subject.authorize_params # initializes session / populates 'nonce', 'state', etc
      id_token_payload['nonce'] = subject.session['omniauth.nonce']
    end

    describe 'id_token' do
      context 'issued by valid issuer' do
        before(:each) do
          request.params.merge!('id_token' => id_token)
        end
        context 'when the id_token is passed into the access token' do
          it 'should include id_token when set on the access_token' do
            expect(subject.extra[:raw_info]).to include(id_token: id_token)
          end

          it 'should include id_info when id_token is set on the access_token' do
            expect(subject.extra[:raw_info]).to include(id_info: id_token_payload)
          end
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -252,6 +252,21 @@
       end
     end
 
+    context 'with a spoofed email in the user payload' do
+      before do
+        request.params['user'] = {
+          name: {
+            firstName: 'first',
+            lastName: 'last'
+          },
+          email: "spoofed@example.com"
+        }.to_json
+      end
+
+      it 'should return the true email' do
+        expect(subject.info[:email]).to eq('something@privatrerelay.appleid.com')
+      end
+    end
   end
 
   describe '#extra' do
```
