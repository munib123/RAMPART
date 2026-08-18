# CrossVul Fix Pair: Improper Access Control in ruby
**Pair ID:** 748_4
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-284
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `748_4`)

## Vulnerability Information & PoC

## Description
Improper Access Control - Access control involves the use of several protection mechanisms such as: Authentication (proving the identity of an actor) Authorization (ensuring that a given actor can access a resource), and Ac...

## Vulnerable Code
```ruby
Lines 1352-1392 of the vulnerable file.


      expect(response.status).to eq(302)
      expect(session[:current_user_id]).to be_blank
      expect(response.cookies["_t"]).to be_blank
    end
  end

  describe '#one_time_password' do
    context 'missing token' do
      it 'returns the right response' do
        get "/session/otp"
        expect(response.status).to eq(404)
      end
    end

    context 'invalid token' do
      it 'returns the right response' do
        get "/session/otp/asd1231dasd123"

        expect(response.status).to eq(404)
      end

      context 'when token is valid' do
        it 'should authenticate user and delete token' do
          user = Fabricate(:user)

          get "/session/current.json"
          expect(response.status).to eq(404)

          token = SecureRandom.hex
          $redis.setex "otp_#{token}", 10.minutes, user.username

          get "/session/otp/#{token}"

          expect(response.status).to eq(302)
          expect(response).to redirect_to("/")
          expect($redis.get("otp_#{token}")).to eq(nil)

          get "/session/current.json"
          expect(response.status).to eq(200)
        end
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1369,9 +1369,40 @@
         get "/session/otp/asd1231dasd123"
 
         expect(response.status).to eq(404)
+
+        post "/session/otp/asd1231dasd123"
+
+        expect(response.status).to eq(404)
       end
 
       context 'when token is valid' do
+        it "should display the form for GET" do
+          token = SecureRandom.hex
+          $redis.setex "otp_#{token}", 10.minutes, user.username
+
+          get "/session/otp/#{token}"
+
+          expect(response.status).to eq(200)
+          expect(response.body).to include(
+            I18n.t("user_api_key.otp_confirmation.logging_in_as", username: user.username)
+          )
+          expect($redis.get("otp_#{token}")).to eq(user.username)
+
+          expect(session[:current_user_id]).to eq(nil)
+        end
+
+        it "should redirect on GET if already logged in" do
+          sign_in(user)
+          token = SecureRandom.hex
+          $redis.setex "otp_#{token}", 10.minutes, user.username
+
+          get "/session/otp/#{token}"
+          expect(response.status).to eq(302)
+
+          expect($redis.get("otp_#{token}")).to eq(nil)
+          expect(session[:current_user_id]).to eq(user.id)
+        end
+
         it 'should authenticate user and delete token' do
           user = Fabricate(:user)
 
@@ -1381,7 +1412,7 @@
           token = SecureRandom.hex
           $redis.setex "otp_#{token}", 10.minutes, user.username
 
-          get "/session/otp/#{token}"
+          post "/session/otp/#{token}"
 
           expect(response.status).to eq(302)
           expect(response).to redirect_to("/")
```
