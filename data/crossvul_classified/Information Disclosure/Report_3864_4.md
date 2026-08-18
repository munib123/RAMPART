# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in ruby
**Pair ID:** 3864_4
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3864_4`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```ruby
Lines 85-125 of the vulnerable file.


  context "application_owner is enabled" do
    before do
      Doorkeeper.configure do
        orm DOORKEEPER_ORM
        enable_application_owner
      end
    end

    context "application owner is not required" do
      before(:each) do
        unset_require_owner
      end

      it "is valid given valid attributes" do
        expect(new_application).to be_valid
      end
    end

    context "application owner is required" do
      before(:each) do
        require_owner
        @owner = FactoryBot.build_stubbed(:doorkeeper_testing_user)
      end

      it "is invalid without an owner" do
        expect(new_application).not_to be_valid
      end

      it "is valid with an owner" do
        new_application.owner = @owner
        expect(new_application).to be_valid
      end
    end
  end

  context "redirect URI" do
    context "when grant flows allow blank redirect URI" do
      before do
        Doorkeeper.configure do
          grant_flows %w[password client_credentials]
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -102,7 +102,7 @@
     end
 
     context "application owner is required" do
-      before(:each) do
+      before do
         require_owner
         @owner = FactoryBot.build_stubbed(:doorkeeper_testing_user)
       end
@@ -421,16 +421,7 @@
         .to receive(:application_secret_strategy).and_return(Doorkeeper::SecretStoring::Plain)
     end
 
-    it "includes plaintext secret" do
-      expect(app.as_json).to include("secret" => "123123123")
-    end
-
-    it "respects custom options" do
-      expect(app.as_json(except: :secret)).not_to include("secret")
-      expect(app.as_json(only: :id)).to match("id" => app.id)
-    end
-
-    # AR specific
+    # AR specific feature
     if DOORKEEPER_ORM == :active_record
       it "correctly works with #to_json" do
         ActiveRecord::Base.include_root_in_json = true
@@ -438,5 +429,62 @@
         ActiveRecord::Base.include_root_in_json = false
       end
     end
+
+    context "when called without authorized resource owner" do
+      it "includes minimal set of attributes" do
+        expect(app.as_json).to match(
+          "id" => app.id,
+          "name" => app.name,
+          "created_at" => an_instance_of(String),
+        )
+      end
+
+      it "includes application UID if it's public" do
+        app = FactoryBot.create :application, secret: "123123123", confidential: false
+
+        expect(app.as_json).to match(
+          "id" => app.id,
+          "name" => app.name,
+          "created_at" => an_instance_of(String),
+          "uid" => app.uid,
+        )
+      end
+
+      it "respects custom options" do
+        expect(app.as_json(except: :id)).not_to include("id")
+        expect(app.as_json(only: %i[name created_at secret]))
+          .to match(
+            "name" => app.name,
+            "created_at" => an_instance_of(String),
+          )
+      end
+    end
+
+    context "when called with authorized resource owner" do
+      let(:owner) { FactoryBot.create(:doorkeeper_testing_user) }
+      let(:other_owner) { FactoryBot.create(:doorkeeper_testing_user) }
+      let(:app) { FactoryBot.create(:application, secret: "123123123", owner: owner) }
+
+      before do
+        Doorkeeper.configure do
+          orm DOORKEEPER_ORM
+          enable_application_owner confirmation: false
+        end
+      end
+
+      it "includes all the attributes" do
+        expect(app.as_json(current_resource_owner: owner))
+          .to include(
+            "secret" => "123123123",
+            "redirect_uri" => app.redirect_uri,
+            "uid" => app.uid,
+          )
+      end
+
+      it "doesn't include unsafe attributes if current owner isn't the same as owner" do
+        expect(app.as_json(current_resource_owner: other_owner))
+          .not_to include("redirect_uri")
+      end
+    end
   end
 end
```
