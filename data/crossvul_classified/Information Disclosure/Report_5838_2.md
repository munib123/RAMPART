# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in ruby
**Pair ID:** 5838_2
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5838_2`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```ruby
Lines 192-212 of the vulnerable file.

      @user.set_individual_locale
      I18n.locale.should == @locale
    end
  end

  describe "Setting single access token" do
    it "should update single_access_token attribute if it is not set already" do
      @user = FactoryGirl.create(:user, :single_access_token => nil)

      @user.set_single_access_token
      @user.single_access_token.should_not == nil
    end

    it "should not update single_access_token attribute if it is set already" do
      @user = FactoryGirl.create(:user, :single_access_token => "token")

      @user.set_single_access_token
      @user.single_access_token.should == "token"
    end
  end
end
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -209,4 +209,18 @@
       @user.single_access_token.should == "token"
     end
   end
+
+  describe "serialization" do
+
+    let(:user) { FactoryGirl.build(:user) }
+
+    it "to json" do
+      expect(user.to_json).to eql([user.name].to_json)
+    end
+
+    it "to xml" do
+      expect(user.to_xml).to eql([user.name].to_xml)
+    end
+
+  end
 end
```
