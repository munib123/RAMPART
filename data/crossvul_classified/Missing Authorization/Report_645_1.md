# CrossVul Fix Pair: Missing Authorization in ruby
**Pair ID:** 645_1
**Vulnerability Class:** Missing Authorization
**CWE:** CWE-862
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `645_1`)

## Vulnerability Information & PoC

## Description
Missing Authorization - Assuming a user with a given identity, authorization is the process of determining whether that user can access a given resource, based on the user's privileges and any permissions or other access-...

## Vulnerable Code
```ruby
Lines 410-430 of the vulnerable file.


    let(:review_by_user)    { create(:review, by_user:    user.login) }
    let(:review_by_group)   { create(:review, by_group:   group.title) }
    let(:review_by_project) { create(:review, by_project: project.name) }
    let(:review_by_package) { create(:review, by_project: project.name, by_package: package.name) }

    it 'returns true if review configuration matches provided hash' do
      expect(review_by_user.reviewable_by?(by_user:       user.login)).to be true
      expect(review_by_group.reviewable_by?(by_group:     group.title)).to be true
      expect(review_by_project.reviewable_by?(by_project: project.name)).to be true
      expect(review_by_package.reviewable_by?(by_package: package.name)).to be true
    end

    it 'returns false if review configuration does not match provided hash' do
      expect(review_by_user.reviewable_by?(by_user:       other_user.login)).to be_falsy
      expect(review_by_group.reviewable_by?(by_group:     other_group.title)).to be_falsy
      expect(review_by_project.reviewable_by?(by_project: other_project.name)).to be_falsy
      expect(review_by_package.reviewable_by?(by_package: other_package.name)).to be_falsy
    end
  end
end
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -427,4 +427,20 @@
       expect(review_by_package.reviewable_by?(by_package: other_package.name)).to be_falsy
     end
   end
+
+  describe '.new_from_xml_hash' do
+    let(:request_xml) do
+      "<request>
+        <review state='accepted' by_user='#{user}'/>
+      </request>"
+    end
+    let(:request_hash) { Xmlhash.parse(request_xml) }
+    let(:review_hash) { request_hash['review'] }
+
+    subject { Review.new_from_xml_hash(review_hash) }
+
+    it 'initalizes the review in state :new' do
+      expect(subject.state).to eq(:new)
+    end
+  end
 end
```
