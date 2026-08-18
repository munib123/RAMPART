# CrossVul Fix Pair: Improper Authentication in ruby
**Pair ID:** 4202_2
**Vulnerability Class:** Improper Authentication - Generic
**CWE:** CWE-287
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4202_2`)

## Vulnerability Information & PoC

## Description
Improper Authentication - When an actor claims to have a given identity, the product does not prove or insufficiently proves that the claim is correct.

## Vulnerable Code
```ruby
Lines 12-32 of the vulnerable file.

  end

  context 'authorization failure' do
    let(:user) { create(:user) }
    let(:another_user) { create(:user) }
    let!(:order) { create(:order, user: another_user) }

    include_context 'API v2 tokens'

    before do
      allow_any_instance_of(Spree::Api::V2::Storefront::CartController).to receive(:spree_current_order).and_return(order)
      patch '/api/v2/storefront/cart/empty', headers: headers_bearer
    end

    it_behaves_like 'returns 403 HTTP status'

    it 'returns proper error message' do
      expect(json_response['error']).to eq('You are not authorized to access this page.')
    end
  end
end
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -29,4 +29,19 @@
       expect(json_response['error']).to eq('You are not authorized to access this page.')
     end
   end
+
+  context 'expired token failure' do
+    let(:user) { create(:user) }
+    let(:headers) { headers_bearer }
+
+    include_context 'API v2 tokens'
+
+    before do
+      token.expires_in = -1
+      token.save
+      get '/api/v2/storefront/account', headers: headers
+    end
+
+    it_behaves_like 'returns 401 HTTP status'
+  end
 end
```
