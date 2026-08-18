# CrossVul Fix Pair: Improper Authentication in ruby
**Pair ID:** 4202_1
**Vulnerability Class:** Improper Authentication - Generic
**CWE:** CWE-287
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4202_1`)

## Vulnerability Information & PoC

## Description
Improper Authentication - When an actor claims to have a given identity, the product does not prove or insufficiently proves that the claim is correct.

## Vulnerable Code
```ruby
Lines 1-13 of the vulnerable file.

shared_context 'API v2 tokens' do
  let(:token) { Doorkeeper::AccessToken.create!(resource_owner_id: user.id, expires_in: nil) }
  let(:headers_bearer) { { 'Authorization' => "Bearer #{token.token}" } }
  let(:headers_order_token) { { 'X-Spree-Order-Token' => order.token } }
end

[200, 201, 400, 404, 403, 422].each do |status_code|
  shared_examples "returns #{status_code} HTTP status" do
    it "returns #{status_code}" do
      expect(response.status).to eq(status_code)
    end
  end
end
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -4,7 +4,7 @@
   let(:headers_order_token) { { 'X-Spree-Order-Token' => order.token } }
 end
 
-[200, 201, 400, 404, 403, 422].each do |status_code|
+[200, 201, 400, 401, 404, 403, 422].each do |status_code|
   shared_examples "returns #{status_code} HTTP status" do
     it "returns #{status_code}" do
       expect(response.status).to eq(status_code)
```
