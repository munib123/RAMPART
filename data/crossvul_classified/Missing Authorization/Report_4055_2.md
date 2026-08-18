# CrossVul Fix Pair: Missing Authorization in ruby
**Pair ID:** 4055_2
**Vulnerability Class:** Missing Authorization
**CWE:** CWE-862
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4055_2`)

## Vulnerability Information & PoC

## Description
Missing Authorization - Assuming a user with a given identity, authorization is the process of determining whether that user can access a given resource, based on the user's privileges and any permissions or other access-...

## Vulnerable Code
```ruby
Lines 1776-1816 of the vulnerable file.

          'Mime-Type'    => 'image/jpeg',
          'Content-ID'   => '15.274327094.140938.4@zammad.example.com',
        },
        created_by_id: 1,
      )
      Store.add(
        object:        'Ticket::Article',
        o_id:          article.id,
        data:          'content_file1_normally_should_be_an_pdf',
        filename:      'Rechnung_RE-2018-200.pdf',
        preferences:   {
          'Content-Type'        => 'application/octet-stream; name="Rechnung_RE-2018-200.pdf"',
          'Mime-Type'           => 'application/octet-stream',
          'Content-ID'          => '8AB0BEC88984EE4EBEF643C79C8E0346@zammad.example.com',
          'Content-Description' => 'Rechnung_RE-2018-200.pdf',
          'Content-Disposition' => 'attachment',
        },
        created_by_id: 1,
      )

      authenticated_as(agent_user)
      get "/api/v1/ticket_split?ticket_id=#{ticket.id}&article_id=#{article.id}&form_id=new_form_id123", params: {}, as: :json
      expect(response).to have_http_status(:ok)
      expect(json_response).to be_a_kind_of(Hash)
      expect(json_response['assets']).to be_truthy
      expect(json_response['assets']['Ticket']).to be_truthy
      expect(json_response['assets']['Ticket'][ticket.id.to_s]).to be_truthy
      expect(json_response['assets']['TicketArticle'][article.id.to_s]).to be_truthy
      expect(json_response['attachments']).to be_truthy
      expect(json_response['attachments'].count).to eq(3)

      get "/api/v1/ticket_split?ticket_id=#{ticket.id}&article_id=#{article.id}&form_id=new_form_id123", params: {}, as: :json
      expect(response).to have_http_status(:ok)
      expect(json_response).to be_a_kind_of(Hash)
      expect(json_response['assets']).to be_truthy
      expect(json_response['assets']['Ticket']).to be_truthy
      expect(json_response['assets']['Ticket'][ticket.id.to_s]).to be_truthy
      expect(json_response['assets']['TicketArticle'][article.id.to_s]).to be_truthy
      expect(json_response['attachments']).to be_truthy
      expect(json_response['attachments'].count).to eq(0)

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1793,6 +1793,10 @@
         created_by_id: 1,
       )
 
+      authenticated_as(customer_user)
+      get "/api/v1/ticket_split?ticket_id=#{ticket.id}&article_id=#{article.id}&form_id=new_form_id123", params: {}, as: :json
+      expect(response).to have_http_status(:unauthorized)
+
       authenticated_as(agent_user)
       get "/api/v1/ticket_split?ticket_id=#{ticket.id}&article_id=#{article.id}&form_id=new_form_id123", params: {}, as: :json
       expect(response).to have_http_status(:ok)
@@ -1918,6 +1922,10 @@
         customer_id: customer_user.id,
       )
 
+      authenticated_as(customer_user)
+      get "/api/v1/ticket_merge/#{ticket2.id}/#{ticket1.id}", params: {}, as: :json
+      expect(response).to have_http_status(:unauthorized)
+
       authenticated_as(agent_user)
       get "/api/v1/ticket_merge/#{ticket2.id}/#{ticket1.id}", params: {}, as: :json
       expect(response).to have_http_status(:ok)
@@ -2068,7 +2076,39 @@
       expect(json_response['assets'].class).to eq(Hash)
       expect(json_response['assets']['User'][customer_user.id.to_s]).not_to be_nil
       expect(json_response['assets']['Ticket'][ticket1.id.to_s]).not_to be_nil
-    end
+
+      authenticated_as(customer_user)
+      get "/api/v1/ticket_history/#{ticket1.id}", params: {}, as: :json
+      expect(response).to have_http_status(:unauthorized)
+    end
+
+    it 'does ticket related' do
+      ticket1 = create(
+        :ticket,
+        title:       'some title',
+        group:       ticket_group,
+        customer_id: customer_user.id,
+      )
+
+      authenticated_as(agent_user)
+      get "/api/v1/ticket_related/#{ticket1.id}", params: {}, as: :json
+      expect(response).to have_http_status(:ok)
+
+      authenticated_as(customer_user)
+      get "/api/v1/ticket_related/#{ticket1.id}", params: {}, as: :json
+      expect(response).to have_http_status(:unauthorized)
+    end
+
+    it 'does ticket recent' do
+      authenticated_as(agent_user)
+      get '/api/v1/ticket_recent', params: {}, as: :json
+      expect(response).to have_http_status(:ok)
+
+      authenticated_as(customer_user)
+      get '/api/v1/ticket_recent', params: {}, as: :json
+      expect(response).to have_http_status(:unauthorized)
+    end
+
   end
 
   describe 'stats' do
@@ -2213,7 +2253,7 @@
       end
 
       context 'as authorized customer', authenticated_as: -> { customer_authorized } do
-        include_examples 'has access'
+        include_examples 'has no access'
       end
 
       context 'as unauthorized customer', authenticated_as: -> { customer_unauthorized } do
```
