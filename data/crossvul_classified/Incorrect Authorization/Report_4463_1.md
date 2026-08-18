# CrossVul Fix Pair: Incorrect Authorization in ruby
**Pair ID:** 4463_1
**Vulnerability Class:** Incorrect Authorization
**CWE:** CWE-863
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4463_1`)

## Vulnerability Information & PoC

## Description
Incorrect Authorization - Assuming a user with a given identity, authorization is the process of determining whether that user can access a given resource, based on the user's privileges and any permissions or other access-...

## Vulnerable Code
```ruby
Lines 101-141 of the vulnerable file.

      expect(ticket.articles.count).to eq(4)
      expect(ticket.articles[0].attachments.count).to eq(0)
      expect(ticket.articles[1].attachments.count).to eq(0)
      expect(ticket.articles[2].attachments.count).to eq(1)
      expect(ticket.articles[3].attachments.count).to eq(1)

      get "/api/v1/ticket_articles/#{json_response['id']}?expand=true", params: {}, as: :json
      expect(response).to have_http_status(:ok)
      expect(json_response).to be_a_kind_of(Hash)
      expect(json_response['attachments'].count).to eq(1)
      expect(json_response['attachments'][0]['id']).to be_truthy
      expect(json_response['attachments'][0]['filename']).to eq('some_file.txt')
      expect(json_response['attachments'][0]['size']).to eq('8')
      expect(json_response['attachments'][0]['preferences']['Mime-Type']).to eq('text/plain')

      params = {
        ticket_id:    json_response['ticket_id'],
        content_type: 'text/plain',
        body:         'some body',
        type:         'note',
        preferences:  {
          some_key1: 123,
        },
      }
      post '/api/v1/ticket_articles', params: params, as: :json
      expect(response).to have_http_status(:created)
      expect(json_response).to be_a_kind_of(Hash)
      expect(json_response['subject']).to be_nil
      expect(json_response['body']).to eq('some body')
      expect(json_response['content_type']).to eq('text/plain')
      expect(json_response['updated_by_id']).to eq(agent.id)
      expect(json_response['created_by_id']).to eq(agent.id)
      expect(json_response['preferences']['some_key1']).to eq(123)
      expect(ticket.articles.count).to eq(5)

      params = {
        body:        'some body 2',
        preferences: {
          some_key2: 'abc',
        },
      }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -118,8 +118,10 @@
         content_type: 'text/plain',
         body:         'some body',
         type:         'note',
+        internal:     false,
         preferences:  {
           some_key1: 123,
+          highlight: '123',
         },
       }
       post '/api/v1/ticket_articles', params: params, as: :json
@@ -127,28 +129,34 @@
       expect(json_response).to be_a_kind_of(Hash)
       expect(json_response['subject']).to be_nil
       expect(json_response['body']).to eq('some body')
+      expect(json_response['internal']).to eq(false)
       expect(json_response['content_type']).to eq('text/plain')
       expect(json_response['updated_by_id']).to eq(agent.id)
       expect(json_response['created_by_id']).to eq(agent.id)
       expect(json_response['preferences']['some_key1']).to eq(123)
+      expect(json_response['preferences']['highlight']).to eq('123')
       expect(ticket.articles.count).to eq(5)
 
       params = {
         body:        'some body 2',
+        internal:    true,
         preferences: {
           some_key2: 'abc',
+          highlight: '234',
         },
       }
       put "/api/v1/ticket_articles/#{json_response['id']}", params: params, as: :json
       expect(response).to have_http_status(:ok)
       expect(json_response).to be_a_kind_of(Hash)
       expect(json_response['subject']).to be_nil
-      expect(json_response['body']).to eq('some body 2')
+      expect(json_response['body']).not_to eq('some body 2')
+      expect(json_response['internal']).to eq(true)
       expect(json_response['content_type']).to eq('text/plain')
       expect(json_response['updated_by_id']).to eq(agent.id)
       expect(json_response['created_by_id']).to eq(agent.id)
       expect(json_response['preferences']['some_key1']).to eq(123)
-      expect(json_response['preferences']['some_key2']).to eq('abc')
+      expect(json_response['preferences']['some_key2']).not_to eq('abc')
+      expect(json_response['preferences']['highlight']).to eq('234')
 
     end
 
```
