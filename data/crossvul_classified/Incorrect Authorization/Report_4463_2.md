# CrossVul Fix Pair: Incorrect Authorization in ruby
**Pair ID:** 4463_2
**Vulnerability Class:** Incorrect Authorization
**CWE:** CWE-863
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4463_2`)

## Vulnerability Information & PoC

## Description
Incorrect Authorization - Assuming a user with a given identity, authorization is the process of determining whether that user can access a given resource, based on the user's privileges and any permissions or other access-...

## Vulnerable Code
```ruby
Lines 885-925 of the vulnerable file.

      expect(response).to have_http_status(:created)
      expect(json_response).to be_a_kind_of(Hash)
      expect(json_response['ticket_id']).to eq(ticket.id)
      expect(json_response['from']).to eq(%("Tickets Agent via #{ticket_group.email_address.realname}" <#{ticket_group.email_address.email}>))
      expect(json_response['subject']).to eq('some subject')
      expect(json_response['body']).to eq('some body')
      expect(json_response['content_type']).to eq('text/plain')
      expect(json_response['internal']).to eq(true)
      expect(json_response['created_by_id']).to eq(agent.id)
      expect(json_response['sender_id']).to eq(Ticket::Article::Sender.lookup(name: 'Agent').id)
      expect(json_response['type_id']).to eq(Ticket::Article::Type.lookup(name: 'email').id)

      params = {
        subject: 'new subject',
      }
      put "/api/v1/ticket_articles/#{json_response['id']}", params: params, as: :json
      expect(response).to have_http_status(:ok)
      expect(json_response).to be_a_kind_of(Hash)
      expect(json_response['ticket_id']).to eq(ticket.id)
      expect(json_response['from']).to eq(%("Tickets Agent via #{ticket_group.email_address.realname}" <#{ticket_group.email_address.email}>))
      expect(json_response['subject']).to eq('new subject')
      expect(json_response['body']).to eq('some body')
      expect(json_response['content_type']).to eq('text/plain')
      expect(json_response['internal']).to eq(true)
      expect(json_response['created_by_id']).to eq(agent.id)
      expect(json_response['sender_id']).to eq(Ticket::Article::Sender.lookup(name: 'Agent').id)
      expect(json_response['type_id']).to eq(Ticket::Article::Type.lookup(name: 'email').id)

      params = {
        from:      'something which should not be changed on server side',
        ticket_id: ticket.id,
        subject:   'some subject',
        body:      'some body',
        type:      'email',
        internal:  false,
      }
      post '/api/v1/ticket_articles', params: params, as: :json
      expect(response).to have_http_status(:created)
      expect(json_response['internal']).to eq(false)

      delete "/api/v1/ticket_articles/#{json_response['id']}", params: {}, as: :json
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -902,7 +902,7 @@
       expect(json_response).to be_a_kind_of(Hash)
       expect(json_response['ticket_id']).to eq(ticket.id)
       expect(json_response['from']).to eq(%("Tickets Agent via #{ticket_group.email_address.realname}" <#{ticket_group.email_address.email}>))
-      expect(json_response['subject']).to eq('new subject')
+      expect(json_response['subject']).not_to eq('new subject')
       expect(json_response['body']).to eq('some body')
       expect(json_response['content_type']).to eq('text/plain')
       expect(json_response['internal']).to eq(true)
@@ -991,7 +991,7 @@
       expect(json_response).to be_a_kind_of(Hash)
       expect(json_response['ticket_id']).to eq(ticket.id)
       expect(json_response['from']).to eq('Tickets Admin')
-      expect(json_response['subject']).to eq('new subject')
+      expect(json_response['subject']).not_to eq('new subject')
       expect(json_response['body']).to eq('some body')
       expect(json_response['content_type']).to eq('text/plain')
       expect(json_response['internal']).to eq(true)
```
