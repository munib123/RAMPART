# CrossVul Fix Pair: Missing Authorization in ruby
**Pair ID:** 4055_0
**Vulnerability Class:** Missing Authorization
**CWE:** CWE-862
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4055_0`)

## Vulnerability Information & PoC

## Description
Missing Authorization - Assuming a user with a given identity, authorization is the process of determining whether that user can access a given resource, based on the user's privileges and any permissions or other access-...

## Vulnerable Code
```ruby
Lines 1-29 of the vulnerable file.

# Copyright (C) 2012-2016 Zammad Foundation, http://zammad-foundation.org/

class TicketsController < ApplicationController
  include CreatesTicketArticles
  include ClonesTicketArticleAttachments
  include ChecksUserAttributesByCurrentUserPermission
  include TicketStats

  prepend_before_action -> { authorize! }, only: %i[create selector import_example import_start]
  prepend_before_action :authentication_check

  # GET /api/v1/tickets
  def index
    offset = 0
    per_page = 100

    if params[:page] && params[:per_page]
      offset = (params[:page].to_i - 1) * params[:per_page].to_i
      per_page = params[:per_page].to_i
    end

    if per_page > 100
      per_page = 100
    end

    access_condition = Ticket.access_condition(current_user, 'read')
    tickets = Ticket.where(access_condition).order(id: :asc).offset(offset).limit(per_page)

    if response_expand?
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -6,7 +6,7 @@
   include ChecksUserAttributesByCurrentUserPermission
   include TicketStats
 
-  prepend_before_action -> { authorize! }, only: %i[create selector import_example import_start]
+  prepend_before_action -> { authorize! }, only: %i[create selector import_example import_start ticket_customer ticket_history ticket_related ticket_recent ticket_merge ticket_split]
   prepend_before_action :authentication_check
 
   # GET /api/v1/tickets
```
