# CrossVul Fix Pair: Incorrect Authorization in ruby
**Pair ID:** 4463_0
**Vulnerability Class:** Incorrect Authorization
**CWE:** CWE-863
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4463_0`)

## Vulnerability Information & PoC

## Description
Incorrect Authorization - Assuming a user with a given identity, authorization is the process of determining whether that user can access a given resource, based on the user's privileges and any permissions or other access-...

## Vulnerable Code
```ruby
Lines 84-128 of the vulnerable file.

    if response_expand?
      result = article.attributes_with_association_names
      render json: result, status: :created
      return
    end

    if response_full?
      full = Ticket::Article.full(params[:id])
      render json: full, status: :created
      return
    end

    render json: article.attributes_with_association_names, status: :created
  end

  # PUT /articles/1
  def update
    article = Ticket::Article.find(params[:id])
    authorize!(article)

    clean_params = Ticket::Article.association_name_to_id_convert(params)
    clean_params = Ticket::Article.param_cleanup(clean_params, true)

    # only apply preferences changes (keep not updated keys/values)
    clean_params = article.param_preferences_merge(clean_params)

    article.update!(clean_params)

    if response_expand?
      result = article.attributes_with_association_names
      render json: result, status: :ok
      return
    end

    if response_full?
      full = Ticket::Article.full(params[:id])
      render json: full, status: :ok
      return
    end

    render json: article.attributes_with_association_names, status: :ok
  end

  # DELETE /api/v1/ticket_articles/:id
  def destroy
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -101,11 +101,18 @@
     article = Ticket::Article.find(params[:id])
     authorize!(article)
 
-    clean_params = Ticket::Article.association_name_to_id_convert(params)
-    clean_params = Ticket::Article.param_cleanup(clean_params, true)
-
-    # only apply preferences changes (keep not updated keys/values)
-    clean_params = article.param_preferences_merge(clean_params)
+    # only update internal and highlight info
+    clean_params = {}
+    if !params[:internal].nil?
+      clean_params[:internal] = params[:internal]
+    end
+    if params.dig(:preferences, :highlight).present?
+      clean_params = article.param_preferences_merge(clean_params.merge(
+                                                       preferences: {
+                                                         highlight: params[:preferences][:highlight].to_s
+                                                       }
+                                                     ))
+    end
 
     article.update!(clean_params)
 
```
