# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in ruby
**Pair ID:** 5838_1
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5838_1`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```ruby
Lines 120-160 of the vulnerable file.

    end
    member do
      put  :attach
      post :discard
      post :subscribe
      post :unsubscribe
      get :contacts
    end
  end

  resources :tasks, :id => /\d+/ do
    collection do
      post :filter
      post :auto_complete
    end
    member do
      put :complete
    end
  end

  resources :users, :id => /\d+/ do
    member do
      get :avatar
      get :password
      put :upload_avatar
      put :change_password
      post :redraw
    end

    collection do
      match :auto_complete
    end
    collection do
      get :opportunities_overview
    end
  end

  namespace :admin do
    resources :groups

    resources :users do
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -137,7 +137,7 @@
     end
   end
 
-  resources :users, :id => /\d+/ do
+  resources :users, :id => /\d+/, :except => [:index, :destroy] do
     member do
       get :avatar
       get :password
```
