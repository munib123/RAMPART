# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in ruby
**Pair ID:** 4892_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4892_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```ruby
Lines 1-29 of the vulnerable file.

# ライブラリ
require 'sinatra'

# 開発環境用ライブラリ
if settings.development?
  require 'pry'
  require 'sinatra/reloader'
end

# クラス
require './class/vine.rb'
require './class/itunes.rb'
require './class/extract.rb'

get '/' do
  erb :index
end

# 音楽の検索
get '/music' do
  info = params["info"]
  search = Itunes.new()
  @music = search.search_musics(info)
  content_type :json
  data = { music: @music }
  data.to_json
end

# 検索ワードの決定
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -6,6 +6,11 @@
   require 'pry'
   require 'sinatra/reloader'
 end
+
+# ERBテンプレートで変数を自動エスケープ
+# cf. http://www.sinatrarb.com/faq.html#auto_escape_html
+require 'erubis'
+set :erb, :escape_html => true
 
 # クラス
 require './class/vine.rb'
```
