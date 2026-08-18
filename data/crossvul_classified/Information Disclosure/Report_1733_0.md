# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in ruby
**Pair ID:** 1733_0
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1733_0`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```ruby
Lines 159-199 of the vulnerable file.

          mustache :edit
        end
      else
        redirect to("/create/#{encodeURIComponent(@name)}")
      end
    end

    post '/uploadFile' do
      wiki = wiki_new

      unless wiki.allow_uploads
        @message = "File uploads are disabled"
        mustache :error
        return
      end

      if params[:file]
        fullname = params[:file][:filename]
        tempfile = params[:file][:tempfile]
      end

      # Remove page file dir prefix from upload path if necessary -- committer handles this itself
      dir      = wiki.per_page_uploads ? params[:upload_dest].match(/^(#{wiki.page_file_dir}\/+)?(.*)/)[2] : 'uploads'
      ext      = ::File.extname(fullname)
      format   = ext.split('.').last || 'txt'
      filename = ::File.basename(fullname, ext)
      contents = ::File.read(tempfile)
      reponame = filename + '.' + format

      head = wiki.repo.head

      options = {
          :message => "Uploaded file to #{dir}/#{reponame}",
          :parent  => wiki.repo.head.commit,
      }
      author  = session['gollum.author']
      unless author.nil?
        options.merge! author
      end

      begin
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -176,6 +176,7 @@
         fullname = params[:file][:filename]
         tempfile = params[:file][:tempfile]
       end
+      halt 500 unless tempfile.is_a? Tempfile
 
       # Remove page file dir prefix from upload path if necessary -- committer handles this itself
       dir      = wiki.per_page_uploads ? params[:upload_dest].match(/^(#{wiki.page_file_dir}\/+)?(.*)/)[2] : 'uploads'
```
