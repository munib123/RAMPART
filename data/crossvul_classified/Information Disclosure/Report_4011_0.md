# CrossVul Fix Pair: Exposure of Resource to Wrong Sphere in ruby
**Pair ID:** 4011_0
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-668
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4011_0`)

## Vulnerability Information & PoC

## Description
Exposure of Resource to Wrong Sphere - Resources such as files and directories may be inadvertently exposed through mechanisms such as insecure permissions, or when a program accidentally operates on the wrong object.

## Vulnerable Code
```ruby
Lines 39-79 of the vulnerable file.

end

# create DB backup
get '/admin/dbbackup' do
  redirect to('/no_access') unless is_administrator?
  bdate = Time.now
  filename = './tmp/master' + '-' + (bdate.strftime('%Y%m%d%H%M%S') + '.bak')
  FileUtils.copy_file('./db/master.db', filename)
  if !File.zero?(filename)
    send_file filename, filename: filename.to_s, type: 'Application/octet-stream'
    serpico_log("DB backup created")
  else
    'No copy of the database is available. Please try again.'
    sleep(5)
    redirect to('/admin/')
   end
end

# create backup of all attachments
get '/admin/attacments_backup' do
  bdate = Time.now
  zip_file = './tmp/Attachments' + '-' + (bdate.strftime('%Y%m%d%H%M%S') + '.zip')
  Zip::File.open(zip_file, Zip::File::CREATE) do |zipfile|
    Dir['./attachments/*'].each do |name|
      zipfile.add(name.split('/').last, name)
    end
  end
  send_file zip_file, type: 'zip', filename: zip_file
  # File.delete(rand_zip) should the temp file be deleted?
  serpico_log("Backup of attachments created")
end

# Create a new user
post '/admin/add_user' do
  redirect to('/no_access') unless is_administrator?

  user = User.first(username: params[:username])

  if user
    if params[:password] && (params[:password].size > 1)
      # we have to hardcode the input params to prevent param pollution
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -56,6 +56,7 @@
 
 # create backup of all attachments
 get '/admin/attacments_backup' do
+  redirect to('/no_access') unless is_administrator?
   bdate = Time.now
   zip_file = './tmp/Attachments' + '-' + (bdate.strftime('%Y%m%d%H%M%S') + '.zip')
   Zip::File.open(zip_file, Zip::File::CREATE) do |zipfile|
```
