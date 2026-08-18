# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in ruby
**Pair ID:** 4724_0
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4724_0`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```ruby
Lines 5-45 of the vulnerable file.

#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


require File.join("chef", "webui_user")

class Users < Application
  provides :json

  before :authenticate_every

  # GET to /users
  def index
    @user_list = Chef::WebUIUser.cdb_list
    display(@user_list.inject({}) { |r,n| r[n] = absolute_url(:user, n); r })
  end

  # GET to /users/:id
  def show
    begin
      @user = Chef::WebUIUser.cdb_load(params[:id])
    rescue Chef::Exceptions::CouchDBNotFound => e
      raise NotFound, "Cannot load user #{params[:id]}"
    end
    display @user
  end

  # PUT to /users/:id
  def update
    begin
      Chef::WebUIUser.cdb_load(params[:id])
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -22,6 +22,7 @@
   provides :json
 
   before :authenticate_every
+  before :is_admin, :only => [ :create, :destroy, :update ]
 
   # GET to /users
   def index
```
