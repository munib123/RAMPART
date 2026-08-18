# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in ruby
**Pair ID:** 3560_0
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3560_0`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```ruby
Lines 13-53 of the vulnerable file.

#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

require 'chef/cookbook_loader'
require 'chef/cookbook/metadata'

class Cookbooks < Application

  include Merb::CookbookVersionHelper

  provides :json

  before :authenticate_every
  before :params_helper

  attr_accessor :cookbook_name, :cookbook_version

  def params_helper
    self.cookbook_name = params[:cookbook_name]
    self.cookbook_version = params[:cookbook_version]
  end

  include Chef::Mixin::Checksum
  include Merb::TarballHelper

  def index
    if request.env['HTTP_X_CHEF_VERSION'] =~ /0\.9/
      index_09
    else
      index_010
    end
  end

  # GET /cookbooks
  # returns data in the format of:
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -30,6 +30,7 @@
 
   before :authenticate_every
   before :params_helper
+  before :is_admin, :only => [ :update, :destroy ]
 
   attr_accessor :cookbook_name, :cookbook_version
 
```
