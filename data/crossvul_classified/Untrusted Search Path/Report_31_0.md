# CrossVul Fix Pair: Untrusted Search Path in ruby
**Pair ID:** 31_0
**Vulnerability Class:** Untrusted Search Path
**CWE:** CWE-426
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `31_0`)

## Vulnerability Information & PoC

## Description
Untrusted Search Path - This might allow attackers to execute their own programs, access unauthorized data files, or modify configuration in unexpected ways.

## Vulnerable Code
```ruby
Lines 26-66 of the vulnerable file.

# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.#

module FFI
  CURRENT_PROCESS = USE_THIS_PROCESS_AS_LIBRARY = Object.new

  # @param [#to_s] lib library name
  # @return [String] library name formatted for current platform
  # Transform a generic library name to a platform library name
  # @example
  #  # Linux
  #  FFI.map_library_name 'c'     # -> "libc.so.6"
  #  FFI.map_library_name 'jpeg'  # -> "libjpeg.so"
  #  # Windows
  #  FFI.map_library_name 'c'     # -> "msvcrt.dll"
  #  FFI.map_library_name 'jpeg'  # -> "jpeg.dll"
  def self.map_library_name(lib)
    # Mangle the library name to reflect the native library naming conventions
    lib = lib.to_s unless lib.kind_of?(String)
    lib = Library::LIBC if lib == 'c'

    if lib && File.basename(lib) == lib
      lib = Platform::LIBPREFIX + lib unless lib =~ /^#{Platform::LIBPREFIX}/
      r = Platform::IS_GNU ? "\\.so($|\\.[1234567890]+)" : "\\.#{Platform::LIBSUFFIX}$"
      lib += ".#{Platform::LIBSUFFIX}" unless lib =~ /#{r}/
    end

    lib
  end

  # Exception raised when a function is not found in libraries
  class NotFoundError < LoadError
    def initialize(function, *libraries)
      super("Function '#{function}' not found in [#{libraries[0].nil? ? 'current process' : libraries.join(", ")}]")
    end
  end

  # This module is the base to use native functions.
  #
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -43,7 +43,6 @@
   #  FFI.map_library_name 'jpeg'  # -> "jpeg.dll"
   def self.map_library_name(lib)
     # Mangle the library name to reflect the native library naming conventions
-    lib = lib.to_s unless lib.kind_of?(String)
     lib = Library::LIBC if lib == 'c'
 
     if lib && File.basename(lib) == lib
@@ -103,7 +102,7 @@
           FFI::DynamicLibrary.open(nil, FFI::DynamicLibrary::RTLD_LAZY | FFI::DynamicLibrary::RTLD_LOCAL)
 
         else
-          libnames = (name.is_a?(::Array) ? name : [ name ]).map { |n| [ n, FFI.map_library_name(n) ].uniq }.flatten.compact
+          libnames = (name.is_a?(::Array) ? name : [ name ]).map(&:to_s).map { |n| [ n, FFI.map_library_name(n) ].uniq }.flatten.compact
           lib = nil
           errors = {}
 
@@ -126,7 +125,6 @@
                 retry
               else
                 # TODO better library lookup logic
-                libname = libname.to_s
                 unless libname.start_with?("/")
                   path = ['/usr/lib/','/usr/local/lib/'].find do |pth|
                     File.exist?(pth + libname)
```
