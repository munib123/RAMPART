# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in ruby
**Pair ID:** 5534_1
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5534_1`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```ruby
Lines 29-69 of the vulnerable file.

    params = Rack::Multipart.parse_multipart(env)
    params["text"].should.equal "contents"
  end

  should "raise RangeError if the key space is exhausted" do
    env = Rack::MockRequest.env_for("/", multipart_fixture(:content_type_and_no_filename))

    old, Rack::Utils.key_space_limit = Rack::Utils.key_space_limit, 1
    begin
      lambda { Rack::Multipart.parse_multipart(env) }.should.raise(RangeError)
    ensure
      Rack::Utils.key_space_limit = old
    end
  end

  should "parse multipart form webkit style" do
    env = Rack::MockRequest.env_for '/', multipart_fixture(:webkit)
    env['CONTENT_TYPE'] = "multipart/form-data; boundary=----WebKitFormBoundaryWLHCs9qmcJJoyjKR"
    params = Rack::Multipart.parse_multipart(env)
    params['profile']['bio'].should.include 'hello'
  end

  should "parse multipart upload with text file" do
    env = Rack::MockRequest.env_for("/", multipart_fixture(:text))
    params = Rack::Multipart.parse_multipart(env)
    params["submit-name"].should.equal "Larry"
    params["submit-name-with-content"].should.equal "Berry"
    params["files"][:type].should.equal "text/plain"
    params["files"][:filename].should.equal "file1.txt"
    params["files"][:head].should.equal "Content-Disposition: form-data; " +
      "name=\"files\"; filename=\"file1.txt\"\r\n" +
      "Content-Type: text/plain\r\n"
    params["files"][:name].should.equal "files"
    params["files"][:tempfile].read.should.equal "contents"
  end

  should "parse multipart upload with nested parameters" do
    env = Rack::MockRequest.env_for("/", multipart_fixture(:nested))
    params = Rack::Multipart.parse_multipart(env)
    params["foo"]["submit-name"].should.equal "Larry"
    params["foo"]["files"][:type].should.equal "text/plain"
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -46,6 +46,59 @@
     env['CONTENT_TYPE'] = "multipart/form-data; boundary=----WebKitFormBoundaryWLHCs9qmcJJoyjKR"
     params = Rack::Multipart.parse_multipart(env)
     params['profile']['bio'].should.include 'hello'
+  end
+
+  should "reject insanely long boundaries" do
+    # using a pipe since a tempfile can use up too much space
+    rd, wr = IO.pipe
+
+    # we only call rewind once at start, so make sure it succeeds
+    # and doesn't hit ESPIPE
+    def rd.rewind; end
+    wr.sync = true
+
+    # mock out length to make this pipe look like a Tempfile
+    def rd.length
+      1024 * 1024 * 8
+    end
+
+    # write to a pipe in a background thread, this will write a lot
+    # unless Rack (properly) shuts down the read end
+    thr = Thread.new do
+      begin
+        wr.write("--AaB03x")
+
+        # make the initial boundary a few gigs long
+        longer = "0123456789" * 1024 * 1024
+        (1024 * 1024).times { wr.write(longer) }
+
+        wr.write("\r\n")
+        wr.write('Content-Disposition: form-data; name="a"; filename="a.txt"')
+        wr.write("\r\n")
+        wr.write("Content-Type: text/plain\r\n")
+        wr.write("\r\na")
+        wr.write("--AaB03x--\r\n")
+        wr.close
+      rescue => err # this is EPIPE if Rack shuts us down
+        err
+      end
+    end
+
+    fixture = {
+      "CONTENT_TYPE" => "multipart/form-data; boundary=AaB03x",
+      "CONTENT_LENGTH" => rd.length.to_s,
+      :input => rd,
+    }
+
+    env = Rack::MockRequest.env_for '/', fixture
+    lambda {
+      Rack::Multipart.parse_multipart(env)
+    }.should.raise(EOFError)
+    rd.close
+
+    err = thr.value
+    err.should.be.instance_of Errno::EPIPE
+    wr.close
   end
 
   should "parse multipart upload with text file" do
```
