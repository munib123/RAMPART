# CrossVul Fix Pair: Insufficient Verification of Data Authenticity in javascript
**Pair ID:** 1948_0
**Vulnerability Class:** Insufficient Verification of Data Authenticity
**CWE:** CWE-345
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1948_0`)

## Vulnerability Information & PoC

## Description
Insufficient Verification of Data Authenticity - The product does not sufficiently verify the origin or authenticity of data, in a way that causes it to accept invalid data.

## Vulnerable Code
```javascript
Lines 271-311 of the vulnerable file.

                    // only auto-download if a user triggered this iframe explicitly
                    auto: !this.props.decryptedBlob,
                }, "*");
            };

            const url = "usercontent/"; // XXX: this path should probably be passed from the skin

            // If the attachment is encrypted then put the link inside an iframe.
            return (
                <span className="mx_MFileBody">
                    <div className="mx_MFileBody_download">
                        <div style={{display: "none"}}>
                            { /*
                              * Add dummy copy of the "a" tag
                              * We'll use it to learn how the download link
                              * would have been styled if it was rendered inline.
                              */ }
                            <a ref={this._dummyLink} />
                        </div>
                        <iframe
                            src={`${url}?origin=${encodeURIComponent(window.location.origin)}`}
                            onLoad={onIframeLoad}
                            ref={this._iframe}
                            sandbox="allow-scripts allow-downloads allow-downloads-without-user-activation" />
                    </div>
                </span>
            );
        } else if (contentUrl) {
            const downloadProps = {
                target: "_blank",
                rel: "noreferrer noopener",

                // We set the href regardless of whether or not we intercept the download
                // because we don't really want to convert the file to a blob eagerly, and
                // still want "open in new tab" and "save link as" to work.
                href: contentUrl,
            };

            // Blobs can only have up to 500mb, so if the file reports as being too large then
            // we won't try and convert it. Likewise, if the file size is unknown then we'll assume
            // it is too big. There is the risk of the reported file size and the actual file size
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -288,7 +288,7 @@
                             <a ref={this._dummyLink} />
                         </div>
                         <iframe
-                            src={`${url}?origin=${encodeURIComponent(window.location.origin)}`}
+                            src={url}
                             onLoad={onIframeLoad}
                             ref={this._iframe}
                             sandbox="allow-scripts allow-downloads allow-downloads-without-user-activation" />
```
