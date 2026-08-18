# CrossVul Fix Pair: Server-Side Request Forgery (SSRF) in csharp
**Pair ID:** 2506_2
**Vulnerability Class:** Server-Side Request Forgery (SSRF)
**CWE:** CWE-918
**Language:** csharp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2506_2`)

## Vulnerability Information & PoC

## Description
Server-Side Request Forgery (SSRF) - By providing URLs to unexpected hosts or ports, attackers can make it appear that the server is sending the request, possibly bypassing access controls such as firewalls that prevent the attackers ...

## Vulnerable Code
```csharp
Lines 409-449 of the vulnerable file.


        private void RenderImage(Image image, Stream outStream)
        {
            try
            {
                if (ContentType == ImageFormat.Gif)
                {
                    var quantizer = new OctreeQuantizer(255, 8);
                    using (var quantized = quantizer.Quantize(image))
                    {
                        quantized.Save(outStream, ImageFormat.Gif);
                    }
                }
                else
                {
                    var eps = new EncoderParameters(1)
                    {
                        Param = { [0] = new EncoderParameter(System.Drawing.Imaging.Encoder.Quality, ImageCompression) }
                    };
                    var ici = GetEncoderInfo(GetImageMimeType(ContentType));
                    image.Save(outStream, ici, eps);
                }
            }
            finally
            {
                image?.Dispose();
            }
        }

        /// <summary>
        /// Returns the encoder for the specified mime type
        /// </summary>
        /// <param name="mimeType">The mime type of the content</param>
        /// <returns>ImageCodecInfo</returns>
        private static ImageCodecInfo GetEncoderInfo(string mimeType)
        {
            var encoders = ImageCodecInfo.GetImageEncoders();
            var e = encoders.FirstOrDefault(x => x.MimeType == mimeType);
            return e;
        }
    }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -426,7 +426,7 @@
                         Param = { [0] = new EncoderParameter(System.Drawing.Imaging.Encoder.Quality, ImageCompression) }
                     };
                     var ici = GetEncoderInfo(GetImageMimeType(ContentType));
-                    image.Save(outStream, ici, eps);
+                    image?.Save(outStream, ici, eps);
                 }
             }
             finally
```
