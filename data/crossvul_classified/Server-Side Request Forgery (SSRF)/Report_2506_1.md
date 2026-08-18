# CrossVul Fix Pair: Server-Side Request Forgery (SSRF) in csharp
**Pair ID:** 2506_1
**Vulnerability Class:** Server-Side Request Forgery (SSRF)
**CWE:** CWE-918
**Language:** csharp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2506_1`)

## Vulnerability Information & PoC

## Description
Server-Side Request Forgery (SSRF) - By providing URLs to unexpected hosts or ports, attackers can make it appear that the server is sending the request, possibly bypassing access controls such as firewalls that prevent the attackers ...

## Vulnerable Code
```csharp
Lines 96-136 of the vulnerable file.


		/// <summary>
		/// Sets the Backcolor 
		/// </summary>
		public Color BackColor { get; set; } = Color.White;

        public ImageResizeTransform() {
            InterpolationMode = InterpolationMode.HighQualityBicubic;
            SmoothingMode = SmoothingMode.HighQuality;
            PixelOffsetMode = PixelOffsetMode.HighQuality;
            CompositingQuality = CompositingQuality.HighQuality;
			Mode = ImageResizeMode.Fit;
		}

        /// <summary>
        /// Processes an input image applying a resize image transformation
        /// </summary>
        /// <param name="image">Input image</param>
        /// <returns>Image result after image transformation</returns>
        public override Image ProcessImage(Image image)
		{
            if (MaxWidth > 0)
            {
                Width = image.Width > MaxWidth ? MaxWidth : image.Width;
            }

            if (MaxHeight > 0)
            {
                Height = image.Height > MaxHeight ? MaxHeight : image.Height;
            }

            int scaledHeight = (int)(image.Height * ((float)Width / (float)image.Width));
			int scaledWidth = (int)(image.Width * ((float)Height / (float)image.Height));

			Image procImage;
			switch (Mode) {
				case ImageResizeMode.Fit:
					procImage = FitImage(image, scaledHeight, scaledWidth);
					break;
				case ImageResizeMode.Crop:
					procImage = CropImage(image, scaledHeight, scaledWidth);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -113,7 +113,10 @@
         /// <param name="image">Input image</param>
         /// <returns>Image result after image transformation</returns>
         public override Image ProcessImage(Image image)
-		{
+        {
+            if (image == null)
+                return null;    
+
             if (MaxWidth > 0)
             {
                 Width = image.Width > MaxWidth ? MaxWidth : image.Width;
```
