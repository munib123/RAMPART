# CrossVul Fix Pair: Divide By Zero in c
**Pair ID:** 1009_0
**Vulnerability Class:** Divide By Zero
**CWE:** CWE-369
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1009_0`)

## Vulnerability Information & PoC

## Description
Divide By Zero - This weakness typically occurs when an unexpected value is provided to the product, or if an error occurs that is not properly detected.

## Vulnerable Code
```c
Lines 2301-2341 of the vulnerable file.


                status=GetOneCacheViewVirtualPixel(pixel_view,(ssize_t)
                  MagickRound(mean_location.x+u),(ssize_t) MagickRound(
                  mean_location.y+v),&pixel,exception);
                distance=(mean_pixel.red-pixel.red)*(mean_pixel.red-pixel.red)+
                  (mean_pixel.green-pixel.green)*(mean_pixel.green-pixel.green)+
                  (mean_pixel.blue-pixel.blue)*(mean_pixel.blue-pixel.blue);
                if (distance <= (color_distance*color_distance))
                  {
                    sum_location.x+=mean_location.x+u;
                    sum_location.y+=mean_location.y+v;
                    sum_pixel.red+=pixel.red;
                    sum_pixel.green+=pixel.green;
                    sum_pixel.blue+=pixel.blue;
                    sum_pixel.opacity+=pixel.opacity;
                    count++;
                  }
              }
          }
        }
        gamma=1.0/count;
        mean_location.x=gamma*sum_location.x;
        mean_location.y=gamma*sum_location.y;
        mean_pixel.red=gamma*sum_pixel.red;
        mean_pixel.green=gamma*sum_pixel.green;
        mean_pixel.blue=gamma*sum_pixel.blue;
        mean_pixel.opacity=gamma*sum_pixel.opacity;
        distance=(mean_location.x-previous_location.x)*
          (mean_location.x-previous_location.x)+
          (mean_location.y-previous_location.y)*
          (mean_location.y-previous_location.y)+
          255.0*QuantumScale*(mean_pixel.red-previous_pixel.red)*
          255.0*QuantumScale*(mean_pixel.red-previous_pixel.red)+
          255.0*QuantumScale*(mean_pixel.green-previous_pixel.green)*
          255.0*QuantumScale*(mean_pixel.green-previous_pixel.green)+
          255.0*QuantumScale*(mean_pixel.blue-previous_pixel.blue)*
          255.0*QuantumScale*(mean_pixel.blue-previous_pixel.blue);
        if (distance <= 3.0)
          break;
      }
      q->red=ClampToQuantum(mean_pixel.red);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2318,7 +2318,7 @@
               }
           }
         }
-        gamma=1.0/count;
+        gamma=PerceptibleReciprocal(count);
         mean_location.x=gamma*sum_location.x;
         mean_location.y=gamma*sum_location.y;
         mean_pixel.red=gamma*sum_pixel.red;
```
