# CrossVul Fix Pair: Improper Neutralization of Special Elements used in a Command ('Command Injection') in c
**Pair ID:** 709_1
**Vulnerability Class:** Command Injection - Generic
**CWE:** CWE-77
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `709_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in a Command ('Command Injection') - Command injection vulnerabilities typically occur when: 1.

## Vulnerable Code
```c
Lines 1-31 of the vulnerable file.

#include "OpenCV.h"

#ifdef HAVE_OPENCV_FACE

#if CV_MAJOR_VERSION >= 3
#include <opencv2/face.hpp>
namespace cv {
  using cv::face::FaceRecognizer;
}
#else
#include "opencv2/contrib/contrib.hpp"
#endif

class FaceRecognizerWrap: public Nan::ObjectWrap {
public:
  cv::Ptr<cv::FaceRecognizer> rec;
  int typ;

  static Nan::Persistent<FunctionTemplate> constructor;
  static void Init(Local<Object> target);
  static NAN_METHOD(New);

  FaceRecognizerWrap(cv::Ptr<cv::FaceRecognizer> f, int type);

  JSFUNC(CreateLBPH)
  JSFUNC(CreateEigen)
  JSFUNC(CreateFisher)

  JSFUNC(TrainSync)
  JSFUNC(Train)
  JSFUNC(UpdateSync)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -8,6 +8,7 @@
   using cv::face::FaceRecognizer;
 }
 #else
+#warning using opencv2 contrib
 #include "opencv2/contrib/contrib.hpp"
 #endif
 
```
