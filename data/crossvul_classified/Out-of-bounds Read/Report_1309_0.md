# CrossVul Fix Pair: Out-of-bounds Read in cpp
**Pair ID:** 1309_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1309_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```cpp
Lines 123-163 of the vulnerable file.

    Mat_<float> I0yy_buf; //!< sum of squares of y gradient values
    Mat_<float> I0xy_buf; //!< sum of x and y gradient products

    /* Extra buffers that are useful if patch mean-normalization is used: */
    Mat_<float> I0x_buf; //!< sum of x gradient values
    Mat_<float> I0y_buf; //!< sum of y gradient values

    /* Auxiliary buffers used in structure tensor computation: */
    Mat_<float> I0xx_buf_aux;
    Mat_<float> I0yy_buf_aux;
    Mat_<float> I0xy_buf_aux;
    Mat_<float> I0x_buf_aux;
    Mat_<float> I0y_buf_aux;

    vector<Ptr<VariationalRefinement> > variational_refinement_processors;

  private: //!< private methods and parallel sections
    void prepareBuffers(Mat &I0, Mat &I1, Mat &flow, bool use_flow);
    void precomputeStructureTensor(Mat &dst_I0xx, Mat &dst_I0yy, Mat &dst_I0xy, Mat &dst_I0x, Mat &dst_I0y, Mat &I0x,
                                   Mat &I0y);

    struct PatchInverseSearch_ParBody : public ParallelLoopBody
    {
        DISOpticalFlowImpl *dis;
        int nstripes, stripe_sz;
        int hs;
        Mat *Sx, *Sy, *Ux, *Uy, *I0, *I1, *I0x, *I0y;
        int num_iter, pyr_level;

        PatchInverseSearch_ParBody(DISOpticalFlowImpl &_dis, int _nstripes, int _hs, Mat &dst_Sx, Mat &dst_Sy,
                                   Mat &src_Ux, Mat &src_Uy, Mat &_I0, Mat &_I1, Mat &_I0x, Mat &_I0y, int _num_iter,
                                   int _pyr_level);
        void operator()(const Range &range) const CV_OVERRIDE;
    };

    struct Densification_ParBody : public ParallelLoopBody
    {
        DISOpticalFlowImpl *dis;
        int nstripes, stripe_sz;
        int h;
        Mat *Ux, *Uy, *Sx, *Sy, *I0, *I1;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -140,6 +140,8 @@
     void prepareBuffers(Mat &I0, Mat &I1, Mat &flow, bool use_flow);
     void precomputeStructureTensor(Mat &dst_I0xx, Mat &dst_I0yy, Mat &dst_I0xy, Mat &dst_I0x, Mat &dst_I0y, Mat &I0x,
                                    Mat &I0y);
+    int autoSelectCoarsestScale(int img_width);
+    void autoSelectPatchSizeAndScales(int img_width);
 
     struct PatchInverseSearch_ParBody : public ParallelLoopBody
     {
@@ -432,6 +434,44 @@
             }
             is++;
         }
+    }
+}
+
+int DISOpticalFlowImpl::autoSelectCoarsestScale(int img_width)
+{
+    const int fratio = 5;
+    return std::max(0, (int)std::floor(log2((2.0f*(float)img_width) / ((float)fratio * (float)patch_size))));
+}
+
+void DISOpticalFlowImpl::autoSelectPatchSizeAndScales(int img_width)
+{
+    switch (finest_scale)
+    {
+    case 1:
+        patch_size = 8;
+        coarsest_scale = autoSelectCoarsestScale(img_width);
+        finest_scale = std::max(coarsest_scale-2, 0);
+        break;
+
+    case 3:
+        patch_size = 12;
+        coarsest_scale = autoSelectCoarsestScale(img_width);
+        finest_scale = std::max(coarsest_scale-4, 0);
+        break;
+
+    case 4:
+        patch_size = 12;
+        coarsest_scale = autoSelectCoarsestScale(img_width);
+        finest_scale = std::max(coarsest_scale-5, 0);
+        break;
+
+    // default case, fall-through.
+    case 2:
+    default:
+        patch_size = 8;
+        coarsest_scale = autoSelectCoarsestScale(img_width);
+        finest_scale = std::max(coarsest_scale-2, 0);
+        break;
     }
 }
 
@@ -1318,8 +1358,19 @@
     else
         flow.create(I1Mat.size(), CV_32FC2);
     UMat &u_flowMat = flow.getUMatRef();
-    coarsest_scale = min((int)(log(max(I0Mat.cols, I0Mat.rows) / (4.0 * patch_size)) / log(2.0) + 0.5), /* Original code serach for maximal movement of width/4 */
+    coarsest_scale = min((int)(log(max(I0Mat.cols, I0Mat.rows) / (4.0 * patch_size)) / log(2.0) + 0.5), /* Original code search for maximal movement of width/4 */
                          (int)(log(min(I0Mat.cols, I0Mat.rows) / patch_size) / log(2.0)));              /* Deepest pyramid level greater or equal than patch*/
+
+    if (coarsest_scale<0)
+        CV_Error(cv::Error::StsBadSize, "The input image must have either width or height >= 12");
+
+    if (coarsest_scale<finest_scale)
+    {
+        // choose the finest level based on coarsest level.
+        // Refs: https://github.com/tikroeger/OF_DIS/blob/2c9f2a674f3128d3a41c10e41cc9f3a35bb1b523/run_dense.cpp#L239
+        int original_img_width = I0.size().width;
+        autoSelectPatchSizeAndScales(original_img_width);
+    }
 
     ocl_prepareBuffers(I0Mat, I1Mat, u_flowMat, use_input_flow);
     u_Ux[coarsest_scale].setTo(0.0f);
@@ -1385,8 +1436,20 @@
     else
         flow.create(I1Mat.size(), CV_32FC2);
     Mat flowMat = flow.getMat();
-    coarsest_scale = min((int)(log(max(I0Mat.cols, I0Mat.rows) / (4.0 * patch_size)) / log(2.0) + 0.5), /* Original code serach for maximal movement of width/4 */
+    coarsest_scale = min((int)(log(max(I0Mat.cols, I0Mat.rows) / (4.0 * patch_size)) / log(2.0) + 0.5), /* Original code search for maximal movement of width/4 */
                          (int)(log(min(I0Mat.cols, I0Mat.rows) / patch_size) / log(2.0)));              /* Deepest pyramid level greater or equal than patch*/
+
+    if (coarsest_scale<0)
+        CV_Error(cv::Error::StsBadSize, "The input image must have either width or height >= 12");
+
+    if (coarsest_scale<finest_scale)
+    {
+        // choose the finest level based on coarsest level.
+        // Refs: https://github.com/tikroeger/OF_DIS/blob/2c9f2a674f3128d3a41c10e41cc9f3a35bb1b523/run_dense.cpp#L239
+        int original_img_width = I0.size().width;
+        autoSelectPatchSizeAndScales(original_img_width);
+    }
+
     int num_stripes = getNumThreads();
 
     prepareBuffers(I0Mat, I1Mat, flowMat, use_input_flow);
```
