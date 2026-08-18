# CrossVul Fix Pair: Off-by-one Error in c
**Pair ID:** 4732_1
**Vulnerability Class:** Off-by-one Error
**CWE:** CWE-193
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4732_1`)

## Vulnerability Information & PoC

## Description
Off-by-one Error - A product calculates or uses an incorrect maximum or minimum value that is 1 more, or 1 less, than the correct value.

## Vulnerable Code
```c
Lines 1247-1287 of the vulnerable file.

}

bool radeon_atom_get_tv_timings(struct radeon_device *rdev, int index,
				struct drm_display_mode *mode)
{
	struct radeon_mode_info *mode_info = &rdev->mode_info;
	ATOM_ANALOG_TV_INFO *tv_info;
	ATOM_ANALOG_TV_INFO_V1_2 *tv_info_v1_2;
	ATOM_DTD_FORMAT *dtd_timings;
	int data_index = GetIndexIntoMasterTable(DATA, AnalogTV_Info);
	u8 frev, crev;
	u16 data_offset, misc;

	if (!atom_parse_data_header(mode_info->atom_context, data_index, NULL,
				    &frev, &crev, &data_offset))
		return false;

	switch (crev) {
	case 1:
		tv_info = (ATOM_ANALOG_TV_INFO *)(mode_info->atom_context->bios + data_offset);
		if (index > MAX_SUPPORTED_TV_TIMING)
			return false;

		mode->crtc_htotal = le16_to_cpu(tv_info->aModeTimings[index].usCRTC_H_Total);
		mode->crtc_hdisplay = le16_to_cpu(tv_info->aModeTimings[index].usCRTC_H_Disp);
		mode->crtc_hsync_start = le16_to_cpu(tv_info->aModeTimings[index].usCRTC_H_SyncStart);
		mode->crtc_hsync_end = le16_to_cpu(tv_info->aModeTimings[index].usCRTC_H_SyncStart) +
			le16_to_cpu(tv_info->aModeTimings[index].usCRTC_H_SyncWidth);

		mode->crtc_vtotal = le16_to_cpu(tv_info->aModeTimings[index].usCRTC_V_Total);
		mode->crtc_vdisplay = le16_to_cpu(tv_info->aModeTimings[index].usCRTC_V_Disp);
		mode->crtc_vsync_start = le16_to_cpu(tv_info->aModeTimings[index].usCRTC_V_SyncStart);
		mode->crtc_vsync_end = le16_to_cpu(tv_info->aModeTimings[index].usCRTC_V_SyncStart) +
			le16_to_cpu(tv_info->aModeTimings[index].usCRTC_V_SyncWidth);

		mode->flags = 0;
		misc = le16_to_cpu(tv_info->aModeTimings[index].susModeMiscInfo.usAccess);
		if (misc & ATOM_VSYNC_POLARITY)
			mode->flags |= DRM_MODE_FLAG_NVSYNC;
		if (misc & ATOM_HSYNC_POLARITY)
			mode->flags |= DRM_MODE_FLAG_NHSYNC;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1264,7 +1264,7 @@
 	switch (crev) {
 	case 1:
 		tv_info = (ATOM_ANALOG_TV_INFO *)(mode_info->atom_context->bios + data_offset);
-		if (index > MAX_SUPPORTED_TV_TIMING)
+		if (index >= MAX_SUPPORTED_TV_TIMING)
 			return false;
 
 		mode->crtc_htotal = le16_to_cpu(tv_info->aModeTimings[index].usCRTC_H_Total);
@@ -1302,7 +1302,7 @@
 		break;
 	case 2:
 		tv_info_v1_2 = (ATOM_ANALOG_TV_INFO_V1_2 *)(mode_info->atom_context->bios + data_offset);
-		if (index > MAX_SUPPORTED_TV_TIMING_V1_2)
+		if (index >= MAX_SUPPORTED_TV_TIMING_V1_2)
 			return false;
 
 		dtd_timings = &tv_info_v1_2->aModeTimings[index];
```
