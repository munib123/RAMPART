# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 4474_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4474_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 955-995 of the vulnerable file.

                                <input id="envira-config-crop-width" type="number" name="_envira_gallery[crop_width]" value="<?php echo $this->get_config( 'crop_width', $this->get_config_default( 'crop_width' ) ); ?>" /> &#215; <input id="envira-config-crop-height" type="number" name="_envira_gallery[crop_height]" value="<?php echo $this->get_config( 'crop_height', $this->get_config_default( 'crop_height' ) ); ?>" /> <span class="envira-unit"><?php _e( 'px', 'envira-gallery-lite' ); ?></span>
                                <p class="description"><?php _e( 'You should adjust these dimensions based on the number of columns in your gallery. This does not affect the full size lightbox images.', 'envira-gallery-lite' ); ?></p>
                            </td>
                        </tr>
                        <tr id="envira-config-crop-box">
                            <th scope="row">
                                <label for="envira-config-crop"><?php _e( 'Crop Images?', 'envira-gallery-lite' ); ?></label>
                            </th>
                            <td>
                                <input id="envira-config-crop" type="checkbox" name="_envira_gallery[crop]" value="<?php echo $this->get_config( 'crop', $this->get_config_default( 'crop' ) ); ?>" <?php checked( $this->get_config( 'crop', $this->get_config_default( 'crop' ) ), 1 ); ?> />
                                <span class="description"><?php _e( 'If enabled, forces images to exactly match the sizes defined above for Image Dimensions and Mobile Dimensions.', 'envira-gallery-lite' ); ?></span>
                                <span class="description"><?php _e( 'If disabled, images will be resized to maintain their aspect ratio.', 'envira-gallery-lite' ); ?></span>

                            </td>
                        </tr>
                    </tbody>
	            </table>

        </div>
        </div>
        <?php 

        // Output an upgrade notice
        Envira_Gallery_Notice_Admin::get_instance()->display_inline_notice(
            'envira_gallery_images_tab',
            __( '' ),
            __( '<h2 style="margin: -10px 0 0 0; font-weight: 600; font-size: 21px; padding: 0;">Improve Your Galleries With Our Premium Addons:</h2>
            <div class="two-column-list">
            <ul>
                <li><a target="_blank" href="' . Envira_Gallery_Common_Admin::get_instance()->get_upgrade_link( 'https://enviragallery.com/customize-your-envira-galleries-with-new-gallery-layouts', 'adminpageconfig', 'customgallerythemes' ) . '">Custom Gallery Themes</a></li>
                <li><a target="_blank" href="' . Envira_Gallery_Common_Admin::get_instance()->get_upgrade_link( 'https://enviragallery.com/how-to-optimize-image-galleries-for-mobile-using-envira-gallery/', 'adminpageconfig', 'mobileoptimizedgalleries' ) . '">Mobile Optimized Galleries</a></li>
                <li><a target="_blank" href="' . Envira_Gallery_Common_Admin::get_instance()->get_upgrade_link( 'https://enviragallery.com/how-to-upload-photos-directly-from-lightroom-to-wordpress/', 'adminpageconfig', 'adobelightroomintegration' ) . '">Adobe Lightroom Integration</a></li>
            </ul>
            <ul>
                <li><a target="_blank" href="' . Envira_Gallery_Common_Admin::get_instance()->get_upgrade_link( 'https://enviragallery.com/how-to-sell-your-photos-in-wordpress/', 'adminpageconfig', 'woocommerceintegration' ) . '">Woocommerce Integration</a></li>
                <li><a target="_blank" href="' . Envira_Gallery_Common_Admin::get_instance()->get_upgrade_link( 'https://enviragallery.com/how-to-protect-your-website-from-image-theft/', 'adminpageconfig', 'imageprotection' ) . '">Image Protection</a></li>
                <li><a target="_blank" href="' . Envira_Gallery_Common_Admin::get_instance()->get_upgrade_link( 'https://enviragallery.com/lite/', 'adminpageconfig', 'prioritytechnicalsupport' ) . '">Priority Technical Support</a></li>
            </ul>
... (excerpt truncated)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -972,7 +972,7 @@
 
         </div>
         </div>
-        <?php 
+        <?php
 
         // Output an upgrade notice
         Envira_Gallery_Notice_Admin::get_instance()->display_inline_notice(
@@ -1164,7 +1164,7 @@
                             <label for="envira-config-title"><?php _e( 'Gallery Title', 'envira-gallery-lite' ); ?></label>
                         </th>
                         <td>
-                            <input id="envira-config-title" type="text" name="_envira_gallery[title]" value="<?php echo $this->get_config( 'title', $this->get_config_default( 'title' ) ); ?>" />
+                            <input id="envira-config-title" type="text" name="_envira_gallery[title]" value="<?php echo esc_html( $this->get_config( 'title', $this->get_config_default( 'title' ) ) ); ?>" />
                             <p class="description"><?php _e( 'Internal gallery title for identification in the admin.', 'envira-gallery-lite' ); ?></p>
                         </td>
                     </tr>
@@ -1321,7 +1321,7 @@
 		</div>
 
 		<?php
-				
+
     }
 
     /**
```
