# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in javascript
**Pair ID:** 1905_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1905_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```javascript
Lines 55-95 of the vulnerable file.

}
const slides = RevealMarkdown.slidify(body, slideOptions)
$('.slides').html(slides)
RevealMarkdown.initialize()
removeDOMEvents($('.slides'))
$('.slides').show()

// default options to init reveal.js
const defaultOptions = {
  controls: true,
  progress: true,
  slideNumber: true,
  history: true,
  center: true,
  transition: 'none',
  dependencies: deps
}

// options from yaml meta
const meta = JSON.parse($('#meta').text())
var options = meta.slideOptions || {}

const view = $('.reveal')

// text language
if (meta.lang && typeof meta.lang === 'string') {
  view.attr('lang', meta.lang)
} else {
  view.removeAttr('lang')
}
// text direction
if (meta.dir && typeof meta.dir === 'string' && meta.dir === 'rtl') {
  options.rtl = true
} else {
  options.rtl = false
}
// breaks
if (typeof meta.breaks === 'boolean' && !meta.breaks) {
  md.options.breaks = false
} else {
  md.options.breaks = true
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -72,7 +72,56 @@
 
 // options from yaml meta
 const meta = JSON.parse($('#meta').text())
-var options = meta.slideOptions || {}
+var options = {
+  autoPlayMedia: meta.slideOptions.autoPlayMedia,
+  autoSlide: meta.slideOptions.autoSlide,
+  autoSlideStoppable: meta.slideOptions.autoSlideStoppable,
+  backgroundTransition: meta.slideOptions.backgroundTransition,
+  center: meta.slideOptions.center,
+  controls: meta.slideOptions.controls,
+  controlsBackArrows: meta.slideOptions.controlsBackArrows,
+  controlsLayout: meta.slideOptions.controlsLayout,
+  controlsTutorial: meta.slideOptions.controlsTutorial,
+  defaultTiming: meta.slideOptions.defaultTiming,
+  display: meta.slideOptions.display,
+  embedded: meta.slideOptions.embedded,
+  fragmentInURL: meta.slideOptions.fragmentInURL,
+  fragments: meta.slideOptions.fragments,
+  hash: meta.slideOptions.hash,
+  height: meta.slideOptions.height,
+  help: meta.slideOptions.help,
+  hideAddressBar: meta.slideOptions.hideAddressBar,
+  hideCursorTime: meta.slideOptions.hideCursorTime,
+  hideInactiveCursor: meta.slideOptions.hideInactiveCursor,
+  history: meta.slideOptions.history,
+  keyboard: meta.slideOptions.keyboard,
+  loop: meta.slideOptions.loop,
+  margin: meta.slideOptions.margin,
+  maxScale: meta.slideOptions.maxScale,
+  minScale: meta.slideOptions.minScale,
+  minimumTimePerSlide: meta.slideOptions.minimumTimePerSlide,
+  mobileViewDistance: meta.slideOptions.mobileViewDistance,
+  mouseWheel: meta.slideOptions.mouseWheel,
+  navigationMode: meta.slideOptions.navigationMode,
+  overview: meta.slideOptions.overview,
+  parallaxBackgroundHorizontal: meta.slideOptions.parallaxBackgroundHorizontal,
+  parallaxBackgroundImage: meta.slideOptions.parallaxBackgroundImage,
+  parallaxBackgroundSize: meta.slideOptions.parallaxBackgroundSize,
+  parallaxBackgroundVertical: meta.slideOptions.parallaxBackgroundVertical,
+  preloadIframes: meta.slideOptions.preloadIframes,
+  previewLinks: meta.slideOptions.previewLinks,
+  progress: meta.slideOptions.progress,
+  rtl: meta.slideOptions.rtl,
+  showNotes: meta.slideOptions.showNotes,
+  shuffle: meta.slideOptions.shuffle,
+  slideNumber: meta.slideOptions.slideNumber,
+  totalTime: meta.slideOptions.totalTime,
+  touch: meta.slideOptions.touch,
+  transition: meta.slideOptions.transition,
+  transitionSpeed: meta.slideOptions.transitionSpeed,
+  viewDistance: meta.slideOptions.viewDistance,
+  width: meta.slideOptions.width
+} || {}
 
 const view = $('.reveal')
 
```
