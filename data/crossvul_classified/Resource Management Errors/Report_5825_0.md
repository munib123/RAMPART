# CrossVul Fix Pair: Resource Management Errors in c
**Pair ID:** 5825_0
**Vulnerability Class:** Resource Management Errors
**CWE:** CWE-399
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5825_0`)

## Vulnerability Information & PoC

## Description
Resource Management Errors

## Vulnerable Code
```c
Lines 188-228 of the vulnerable file.

                double first_pts = s->start_time * AV_TIME_BASE;
                first_pts = FFMIN(FFMAX(first_pts, INT64_MIN), INT64_MAX);
                s->first_pts = s->pts = av_rescale_q(first_pts, AV_TIME_BASE_Q,
                                                     inlink->time_base);
                av_log(ctx, AV_LOG_VERBOSE, "Set first pts to (in:%"PRId64" out:%"PRId64")\n",
                       s->first_pts, av_rescale_q(first_pts, AV_TIME_BASE_Q,
                                                  outlink->time_base));
            } else {
                s->first_pts = s->pts = buf->pts;
            }
        } else {
            av_log(ctx, AV_LOG_WARNING, "Discarding initial frame(s) with no "
                   "timestamp.\n");
            av_frame_free(&buf);
            s->drop++;
        }
        return 0;
    }

    /* now wait for the next timestamp */
    if (buf->pts == AV_NOPTS_VALUE) {
        return write_to_fifo(s->fifo, buf);
    }

    /* number of output frames */
    delta = av_rescale_q_rnd(buf->pts - s->pts, inlink->time_base,
                             outlink->time_base, s->rounding);

    if (delta < 1) {
        /* drop the frame and everything buffered except the first */
        AVFrame *tmp;
        int drop = av_fifo_size(s->fifo)/sizeof(AVFrame*);

        av_log(ctx, AV_LOG_DEBUG, "Dropping %d frame(s).\n", drop);
        s->drop += drop;

        av_fifo_generic_read(s->fifo, &tmp, sizeof(tmp), NULL);
        flush_fifo(s->fifo);
        ret = write_to_fifo(s->fifo, tmp);

        av_frame_free(&buf);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -205,7 +205,7 @@
     }
 
     /* now wait for the next timestamp */
-    if (buf->pts == AV_NOPTS_VALUE) {
+    if (buf->pts == AV_NOPTS_VALUE || av_fifo_size(s->fifo) <= 0) {
         return write_to_fifo(s->fifo, buf);
     }
 
```
