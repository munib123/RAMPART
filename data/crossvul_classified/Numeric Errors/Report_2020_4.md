# CrossVul Fix Pair: Numeric Errors in c
**Pair ID:** 2020_4
**Vulnerability Class:** Numeric Errors
**CWE:** CWE-189
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2020_4`)

## Vulnerability Information & PoC

## Description
Numeric Errors

## Vulnerable Code
```c
Lines 431-471 of the vulnerable file.

	QUERYTYPE  *query = PG_GETARG_QUERYTYPE_P(1);
	CHKVAL		chkval;
	bool		result;

	CHECKARRVALID(val);
	PREPAREARR(val);
	chkval.arrb = ARRPTR(val);
	chkval.arre = chkval.arrb + ARRNELEMS(val);
	result = execute(GETQUERY(query) + query->size - 1,
					 &chkval, true,
					 checkcondition_arr);
	pfree(val);

	PG_FREE_IF_COPY(query, 1);
	PG_RETURN_BOOL(result);
}

static void
findoprnd(ITEM *ptr, int32 *pos)
{
#ifdef BS_DEBUG
	elog(DEBUG3, (ptr[*pos].type == OPR) ?
		 "%d  %c" : "%d  %d", *pos, ptr[*pos].val);
#endif
	if (ptr[*pos].type == VAL)
	{
		ptr[*pos].left = 0;
		(*pos)--;
	}
	else if (ptr[*pos].val == (int32) '!')
	{
		ptr[*pos].left = -1;
		(*pos)--;
		findoprnd(ptr, pos);
	}
	else
	{
		ITEM	   *curitem = &ptr[*pos];
		int32		tmp = *pos;

		(*pos)--;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -448,6 +448,9 @@
 static void
 findoprnd(ITEM *ptr, int32 *pos)
 {
+	/* since this function recurses, it could be driven to stack overflow. */
+	check_stack_depth();
+
 #ifdef BS_DEBUG
 	elog(DEBUG3, (ptr[*pos].type == OPR) ?
 		 "%d  %c" : "%d  %d", *pos, ptr[*pos].val);
@@ -508,7 +511,13 @@
 				(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
 				 errmsg("empty query")));
 
+	if (state.num > QUERYTYPEMAXITEMS)
+		ereport(ERROR,
+				(errcode(ERRCODE_PROGRAM_LIMIT_EXCEEDED),
+		errmsg("number of query items (%d) exceeds the maximum allowed (%d)",
+			   state.num, (int) QUERYTYPEMAXITEMS)));
 	commonlen = COMPUTESIZE(state.num);
+
 	query = (QUERYTYPE *) palloc(commonlen);
 	SET_VARSIZE(query, commonlen);
 	query->size = state.num;
```
