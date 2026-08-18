# CrossVul Fix Pair: Improper Control of Generation of Code ('Code Injection') in python
**Pair ID:** 4111_1
**Vulnerability Class:** Code Injection
**CWE:** CWE-94
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4111_1`)

## Vulnerability Information & PoC

## Description
Improper Control of Generation of Code ('Code Injection') - When a product allows a user's input to contain code syntax, it might be possible for an attacker to craft the code in such a way that it will alter the intended control flow of the product.

## Vulnerable Code
```python
Lines 1-28 of the vulnerable file.

""" A FastAPI app used to create an OpenAPI document for end-to-end testing """
import json
from datetime import date, datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Union

from fastapi import APIRouter, FastAPI, File, Header, Query, UploadFile
from pydantic import BaseModel

app = FastAPI(title="My Test API", description="An API for testing openapi-python-client",)


@app.get("/ping", response_model=bool)
async def ping():
    """ A quick check to see if the system is running """
    return True


test_router = APIRouter()


class AnEnum(Enum):
    """ For testing Enums in all the ways they can be used """

    FIRST_VALUE = "FIRST_VALUE"
    SECOND_VALUE = "SECOND_VALUE"

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -5,7 +5,7 @@
 from pathlib import Path
 from typing import Any, Dict, List, Union
 
-from fastapi import APIRouter, FastAPI, File, Header, Query, UploadFile
+from fastapi import APIRouter, Body, FastAPI, File, Header, Query, UploadFile
 from pydantic import BaseModel
 
 app = FastAPI(title="My Test API", description="An API for testing openapi-python-client",)
@@ -43,13 +43,15 @@
 
     an_enum_value: AnEnum
     nested_list_of_enums: List[List[DifferentEnum]] = []
-    some_dict: Dict[str, str] = {}
+    some_dict: Dict[str, str]
     aCamelDateTime: Union[datetime, date]
     a_date: date
 
 
 @test_router.get("/", response_model=List[AModel], operation_id="getUserList")
-def get_list(an_enum_value: List[AnEnum] = Query(...), some_date: Union[date, datetime] = Query(...)):
+def get_list(
+    an_enum_value: List[AnEnum] = Query(...), some_date: Union[date, datetime] = Query(...),
+):
     """ Get a list of things """
     return
 
@@ -67,6 +69,22 @@
     return
 
 
+@test_router.post("/test_defaults")
+def test_defaults(
+    string_prop: str = Query(default="the default string"),
+    datetime_prop: datetime = Query(default=datetime(1010, 10, 10)),
+    date_prop: date = Query(default=date(1010, 10, 10)),
+    float_prop: float = Query(default=3.14),
+    int_prop: int = Query(default=7),
+    boolean_prop: bool = Query(default=False),
+    list_prop: List[AnEnum] = Query(default=[AnEnum.FIRST_VALUE, AnEnum.SECOND_VALUE]),
+    union_prop: Union[float, str] = Query(default="not a float"),
+    enum_prop: AnEnum = Query(default=AnEnum.FIRST_VALUE),
+    dict_prop: Dict[str, str] = Body(default={"key": "val"}),
+):
+    return
+
+
 app.include_router(test_router, prefix="/tests", tags=["tests"])
 
 
```
