# CrossVul Fix Pair: Improper Certificate Validation in python
**Pair ID:** 1669_0
**Vulnerability Class:** Improper Certificate Validation
**CWE:** CWE-295
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1669_0`)

## Vulnerability Information & PoC

## Description
Improper Certificate Validation - When a certificate is invalid or malicious, it might allow an attacker to spoof a trusted entity by interfering in the communication path between the host and client.

## Vulnerable Code
```python
Lines 2-42 of the vulnerable file.

#
# Copyright © 2012 Red Hat, Inc.
#
# This software is licensed to you under the GNU General Public
# License as published by the Free Software Foundation; either version
# 2 of the License (GPLv2) or (at your option) any later version.
# There is NO WARRANTY for this software, express or implied,
# including the implied warranties of MERCHANTABILITY,
# NON-INFRINGEMENT, or FITNESS FOR A PARTICULAR PURPOSE. You should
# have received a copy of GPLv2 along with this software; if not, see
# http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt.

from pulp.bindings.actions import ActionsAPI
from pulp.bindings.content import OrphanContentAPI, ContentSourceAPI, ContentCatalogAPI
from pulp.bindings.event_listeners import EventListenerAPI
from pulp.bindings.repo_groups import *
from pulp.bindings.repository import *
from pulp.bindings.consumer_groups import *
from pulp.bindings.consumer import *
from pulp.bindings.server_info import ServerInfoAPI
from pulp.bindings.tasks import TasksAPI, TaskSearchAPI
from pulp.bindings.upload import UploadAPI
from pulp.bindings.auth import *


class Bindings(object):

    def __init__(self, pulp_connection):
        """
        @type:   pulp_connection: pulp.bindings.server.PulpConnection
        """

        # Please keep the following in alphabetical order to ease reading
        self.actions = ActionsAPI(pulp_connection)
        self.bind = BindingsAPI(pulp_connection)
        self.bindings = BindingSearchAPI(pulp_connection)
        self.profile = ProfilesAPI(pulp_connection)
        self.consumer = ConsumerAPI(pulp_connection)
        self.consumer_content = ConsumerContentAPI(pulp_connection)
        self.consumer_content_schedules = ConsumerContentSchedulesAPI(pulp_connection)
        self.consumer_group = ConsumerGroupAPI(pulp_connection)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -19,6 +19,7 @@
 from pulp.bindings.consumer_groups import *
 from pulp.bindings.consumer import *
 from pulp.bindings.server_info import ServerInfoAPI
+from pulp.bindings.static import StaticRequest
 from pulp.bindings.tasks import TasksAPI, TaskSearchAPI
 from pulp.bindings.upload import UploadAPI
 from pulp.bindings.auth import *
@@ -67,6 +68,7 @@
         self.repo_unit = RepositoryUnitAPI(pulp_connection)
         self.role = RoleAPI(pulp_connection)
         self.server_info = ServerInfoAPI(pulp_connection)
+        self.static = StaticRequest(pulp_connection)
         self.tasks = TasksAPI(pulp_connection)
         self.tasks_search = TaskSearchAPI(pulp_connection)
         self.uploads = UploadAPI(pulp_connection)
```
