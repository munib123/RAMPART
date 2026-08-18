# CrossVul Fix Pair: Server-Side Request Forgery (SSRF) in php
**Pair ID:** 3882_1
**Vulnerability Class:** Server-Side Request Forgery (SSRF)
**CWE:** CWE-918
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3882_1`)

## Vulnerability Information & PoC

## Description
Server-Side Request Forgery (SSRF) - By providing URLs to unexpected hosts or ports, attackers can make it appear that the server is sending the request, possibly bypassing access controls such as firewalls that prevent the attackers ...

## Vulnerable Code
```php
Lines 171-204 of the vulnerable file.

                            </select>
                            <div ng-repeat="error in errors.Hostgroup_excluded">
                                <div class="help-block text-danger">{{ error }}</div>
                            </div>
                        </div>
                    </div>

                    <div class="alert alert-danger alert-block" ng-show="hasError">
                        <h4 class="alert-heading">{{ grafanaErrors.status }} - {{ grafanaErrors.statusText }}</h4>
                        {{ grafanaErrors.message }}
                    </div>

                    <div class="alert alert-success" ng-show="hasError === false">
                        <i class="fa-fw fa fa-check"></i>
                        <?php echo __('Connection established successfully.'); ?>
                    </div>

                    <div class="col-xs-12 margin-top-10">
                        <div class="well formactions ">
                            <div class="pull-right">
                                <button type="button"
                                        class="btn text-center btn-primary"
                                        ng-click="checkGrafanaConnection()">
                                    <?php echo __('Check Grafana Connection'); ?>
                                </button>
                                <input class="btn btn-primary" type="submit" value="Save">&nbsp;
                            </div>
                        </div>
                    </div>
                </div>
            </form>
        </div>
    </div>
</div>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -188,11 +188,13 @@
                     <div class="col-xs-12 margin-top-10">
                         <div class="well formactions ">
                             <div class="pull-right">
-                                <button type="button"
-                                        class="btn text-center btn-primary"
-                                        ng-click="checkGrafanaConnection()">
-                                    <?php echo __('Check Grafana Connection'); ?>
-                                </button>
+                                <?php if ($this->Acl->hasPermission('testGrafanaConnection', 'GrafanaConfiguration', 'GrafanaModule')): ?>
+                                    <button type="button"
+                                            class="btn text-center btn-primary"
+                                            ng-click="checkGrafanaConnection()">
+                                        <?php echo __('Check Grafana Connection'); ?>
+                                    </button>
+                                <?php endif; ?>
                                 <input class="btn btn-primary" type="submit" value="Save">&nbsp;
                             </div>
                         </div>
```
