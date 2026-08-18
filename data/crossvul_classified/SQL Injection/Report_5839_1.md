# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in ruby
**Pair ID:** 5839_1
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5839_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```ruby
Lines 25-67 of the vulnerable file.

      activity = FactoryGirl.create(:version, :item => FactoryGirl.create(:account, :user => @current_user), :event => "view")
      controller.should_receive(:get_activities).once.and_return([])

      get :index
      assigns[:activities].should == []
    end

    it "should get a list of my tasks ordered by due_at" do
      task_1 = FactoryGirl.create(:task, :name => "Your first task", :bucket => "due_asap", :assigned_to => current_user.id)
      task_2 = FactoryGirl.create(:task, :name => "Another task for you", :bucket => "specific_time", :calendar => 5.days.from_now.to_s, :assigned_to => current_user.id)
      task_3 = FactoryGirl.create(:task, :name => "Third Task", :bucket => "due_next_week", :assigned_to => current_user.id)
      task_4 = FactoryGirl.create(:task, :name => "i've assigned it to myself", :user => current_user, :calendar => 20.days.from_now.to_s, :assigned_to => nil, :bucket => "specific_time")

      FactoryGirl.create(:task, :name => "Someone else's Task", :user_id => current_user.id, :bucket => "due_asap", :assigned_to => FactoryGirl.create(:user).id)
      FactoryGirl.create(:task, :name => "Not my task", :bucket => "due_asap", :assigned_to => FactoryGirl.create(:user).id)

      get :index
      assigns[:my_tasks].should == [task_1, task_2, task_3, task_4]
    end

		it "should not display completed tasks" do
			task_1 = FactoryGirl.create(:task, :user_id => current_user.id, :name => "Your first task", :bucket => "due_asap", :assigned_to => current_user.id)
			task_2 = FactoryGirl.create(:task, :user_id => current_user.id, :name => "Completed task", :bucket => "due_asap", :completed_at => 1.days.ago, :completed_by => current_user.id, :assigned_to => current_user.id)

			get :index
			assigns[:my_tasks].should == [task_1]
		end

    it "should get a list of my opportunities ordered by closes_on" do
      opportunity_1 = FactoryGirl.create(:opportunity, :name => "Your first opportunity", :closes_on => 15.days.from_now, :assigned_to => current_user.id, :stage => 'proposal')
      opportunity_2 = FactoryGirl.create(:opportunity, :name => "Another opportunity for you", :closes_on => 10.days.from_now, :assigned_to => current_user.id, :stage => 'proposal')
      opportunity_3 = FactoryGirl.create(:opportunity, :name => "Third Opportunity", :closes_on => 5.days.from_now, :assigned_to => current_user.id, :stage => 'proposal')
      opportunity_4 = FactoryGirl.create(:opportunity, :name => "Fourth Opportunity", :closes_on => 50.days.from_now, :assigned_to => nil, :user_id => current_user.id, :stage => 'proposal')

      FactoryGirl.create(:opportunity_in_pipeline, :name => "Someone else's Opportunity", :assigned_to => FactoryGirl.create(:user).id, :stage => 'proposal')
      FactoryGirl.create(:opportunity_in_pipeline, :name => "Not my opportunity", :assigned_to => FactoryGirl.create(:user).id, :stage => 'proposal')

      get :index
      assigns[:my_opportunities].should == [opportunity_3, opportunity_2, opportunity_1, opportunity_4]
    end

    it "should get a list of my accounts ordered by name" do
      account_1 = FactoryGirl.create(:account, :name => "Anderson", :assigned_to => current_user.id)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -42,13 +42,13 @@
       assigns[:my_tasks].should == [task_1, task_2, task_3, task_4]
     end
 
-		it "should not display completed tasks" do
-			task_1 = FactoryGirl.create(:task, :user_id => current_user.id, :name => "Your first task", :bucket => "due_asap", :assigned_to => current_user.id)
-			task_2 = FactoryGirl.create(:task, :user_id => current_user.id, :name => "Completed task", :bucket => "due_asap", :completed_at => 1.days.ago, :completed_by => current_user.id, :assigned_to => current_user.id)
-
-			get :index
-			assigns[:my_tasks].should == [task_1]
-		end
+    it "should not display completed tasks" do
+      task_1 = FactoryGirl.create(:task, :user_id => current_user.id, :name => "Your first task", :bucket => "due_asap", :assigned_to => current_user.id)
+      task_2 = FactoryGirl.create(:task, :user_id => current_user.id, :name => "Completed task", :bucket => "due_asap", :completed_at => 1.days.ago, :completed_by => current_user.id, :assigned_to => current_user.id)
+
+      get :index
+      assigns[:my_tasks].should == [task_1]
+    end
 
     it "should get a list of my opportunities ordered by closes_on" do
       opportunity_1 = FactoryGirl.create(:opportunity, :name => "Your first opportunity", :closes_on => 15.days.from_now, :assigned_to => current_user.id, :stage => 'proposal')
@@ -153,42 +153,91 @@
       session[:hello].should == true
     end
   end
-  
+
   describe "activity_user" do
-  
+
     before(:each) do
       @user = double(User, :id => 1, :is_a? => true)
       @cur_user = double(User)
     end
-  
+
     it "should find a user by email" do
       @cur_user.stub(:pref).and_return(:activity_user => 'billy@example.com')
       controller.instance_variable_set(:@current_user, @cur_user)
       User.should_receive(:where).with(:email => 'billy@example.com').and_return([@user])
       controller.send(:activity_user).should == 1
     end
-    
+
     it "should find a user by first name or last name" do
       @cur_user.stub(:pref).and_return(:activity_user => 'Billy')
       controller.instance_variable_set(:@current_user, @cur_user)
       User.should_receive(:where).with("upper(first_name) LIKE upper('%Billy%') OR upper(last_name) LIKE upper('%Billy%')").and_return([@user])
       controller.send(:activity_user).should == 1
     end
-    
+
     it "should find a user by first name and last name" do
       @cur_user.stub(:pref).and_return(:activity_user => 'Billy Elliot')
       controller.instance_variable_set(:@current_user, @cur_user)
       User.should_receive(:where).with("(upper(first_name) LIKE upper('%Billy%') AND upper(last_name) LIKE upper('%Elliot%')) OR (upper(first_name) LIKE upper('%Elliot%') AND upper(last_name) LIKE upper('%Billy%'))").and_return([@user])
       controller.send(:activity_user).should == 1
     end
-    
+
     it "should return nil when 'all_users' is specified" do
       @cur_user.stub(:pref).and_return(:activity_user => 'all_users')
       controller.instance_variable_set(:@current_user, @cur_user)
       User.should_not_receive(:where)
       controller.send(:activity_user).should == nil
     end
-    
+
+  end
+
+  describe "timeline" do
+
+    before(:each) do
+      require_user
+    end
+
+    it "should collapse all comments and emails on a specific contact" do
+      comment = double(Comment)
+      Comment.should_receive(:find).with("1").and_return(comment)
+      comment.should_receive(:update_attribute).with(:state, 'Collapsed')
+      xhr :get, :timeline, :type => "comment", :id => "1", :state => "Collapsed"
+    end
+
+    it "should expand all comments and emails on a specific contact" do
+      comment = double(Comment)
+      Comment.should_receive(:find).with("1").and_return(comment)
+      comment.should_receive(:update_attribute).with(:state, 'Expanded')
+      xhr :get, :timeline, :type => "comment", :id => "1", :state => "Expanded"
+    end
+
+    it "should not do anything when state neither Expanded nor Collapsed" do
+      comment = double(Comment)
+      Comment.should_not_receive(:find).with("1")
+      xhr :get, :timeline, :type => "comment", :id => "1", :state => "Explode"
+    end
+
+    it "should collapse all comments and emails on Contact" do
+      where_stub = double
+      where_stub.should_receive(:update_all).with(:state => "Collapsed")
+      Comment.should_receive(:where).and_return(where_stub)
+      xhr :get, :timeline, :id => "1,2,3,4+", :state => "Collapsed"
+    end
+
+    it "should not allow an arbitary state (sanitizes input)" do
+      where_stub = double
+      where_stub.should_receive(:update_all).with(:state => "Expanded")
+      Comment.should_receive(:where).and_return(where_stub)
+      xhr :get, :timeline, :id => "1,2,3,4+", :state => "Expanded"
+    end
+
+    it "should not update an arbitary model (sanitizes input)" do
+      where_stub = double
+      where_stub.should_receive(:update_all).with(:state => "Expanded")
+      Comment.should_receive(:where).and_return(where_stub)
+      xhr :get, :timeline, :id => "1,2,3,4+", :state => "Expanded"
+    end
+
   end
 
 end
```
