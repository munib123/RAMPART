# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in ruby
**Pair ID:** 5840_1
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5840_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```ruby
Lines 154-194 of the vulnerable file.

    end
  end

  describe "activity_user" do

    before(:each) do
      @user = double(User, :id => 1, :is_a? => true)
      @cur_user = double(User)
    end

    it "should find a user by email" do
      @cur_user.stub(:pref).and_return(:activity_user => 'billy@example.com')
      controller.instance_variable_set(:@current_user, @cur_user)
      User.should_receive(:where).with(:email => 'billy@example.com').and_return([@user])
      controller.send(:activity_user).should == 1
    end

    it "should find a user by first name or last name" do
      @cur_user.stub(:pref).and_return(:activity_user => 'Billy')
      controller.instance_variable_set(:@current_user, @cur_user)
      User.should_receive(:where).with("upper(first_name) LIKE upper('%Billy%') OR upper(last_name) LIKE upper('%Billy%')").and_return([@user])
      controller.send(:activity_user).should == 1
    end

    it "should find a user by first name and last name" do
      @cur_user.stub(:pref).and_return(:activity_user => 'Billy Elliot')
      controller.instance_variable_set(:@current_user, @cur_user)
      User.should_receive(:where).with("(upper(first_name) LIKE upper('%Billy%') AND upper(last_name) LIKE upper('%Elliot%')) OR (upper(first_name) LIKE upper('%Elliot%') AND upper(last_name) LIKE upper('%Billy%'))").and_return([@user])
      controller.send(:activity_user).should == 1
    end

    it "should return nil when 'all_users' is specified" do
      @cur_user.stub(:pref).and_return(:activity_user => 'all_users')
      controller.instance_variable_set(:@current_user, @cur_user)
      User.should_not_receive(:where)
      controller.send(:activity_user).should == nil
    end

  end

  describe "timeline" do
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -171,14 +171,16 @@
     it "should find a user by first name or last name" do
       @cur_user.stub(:pref).and_return(:activity_user => 'Billy')
       controller.instance_variable_set(:@current_user, @cur_user)
-      User.should_receive(:where).with("upper(first_name) LIKE upper('%Billy%') OR upper(last_name) LIKE upper('%Billy%')").and_return([@user])
+      User.should_receive(:where).with(:first_name => 'Billy').and_return([@user])
+      User.should_receive(:where).with(:last_name => 'Billy').and_return([@user])
       controller.send(:activity_user).should == 1
     end
 
     it "should find a user by first name and last name" do
       @cur_user.stub(:pref).and_return(:activity_user => 'Billy Elliot')
       controller.instance_variable_set(:@current_user, @cur_user)
-      User.should_receive(:where).with("(upper(first_name) LIKE upper('%Billy%') AND upper(last_name) LIKE upper('%Elliot%')) OR (upper(first_name) LIKE upper('%Elliot%') AND upper(last_name) LIKE upper('%Billy%'))").and_return([@user])
+      User.should_receive(:where).with(:first_name => 'Billy', :last_name => "Elliot").and_return([@user])
+      User.should_receive(:where).with(:first_name => 'Elliot', :last_name => "Billy").and_return([@user])
       controller.send(:activity_user).should == 1
     end
 
```
