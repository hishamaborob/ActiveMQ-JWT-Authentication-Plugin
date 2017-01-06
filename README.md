# ActiveMQ-JWT-Authentication-Plugin
JWT Authentication Plugin For ActiveMQ With JAAS Authentication Fallback.

```xml
<plugins>
  <bean xmlns="http://www.springframework.org/schema/beans" id="jWTAuthenticationPlugin" class="com.aborob.activemq.plugin.authentication.jwt.JWTAuthenticationPlugin">
    <property name="defaultUser" value="system"/>
    <property name="defaultUserGroups" value="admins,readwrite,users"/>
    <property name="masterSecretKey" value="xxxxxxxxxx"/>
    <property name="tokenHeader" value="JWT-USER"/>
    <property name="jaasConfiguration" value="PropertiesLogin"/>
  </bean>
</plugins>
```
