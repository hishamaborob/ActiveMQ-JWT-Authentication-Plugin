package com.aborob.activemq.plugin.authentication.jwt;

import com.aborob.activemq.plugin.authentication.jwt.filter.JWTAuthenticationBroker;
import org.apache.activemq.broker.Broker;
import org.apache.activemq.broker.BrokerPlugin;
import org.apache.activemq.jaas.GroupPrincipal;
import org.apache.activemq.security.JaasAuthenticationPlugin;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.Principal;
import java.util.HashSet;
import java.util.Set;
import java.util.StringTokenizer;

/**
 * Created by hisham on 03-Nov-16.
 * <p>
 * Usage:
 *   <plugins>
 *       <bean xmlns="http://www.springframework.org/schema/beans" id="jWTAuthenticationPlugin"
 *       class="com.aborob.activemq.plugin.authentication.jwt.JWTAuthenticationPlugin">
 *          <property name="defaultUser" value="system"/>
 *          <property name="defaultUserGroups" value="admins,readwrite,users"/>
 *          <property name="masterSecretKey" value="xxxxxxxxxx"/>
 *          <property name="tokenHeader" value="JWT-USER"/>
 *          <property name="jaasConfiguration" value="PropertiesLogin"/>
 *      </bean>
 *  </plugins>
 */
public class JWTAuthenticationPlugin implements BrokerPlugin {

    private final Logger logger = LoggerFactory.getLogger(JWTAuthenticationPlugin.class);

    protected String defaultUser = "";
    protected String defaultUserGroups = "";
    protected String masterSecretKey = "";
    protected String tokenHeader = "";
    protected String jaasConfiguration = "activemq-domain";
    protected boolean discoverLoginConfig = true;

    public JWTAuthenticationPlugin() {

    }

    @Override
    public Broker installPlugin(Broker parent) throws Exception {

        logger.info("Initialize JWTAuthenticationPlugin");

        Set<Principal> groups = new HashSet();
        StringTokenizer iter = new StringTokenizer(this.defaultUserGroups, ",");
        while (iter.hasMoreTokens()) {
            String name = iter.nextToken().trim();
            groups.add(new GroupPrincipal(name));
        }
        JaasAuthenticationPlugin jaasAuthenticationPlugin = new JaasAuthenticationPlugin();
        jaasAuthenticationPlugin.setConfiguration(this.jaasConfiguration);
        jaasAuthenticationPlugin.setDiscoverLoginConfig(this.discoverLoginConfig);
        Broker jaasAuthenticationFallbackBroker = jaasAuthenticationPlugin.installPlugin(parent);
        return new JWTAuthenticationBroker(
                parent, jaasAuthenticationFallbackBroker, this.defaultUser,
                groups, this.masterSecretKey, this.tokenHeader);
    }

    public String getMasterSecretKey() {
        return this.masterSecretKey;
    }

    public void setMasterSecretKey(String masterSecretKey) {
        this.masterSecretKey = masterSecretKey;
    }

    public String getDefaultUser() {
        return defaultUser;
    }

    public void setDefaultUser(String defaultUser) {
        this.defaultUser = defaultUser;
    }

    public String getDefaultUserGroups() {
        return defaultUserGroups;
    }

    public void setDefaultUserGroups(String defaultUserGroups) {
        this.defaultUserGroups = defaultUserGroups;
    }

    public String getTokenHeader() {
        return tokenHeader;
    }

    public void setTokenHeader(String tokenHeader) {
        this.tokenHeader = tokenHeader;
    }

    public String getJaasConfiguration() {
        return jaasConfiguration;
    }

    public void setJaasConfiguration(String jaasConfiguration) {
        this.jaasConfiguration = jaasConfiguration;
    }

    public boolean isDiscoverLoginConfig() {
        return discoverLoginConfig;
    }

    public void setDiscoverLoginConfig(boolean discoverLoginConfig) {
        this.discoverLoginConfig = discoverLoginConfig;
    }
}
