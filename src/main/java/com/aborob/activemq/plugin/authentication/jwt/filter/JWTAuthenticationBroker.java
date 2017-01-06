package com.aborob.activemq.plugin.authentication.jwt.filter;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import org.apache.activemq.broker.Broker;
import org.apache.activemq.broker.BrokerFilter;
import org.apache.activemq.broker.ConnectionContext;
import org.apache.activemq.command.ConnectionInfo;
import org.apache.activemq.security.SecurityContext;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.xml.bind.DatatypeConverter;
import java.security.Principal;
import java.util.Iterator;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * Created by hisham on 03-Nov-16.
 */
public class JWTAuthenticationBroker extends BrokerFilter {

    private final Logger logger = LoggerFactory.getLogger(JWTAuthenticationBroker.class);

    public String tokenHeader = "";
    private String defaultUser = "";
    private Set<Principal> defaultUserGroups;
    private String masterSecretKey = "";
    private Broker jaasAuthenticationFallbackBroker;

    private final CopyOnWriteArrayList<SecurityContext> securityContexts = new CopyOnWriteArrayList();

    public JWTAuthenticationBroker(
            Broker next, Broker jaasAuthenticationFallbackBroker, String defaultUser,
            Set<Principal> defaultUserGroups, String masterSecretKey, String tokenHeader) {

        super(next);
        this.jaasAuthenticationFallbackBroker = jaasAuthenticationFallbackBroker;
        this.defaultUser = defaultUser;
        this.defaultUserGroups = defaultUserGroups;
        this.masterSecretKey = masterSecretKey;
        this.tokenHeader = tokenHeader;
        logger.info("Initialize JWTAuthenticationBroker");
    }

    @Override
    public void addConnection(ConnectionContext context, ConnectionInfo info) throws Exception {

        logger.info("AddConnection JWTAuthenticationBroker: " + info.getUserName());
        SecurityContext s = context.getSecurityContext();
        if (s == null) {


            String header = (String) info.getUserName();
            String token = (String) info.getPassword();
            logger.info("SecurityContext JWTAuthenticationBroker: " + header);
            if (header.equals(this.tokenHeader) && !StringUtils.isBlank(token)) {

                logger.info("Validate SecurityContext JWTAuthenticationBroker");
                boolean isTokenValid = false;
                try {
                    Jws<Claims> claimsJws =
                            Jwts.parser().setSigningKey(
                                    DatatypeConverter.parseBase64Binary(this.masterSecretKey))
                                    .parseClaimsJws(token);
                    if (claimsJws != null) {
                        logger.info("Token Claims Valid JWTAuthenticationBroker");
                        isTokenValid = true;
                    }
                } catch (Exception e) {
                    logger.info("Wrong-JWT-Token-" + e.getMessage());
                    logger.debug(e.getMessage(), e);
                }

                if (!isTokenValid) {
                    logger.info("Token Invalid JWTAuthenticationBroker");
                    throw new SecurityException("Token [" + info.getUserName() + "] is invalid.");
                }

                final Set groups = (Set) this.defaultUserGroups;
                s = new SecurityContext(defaultUser) {
                    public Set<Principal> getPrincipals() {
                        return groups;
                    }
                };
                context.setSecurityContext(s);
                this.securityContexts.add(s);
                logger.info("Token Valid JWTAuthenticationBroker");
            }
        }

        try {
            logger.info("Token Add Connection JWTAuthenticationBroker");
            if (s != null) {
                super.addConnection(context, info);
            } else {
                this.jaasAuthenticationFallbackBroker.addConnection(context, info);
            }
        } catch (Exception e) {
            logger.error("Error JWTAuthenticationBroker: " + e.getMessage(), e);
            this.securityContexts.remove(s);
            context.setSecurityContext((SecurityContext) null);
            throw e;
        }
    }

    @Override
    public void removeConnection(ConnectionContext context, ConnectionInfo info, Throwable error) throws Exception {

        super.removeConnection(context, info, error);
        if (this.securityContexts.remove(context.getSecurityContext())) {
            context.setSecurityContext((SecurityContext) null);
        }

    }

    public void refresh() {

        Iterator iter = this.securityContexts.iterator();
        while (iter.hasNext()) {
            SecurityContext sc = (SecurityContext) iter.next();
            sc.getAuthorizedReadDests().clear();
            sc.getAuthorizedWriteDests().clear();
        }

    }
}
