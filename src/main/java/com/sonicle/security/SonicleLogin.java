/*
 * SonicleLogin.java
 *
 * Created on 20 luglio 2006, 9.32
 *
 * To change this template, choose Tools | Template Manager
 * and open the template in the editor.
 */

package com.sonicle.security;

import com.sonicle.commons.db.DbUtils;
import com.sonicle.webtop.core.bol.ODomain;
import com.sonicle.webtop.core.dal.DomainDAO;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import javax.security.auth.login.LoginException;
import javax.sql.DataSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 *
 * @author gbulfon
 */
public class SonicleLogin {

	public final static Logger logger = (Logger) LoggerFactory.getLogger(SonicleLogin.class);
	
    private DataSource datasource = null;
	
	public SonicleLogin(DataSource ds) {
		datasource = ds;
	}

    public com.sonicle.security.Principal validateUser(String username, char password[]) throws LoginException {
        logger.debug("Validating user {}",username);
        //ArrayList<java.security.Principal> principals=null;
        String fullname=username;
        int ix=username.lastIndexOf("@");
        String domainId=username.substring(ix+1);
        username=username.substring(0,ix);
        if (username.equals("admin")) domainId=null;
        String description=null;
        Authenticator authenticator=null;
		Connection con=null;
        AuthenticationDomain ad=null;
        try {
            String domain=null;
            String authuri=null;
            String adminuser=null;
            String adminpassword=null;
            int order=1;
            Boolean enabled=null;
			Boolean casesensitive = null;
			Boolean autocreation = null;
			Boolean advsecurity = null;
			
			con=datasource.getConnection();
            if (domainId!=null) {
				ODomain odomain=DomainDAO.getInstance().selectById(con, domainId);
                if (odomain!=null) {
                    description=odomain.getDescription();
                    domain=odomain.getDomainName();
                    authuri=odomain.getAuthUri();
                    adminuser=odomain.getAuthUsername();
                    adminpassword=odomain.getAuthPassword();
                    //order???
                    enabled=odomain.getEnabled();
					casesensitive = odomain.getCaseSensitiveAuth();
					autocreation = odomain.getUserAutoCreation();
					advsecurity = odomain.getWebtopAdvSecurity();
                }
            } else {
//                fullname="admin@";
                domainId="*";
                description="Administrators";
                domain="local";
                authuri="webtop";
				enabled = true;
				casesensitive = false;
				autocreation = false;
				advsecurity = false;
            }
            if (authuri!=null) {
				// Portare tutto nel costruttore dell' AuthenticationDomain???
                ad=new AuthenticationDomain(domainId,description,domain,authuri,adminuser,adminpassword,order,enabled,casesensitive,autocreation,advsecurity);
                String authUriProtocol=ad.getAuthUriProtocol();
                if (authUriProtocol.startsWith("ldap")) authUriProtocol="ldap";
                String className=AuthenticatorManager.getAuthenticatorClassName(authUriProtocol);
                if (className!=null) {
                    try {
                        Class aclass=Class.forName(className);
                        Object o=aclass.newInstance();
                        if (o instanceof Authenticator) {
                            ad.setAuthenticatorClass(aclass);
                            authenticator=(Authenticator)o;
                        } else {
                            throw new RuntimeException("Class "+className+" does not implement the Authenticator interface");
                        }
                    } catch(Exception exc) {
                        throw new RuntimeException("Unsupported authentication uri \""+authuri+"\"",exc);
                    }
                } else {
                    throw new RuntimeException("Authentication class not found for \""+authUriProtocol+"\"");
                }
            }
        } catch(SQLException exc) {
            logger.error("Error validating user {}",fullname,exc);
        } finally {
			DbUtils.closeQuietly(con);
        }
        if (authenticator==null) return null;

        Principal principal=new Principal(username,ad,description);
        logger.debug("Prepared principal {}",principal);
        principal.setPassword(new String(password));
        authenticator.setAuthenticationDomain(ad);
        authenticator.initialize(datasource);
		if(!authenticator.validateUser(principal.getSubjectId())) throw new LoginException("Bad login format");
        if (!authenticator.authenticate(principal)) throw new LoginException("No principal found!");
        return principal;
    }
        
}
