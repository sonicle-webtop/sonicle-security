/*
 * Authenticator.java
 *
 * Created on 11 agosto 2006, 15.49
 *
 * To change this template, choose Tools | Template Manager
 * and open the template in the editor.
 */

package com.sonicle.security.old;

import javax.security.auth.login.LoginException;
import javax.sql.DataSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 *
 * @author gbulfon
 */
public abstract class Authenticator {
    
	public final static Logger logger = (Logger) LoggerFactory.getLogger(Authenticator.class);
	
    private AuthenticationDomain ad;
	
	public abstract void initialize(DataSource ds);

    public abstract boolean authenticate(Principal principal) throws LoginException;
	
	public abstract boolean validateUser(String user);
	
    public void setAuthenticationDomain(AuthenticationDomain ad) {
        this.ad=ad;
    }

    public AuthenticationDomain getAuthenticationDomain() {
        return ad;
    }
}
