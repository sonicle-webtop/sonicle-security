/*
 * SonicleLogin.java
 *
 * Created on 20 luglio 2006, 9.32
 *
 * To change this template, choose Tools | Template Manager
 * and open the template in the editor.
 */

package com.sonicle.security;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import javax.security.auth.login.LoginException;
import javax.sql.DataSource;

/**
 *
 * @author gbulfon
 */
public class SonicleLogin {

    private DataSource datasource = null;
	
	public SonicleLogin(DataSource ds) {
		datasource = ds;
	}

    public com.sonicle.security.Principal validateUser(String username, char password[]) throws LoginException {
        System.out.println("Validating user "+username);
        ArrayList<java.security.Principal> principals=null;
        String fullname=username;
        int ix=username.lastIndexOf("@");
        String iddomain=username.substring(ix+1);
        username=username.substring(0,ix);
        if (username.equals("admin")) iddomain=null;
        String description=null;
        Authenticator authenticator=null;
		Connection con=null;
        Statement stmt=null;
        ResultSet rs=null;
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
            stmt=con.createStatement();
            if (iddomain!=null) {
                rs=stmt.executeQuery("select * from domains where domain_id='"+iddomain+"'");
                if (rs.next()) {
                    description=rs.getString("description");
                    domain=rs.getString("domain_name");
                    authuri=rs.getString("auth_uri");
                    adminuser=rs.getString("auth_username");
                    adminpassword=rs.getString("auth_password");
                    //order=rs.getInt("order");
                    enabled=rs.getBoolean("enabled");
					casesensitive = rs.getBoolean("case_sensitive_auth");
					autocreation = rs.getBoolean("user_auto_creation");
					advsecurity = rs.getBoolean("webtop_adv_security");
                }
                rs.close();
            } else {
                fullname="admin@";
                iddomain="*";
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
                ad=new AuthenticationDomain(iddomain,description,domain,authuri,adminuser,adminpassword,order,enabled,casesensitive,autocreation,advsecurity);
                String authUriProtocol=ad.getAuthUriProtocol();
                if (authUriProtocol.startsWith("ldap")) authUriProtocol="ldap";
                rs=stmt.executeQuery("select class_name from authentication_classes where auth_uri_protocol='"+authUriProtocol+"'");
                String className=null;
                if (rs.next()) className=rs.getString("class_name");
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
            exc.printStackTrace();
        } finally {
            if (rs!=null) try { rs.close(); } catch(SQLException exc) {}
            if (stmt!=null) try { stmt.close(); } catch(SQLException exc) {}
			if (con!=null) try { con.close(); } catch(SQLException exc) {}
        }
        if (authenticator==null) return null;

        Principal principal=new Principal(username,ad,description);
        System.out.println("Prepared principal "+principal);
        principal.setPassword(new String(password));
        authenticator.setAuthenticationDomain(ad);
        authenticator.initialize(datasource);
		if(!authenticator.validateUser(principal.getSubjectId())) throw new LoginException("Bad login format");
        if (!authenticator.authenticate(principal)) throw new LoginException("No principal found!");
        return principal;
    }
        
}
