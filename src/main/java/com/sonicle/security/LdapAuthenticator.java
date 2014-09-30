/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */

package com.sonicle.security;

import com.novell.ldap.LDAPAttribute;
import com.novell.ldap.LDAPConnection;
import com.novell.ldap.LDAPEntry;
import com.novell.ldap.LDAPSearchResults;
import java.sql.Connection;
import java.util.Enumeration;
import java.util.regex.Pattern;
import javax.security.auth.login.LoginException;
import javax.sql.DataSource;

/**
 *
 * @author gbulfon
 */
public class LdapAuthenticator extends Authenticator {

	/**
	 * Matches:
	 * - matteo.albinola@sonicle.com
	 * - matteo.albinola
	 * Not matches:
	 * - matteo.albinola@sonicle.com@sonicle.com
	 * - matteo.albinola sonicle.com
	 */
	private static final Pattern userPattern = Pattern.compile("^((\\w(([_\\.\\-]?\\w+)*))|(\\w(([_\\.\\-]?\\w+)*)@(\\w+)(([\\.\\-]?\\w+)*)\\.([A-Za-z]{2,})))$");
	
    boolean ssl=false;
    String host="localhost";
    int port=389;
    String searchBase="ou=People";

	@Override
    public void initialize(DataSource ds) {
        AuthenticationDomain ad=getAuthenticationDomain();
        String authuriprotocol=ad.getAuthUriProtocol();
        String authurires=ad.getAuthUriResource();
        int ix=authurires.indexOf("/");
        if (ix>=0) {
            host=authurires.substring(0,ix);
            String auth=authurires.substring(ix+1);
            if (authuriprotocol.equals("ldapOther")) 
                searchBase=auth;
        }
        else host=authurires;
        System.out.println("hostldap="+host);
        ix=host.indexOf(":");
        if (ix>=0) {
            port=Integer.parseInt(host.substring(ix+1));
            host=host.substring(0,ix);
        }
        System.out.println("host.ldap="+host);
        ad.addProperty("ldap.protocol", authuriprotocol);
        ad.addProperty("ldap.host", host);
        ad.addProperty("ldap.port", port);
    }

	@Override
    public boolean authenticate(Principal principal) throws LoginException {
        boolean ret=false;

        try {
            String password=principal.getPassword();
            String username=principal.getUser();
            AuthenticationDomain ad=getAuthenticationDomain();
            String dc2=null;
            String dc1=null;
            String domain=null;
            int ix=username.indexOf("@");
            if (ix>0) {
                domain=username.substring(ix+1);
                username=username.substring(0,ix);
            } else {
                domain=ad.getDomain();
            }
            ix=domain.lastIndexOf(".");
            dc1=domain.substring(ix+1);
            dc2=domain.substring(0,ix);
            
            String dn="uid="+username+","+searchBase+",dc="+dc2+",dc="+dc1;
            System.out.println("LDAP dn: "+dn);
            LDAPConnection conn = new LDAPConnection();
            conn.connect(host, port);
            //conn.bind(dn, password);
            if (!password.equals("")){
                byte[] pw=password.getBytes();
                conn.bind(conn.LDAP_V3, dn,pw);
                String description=getUserDescription(conn,dn);
                ret=true;
            }
            //ad.addProperty("mail.protocol", "imap");
            //ad.addProperty("mail.host", host);
            //ad.addProperty("mail.port", "143");
            //ad.addProperty("mail.username", principal.getUser());
            //ad.addProperty("mail.password", password);
            
        } catch(Exception exc) {
          exc.printStackTrace();
        }
        return ret;
    }
    
    public String getUserDescription(LDAPConnection ld,String dn){
        String[] attr    = {"cn"};
        String filter = "cn=*";
        String val="";
        try{
            LDAPSearchResults res = ld.search(dn,ld.SCOPE_SUB,filter,attr,false);
            while (res.hasMore()) {
                LDAPEntry entry = res.next();
                for (int i =0;i<attr.length;i++){
                    LDAPAttribute attrn = entry.getAttribute(attr[i]);
                    if (attr != null){
                      Enumeration enumVals = attrn.getStringValues();
                        while ( (enumVals != null) && (enumVals.hasMoreElements()) ) {
                            val = (String) enumVals.nextElement();
                        }
                    }
                  }
            }
        }catch(Exception ex){
            ex.printStackTrace();
        }

        return val;
    }
    
	@Override
	public boolean validateUser(String user) {
		if(userPattern.matcher(user).matches()) return true;
		return false;
}
}
