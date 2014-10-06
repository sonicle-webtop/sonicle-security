/*
 * SmbAuthenticator.java
 *
 * Created on 11 agosto 2006, 15.51
 *
 * To change this template, choose Tools | Template Manager
 * and open the template in the editor.
 */

package com.sonicle.security;

import java.sql.*;
import javax.sql.*;
import javax.naming.*;
import javax.security.auth.login.LoginException;

/**
 *
 * @author gbulfon
 */
public class SonicleAuthenticator extends Authenticator {


    private String uri;
    private DataSource datasource;
    String iddomain;
    String remoteiddomain=null;
    
    public void initialize(DataSource mainds) {
        AuthenticationDomain ad=getAuthenticationDomain();
        uri=ad.getAuthUriResource();
        if (uri==null) {
            datasource=mainds;
            iddomain=ad.getIDDomain();
        }
        else if (uri.startsWith("jndi://")) {
            String resource=uri.substring(7);
            //check for remote id or set it to 1
            remoteiddomain=null;
            int ix=resource.indexOf("/");
            if (ix>0) {
                remoteiddomain=resource.substring(ix+1);
                resource=resource.substring(0,ix);
            }
            if (remoteiddomain!=null) {
                String jndiuri="java:comp/env/jdbc/"+resource;
                try {
                    Context context = new InitialContext();
                    datasource=(DataSource)context.lookup(jndiuri);
                    ad.setRemoteDataSource(datasource);
                    ad.setRemoteIDDomain(remoteiddomain);
                    iddomain=remoteiddomain;
                } catch(NamingException exc) {
                }
            }
        }
    }

    public boolean authenticate(Principal principal) throws LoginException {
        if (datasource==null) throw new RuntimeException("No DataSource available for authentication");
        Connection con=null;
        Statement stmt=null;
        ResultSet rs=null;
        boolean result=false;
        String password=principal.getPassword();
        String username=principal.getSubjectId();
        try {
            con=datasource.getConnection();
            //System.out.println("SonicleAuthenticator: Connection="+con);
            stmt=con.createStatement();
            rs=stmt.executeQuery(
                    "select credential, algorithm from credentials, principals "+
                    "where credentials.idprincipal=principals.idprincipal and "+
                    "principals.name='"+username+"' and iddomain='"+iddomain+"'"
            );
            if (rs.next()) {
                String credential=rs.getString("credential");
                CredentialAlgorithm algorithm=CredentialAlgorithm.valueOf(rs.getString("algorithm"));
                result=Credentials.compare(credential,algorithm,password);
                if (result) {
                    principal.setCredential(credential);
                    principal.setCredentialAlgorithm(algorithm);
                }
            }
        } catch(Exception exc) {
            String msg="Authentication failed for principal '"+username+"'";
//            log.error(msg,exc);
            if (rs!=null) try { rs.close(); } catch(SQLException exc1) {}
            if (stmt!=null) try { stmt.close(); } catch(SQLException exc1) {}
            if (con!=null) try { con.close(); } catch(SQLException exc1) {}
            throw new LoginException(msg);
        } finally {
            if (rs!=null) try { rs.close(); } catch(SQLException exc) {}
            if (stmt!=null) try { stmt.close(); } catch(SQLException exc) {}
            if (con!=null) try { con.close(); } catch(SQLException exc) {}
        }
        return result;
    }
	
	public boolean validateUser(String user) {
		return true;
}
}
