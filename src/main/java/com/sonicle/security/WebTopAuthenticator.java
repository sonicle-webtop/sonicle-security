/*
 * SmbAuthenticator.java
 *
 * Created on 11 agosto 2006, 15.51
 *
 * To change this template, choose Tools | Template Manager
 * and open the template in the editor.
 */

package com.sonicle.security;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import javax.security.auth.login.LoginException;
import javax.sql.DataSource;

/**
 *
 * @author gbulfon
 */
public class WebTopAuthenticator extends Authenticator {
	
	private DataSource ds = null;
	
	@Override
	public void initialize(DataSource ds) {
		this.ds =ds;
	}

	@Override
    public boolean authenticate(Principal principal) throws LoginException {
		Connection con=null;
        Statement stmt=null;
        ResultSet rs=null;
        boolean result=false;
        String password=principal.getPassword();
        String username=principal.getUser();
        try {
			con=ds.getConnection();
            System.out.println("WebTopAuthenticator: Connection="+con);
            stmt=con.createStatement();
            String sql=null;
            if (username.equals("admin")) {
                sql="select password, passwordtype from users "+
                    "where login='"+username+"'";
            } else {
                sql="select password, passwordtype from users "+
                    "where iddomain='"+getAuthenticationDomain().getIDDomain()+"' and login='"+username+"'";
            }
            rs=stmt.executeQuery(sql);
            if (rs.next()) {
                String credential=rs.getString("password");
                CredentialAlgorithm algorithm=CredentialAlgorithm.valueOf(rs.getString("passwordtype"));
                result=Credentials.compare(credential,algorithm,password);
                if (result) {
                    principal.setCredential(credential);
                    principal.setCredentialAlgorithm(algorithm);
                }
            }
        } catch(Exception exc) {
            String msg="Authentication failed for principal '"+username+"'";
            System.out.println(msg);
            exc.printStackTrace();
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
	
	@Override
	public boolean validateUser(String user) {
		return true;
}
}
