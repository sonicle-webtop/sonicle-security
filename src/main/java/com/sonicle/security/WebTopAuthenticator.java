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
        String username=principal.getSubjectId();
        try {
			con=ds.getConnection();
            System.out.println("WebTopAuthenticator: Connection="+con);
            stmt=con.createStatement();
            String sql=null;
			AuthenticationDomain ad=getAuthenticationDomain();
			String iddomain=ad.getIDDomain();
/*			boolean isadmin=username.equals("admin");
            if (isadmin) {
                sql="select password, password_type from users "+
                    "where user_id='"+username+"'";
            } else {
                sql="select password, password_type from users "+
                    "where domain_id='"+iddomain+"' and user_id='"+username+"'";
            }*/
			sql="select password, password_type from users "+
				"where domain_id='"+iddomain+"' and user_id='"+username+"'";
            rs=stmt.executeQuery(sql);
            if (rs.next()) {
                String credential=rs.getString("password");
                CredentialAlgorithm algorithm=CredentialAlgorithm.valueOf(rs.getString("password_type"));
                result=Credentials.compare(credential,algorithm,password);
                if (result) {
                    principal.setCredential(credential);
                    principal.setCredentialAlgorithm(algorithm);
					
//					if (!isadmin) {
						rs.close();
						sql="select group_id, description from groups where domain_id in ('"+iddomain+"','*') and group_id in (select group_id from users_groups where domain_id in ('"+iddomain+"','*') and user_id='"+username+"')";
						rs=stmt.executeQuery(sql);
						while(rs.next()) {
							GroupPrincipal group=new GroupPrincipal(rs.getString("group_id"),ad,rs.getString("description"));
							principal.addGroup(group);
						}
//					}
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
