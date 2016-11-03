/*
 * SmbAuthenticator.java
 *
 * Created on 11 agosto 2006, 15.51
 *
 * To change this template, choose Tools | Template Manager
 * and open the template in the editor.
 */

package com.sonicle.security.old;

import com.sonicle.commons.db.DbUtils;
import com.sonicle.webtop.core.bol.OGroup;
import com.sonicle.webtop.core.bol.OUser;
import com.sonicle.webtop.core.dal.GroupDAO;
import com.sonicle.webtop.core.dal.UserDAO;
import java.sql.Connection;
import java.util.List;
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
        boolean result=false;
        String password=new String(principal.getPassword());
        String userId=principal.getSubjectId();
        try {
			con=ds.getConnection();
			
			AuthenticationDomain ad=getAuthenticationDomain();
			String domainId=ad.getIDDomain();
			OUser user=UserDAO.getInstance().selectByDomainUser(con, domainId, userId);
            if (user!=null) {
                String credential=user.getPassword();
                CredentialAlgorithm algorithm=CredentialAlgorithm.valueOf(user.getPasswordType());
                result=Credentials.compare(credential,algorithm,password);
                if (result) {
                    principal.setCredential(credential);
                    principal.setCredentialAlgorithm(algorithm);
                }
            }
        } catch(Exception exc) {
            logger.error("Authentication failed for principal {}",userId,exc);
            throw new LoginException("Authentication failed for principal '"+userId+"'");
        } finally {
			DbUtils.closeQuietly(con);
        }
        return result;
    }
	
	@Override
	public boolean validateUser(String user) {
		return true;
}
}
