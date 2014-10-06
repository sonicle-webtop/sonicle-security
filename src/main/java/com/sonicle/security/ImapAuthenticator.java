/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */

package com.sonicle.security;

import com.sun.mail.imap.IMAPSSLStore;
import com.sun.mail.imap.IMAPStore;
import java.util.Properties;
import javax.mail.Session;
import javax.mail.URLName;
import javax.security.auth.login.LoginException;
import javax.sql.DataSource;

/**
 *
 * @author gbulfon
 */
public class ImapAuthenticator extends Authenticator {

    boolean ssl=false;
    String host;
    int port=143;
    Properties props=System.getProperties();

	@Override
    public void initialize(DataSource mainds) {
        AuthenticationDomain ad=getAuthenticationDomain();
        String authuriprotocol=ad.getAuthUriProtocol();
        String authurires=ad.getAuthUriResource();
        ssl=authuriprotocol.equals("imaps");
        host=authurires;
        int ix=host.indexOf(":");
        if (ix>=0) {
            port=Integer.parseInt(host.substring(ix+1));
            host=host.substring(0,ix);
        }
        ad.addProperty("mail.protocol", authuriprotocol);
        ad.addProperty("mail.host", host);
        ad.addProperty("mail.port", port);
        if (ssl) this.props.setProperty("mail.imaps.ssl.trust", "*");
    }

	@Override
    public boolean authenticate(Principal principal) throws LoginException {
        boolean ret=false;

        try {
            String password=principal.getPassword();
            String username=principal.getSubjectId();
            Session session=Session.getDefaultInstance(props, null);
            IMAPStore store;
            URLName url=new URLName((ssl?"imaps":"imap"),host,port,null,username,password);
            if (ssl) store=new IMAPSSLStore(session,url);
            else store=new IMAPStore(session,url);
            store.connect(host, port, username, password);
            ret=true;
            store.close();
            AuthenticationDomain ad=getAuthenticationDomain();
            ad.addProperty("mail.username", username);
            ad.addProperty("mail.password", password);
        } catch(Exception exc) {
          exc.printStackTrace();
        }
        return ret;
    }
	
	@Override
	public boolean validateUser(String user) {
		return true;
}
}
