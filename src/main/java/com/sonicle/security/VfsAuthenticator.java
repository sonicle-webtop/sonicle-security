/*
 * SmbAuthenticator.java
 *
 * Created on 11 agosto 2006, 15.51
 *
 * To change this template, choose Tools | Template Manager
 * and open the template in the editor.
 */

package com.sonicle.security;

import com.jcraft.jsch.JSch;
import javax.security.auth.login.*;
import java.net.URLEncoder;
import javax.sql.DataSource;
import org.apache.commons.vfs2.FileObject;
import org.apache.commons.vfs2.FileSystemException;
import org.apache.commons.vfs2.FileSystemManager;
import org.apache.commons.vfs2.VFS;

/**
 *
 * @author gbulfon
 */
public class VfsAuthenticator extends Authenticator {
    
    String uri;

    public void initialize(DataSource maindatasource) {
        uri=getAuthenticationDomain().getAuthUriResource();
    }

    public boolean authenticate(Principal principal) throws LoginException {
        String fullname=principal.getName();
        String password=principal.getPassword();
        String username=principal.getSubjectId();
        int ix=uri.indexOf("://")+3;
        String eusername=URLEncoder.encode(username);
        String epassword=URLEncoder.encode(password);
        String vfsuri=uri.substring(0,ix)+eusername+":"+epassword+"@"+uri.substring(ix);
        //System.out.println("auth vfsuri="+vfsuri);
        if (vfsuri.startsWith("sftp")) JSch.setConfig("StrictHostKeyChecking", "no");
//        if (log.isDebugEnabled()) log.debug("vfsuri="+vfsuri);
        boolean isok=false;
        try {
            FileSystemManager vfsm=VFS.getManager();
            FileObject fo=vfsm.resolveFile(vfsuri);
            isok=fo.exists() && fo.isReadable();
            fo.close();
            vfsm.getFilesCache().clear(fo.getFileSystem());
        } catch(FileSystemException exc) {
            exc.printStackTrace();
            String msg="Authentication failed for principal '"+fullname+"'";
//            log.error(msg,exc);
            throw new CredentialException(msg);
        }
        return isok;
    }
	
	public boolean validateUser(String user) {
		return true;
}
}
