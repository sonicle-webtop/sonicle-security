/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */

package com.sonicle.security;

import com.sonicle.commons.db.DbUtils;
import java.io.Serializable;
import java.util.Properties;
import javax.sql.DataSource;
import java.sql.Connection;
import com.sonicle.webtop.core.dal.DomainDAO;
import com.sonicle.webtop.core.bol.ODomain;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 *
 * @author gbulfon
 */
public class AuthenticationDomain implements Serializable {

	public final static Logger logger = (Logger) LoggerFactory.getLogger(AuthenticationDomain.class);
	
    private String iddomain;
    private String remoteiddomain=null;
    private String description;
    private String domain;
    private String authuri;
    private String adminuser;
    private String adminpassword;
    private int order;
    private boolean enabled;
	private Boolean caseSensitiveAuth;
	private Boolean userAutoCreation;
	private Boolean wtAdvancedSecurity;
    private String authuriprotocol;
    private String authuriresource;
    private Class authenticatorClass;
    private DataSource remotedatasource=null;
    private Properties props=new Properties();

    public AuthenticationDomain(String iddomain, String description, String domain, String authuri) {
        this(iddomain,description,domain,authuri,null,null,1,true,true,false,false);        
    }
	
	public AuthenticationDomain(String iddomain, String description, String domain, String authuri, String adminuser, String adminpassword, int order, boolean enabled) {
		this(iddomain,description,domain,authuri,adminuser,adminpassword,order,enabled,true,false,false);
	}
    
    public AuthenticationDomain(String iddomain, String description, String domain, String authuri, String adminuser, String adminpassword, int order, boolean enabled, Boolean caseSensitiveAuth, Boolean userAutoCreation, Boolean wtAdvancedSecurity) {
        this.iddomain=iddomain;
        this.description=description;
        this.domain=domain;
        this.authuri=authuri.trim();
        this.adminuser=adminuser!=null?adminuser.trim():null;
        this.adminpassword=adminpassword!=null?adminpassword.trim():null;
        this.order=order;
        this.enabled=enabled;
		this.caseSensitiveAuth = caseSensitiveAuth;
		this.userAutoCreation = userAutoCreation;
		this.wtAdvancedSecurity = wtAdvancedSecurity;
        
        int ix=authuri.indexOf("://");
        if (ix>0) {
            authuriprotocol=authuri.substring(0,ix);
            int ix2=ix+3;
            if (authuri.length()>ix2)
                authuriresource=authuri.substring(ix2);
        }
        else authuriprotocol=authuri;
        //System.out.println("Authentication Domain : ");
        //System.out.println(" iddomain="+iddomain);
        //System.out.println(" description="+description);
        //System.out.println(" domain="+domain);
        //System.out.println(" authuri="+authuri);
        //System.out.println(" authuriprotocol="+authuriprotocol);
        //System.out.println(" authuriresource="+authuriresource);
    }

    public String getIDDomain() {
        return iddomain;
    }

    public void setRemoteIDDomain(String id) {
        remoteiddomain=id;
    }

    public String getRemoteIDDomain() {
        return remoteiddomain;
    }

    public String getDataIDDomain() {
        if (remoteiddomain==null) return iddomain;
        return remoteiddomain;
    }

    public String getDescription() {
        return description;
    }

    public String getDomain() {
        return domain;
    }

    public String getAuthUri() {
        return authuri;
    }
    
    public String getAdminUser() {
        return adminuser;
    }
    
    public String getAdminPassword() {
        return adminpassword;
    }
    
    public int getOrder() {
        return order;
    }
    
    public boolean isEnabled() {
        return enabled;
    }
	
	public boolean isAuthCaseSensitive() {
		return caseSensitiveAuth;
	}
	
	public boolean isAutoCreationEnabled() {
		return userAutoCreation;
	}
	
	public boolean isWTAdvSecurityEnabled() {
		return wtAdvancedSecurity;
	}

    public String getAuthUriProtocol() {
        return authuriprotocol;
    }

    public String getAuthUriResource() {
        return authuriresource;
    }

    public void setAuthenticatorClass(Class c) {
        this.authenticatorClass=c;
    }

    public Class getAuthenticatorClass() {
        return authenticatorClass;
    }

    public void setRemoteDataSource(DataSource ds) {
        remotedatasource=ds;
    }

    public DataSource getRemoteDataSource() {
        return remotedatasource;
    }

    public void addProperty(String name, String value) {
        props.put(name,value);
    }

    public void addProperty(String name, int value) {
        props.put(name,""+value);
    }

    public void addProperty(String name, boolean value) {
        props.put(name,""+value);
    }

    public String getProperty(String name, String defaultValue) {
        String s=props.getProperty(name);
        if (s==null) s=defaultValue;
        return s;
    }

    public int getProperty(String name, int defaultValue) {
        int n=defaultValue;
        String s=props.getProperty(name);
        if (s!=null) n=Integer.parseInt(s);
        return n;
    }

    public boolean getProperty(String name, boolean defaultValue) {
        boolean b=defaultValue;
        String s=props.getProperty(name);
        if (s!=null) b=s.equals("true");
        return b;
    }
	
	
	public static AuthenticationDomain getInstance(Connection con, String domainId) {
        AuthenticationDomain ad=null;
        try {
			ODomain odomain=DomainDAO.getInstance().selectById(con,domainId);
            if (odomain!=null) {
                String description=odomain.getDescription();
                String domain=odomain.getDomainName();
                String authuri=odomain.getAuthUri();
                String adminuser=odomain.getAuthUsername();
				String adminpassword="";
				
				// TODO: how to manage auth password here??
                //String adminpassword=odomain.getAuthPassword();
                //if (adminpassword!=null && adminpassword.length()>0) 
                //    adminpassword=WebTopApp.decipher(adminpassword,"password");
				
                int order=1;
                boolean enabled=odomain.getEnabled();
				Boolean casesensitive = odomain.getCaseSensitiveAuth();
				Boolean autocreation = odomain.getUserAutoCreation();
				Boolean advsecurity = odomain.getWebtopAdvSecurity();
                ad=new AuthenticationDomain(domainId, description, domain, authuri, adminuser, adminpassword, order, enabled, casesensitive, autocreation, advsecurity);
            }
        } catch(Exception exc) {
			logger.error("Error fetching domain id={}",domainId,exc);
        } finally {
			DbUtils.closeQuietly(con);
        }
        return ad;
	}

}
