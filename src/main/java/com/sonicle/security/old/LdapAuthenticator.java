/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */

package com.sonicle.security.old;

import com.novell.ldap.LDAPAttribute;
import com.novell.ldap.LDAPConnection;
import com.novell.ldap.LDAPEntry;
import com.novell.ldap.LDAPSearchResults;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.regex.Pattern;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.directory.Attribute;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.security.auth.login.LoginException;
import javax.sql.DataSource;
import org.apache.commons.lang3.StringUtils;
import sun.misc.BASE64Decoder;

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
	boolean isLdapAD=false;
	boolean isLdapOther=false;

    public void initialize(DataSource mainds) {
        AuthenticationDomain ad=getAuthenticationDomain();
        String authuriprotocol=ad.getAuthUriProtocol();
        String authurires=ad.getAuthUriResource();
		String auth=authurires;
        int ix=authurires.indexOf("/");
        if (ix>=0) {
            host=authurires.substring(0,ix);
            auth=authurires.substring(ix+1);
        }
        else {
			host=authurires;
			auth="";
		}
		if (ad.isLdapOther()) {
			searchBase=auth;
			isLdapOther=true;
		} else if (ad.isLdapAD())  {
			searchBase=(auth==null||auth.trim().length()==0)?"cn=Users":auth;
			isLdapAD=true;
		}
        ix=host.indexOf(":");
        if (ix>=0) {
            port=Integer.parseInt(host.substring(ix+1));
            host=host.substring(0,ix);
        }
        ad.addProperty("ldap.protocol", authuriprotocol);
        ad.addProperty("ldap.host", host);
        ad.addProperty("ldap.port", port);
    }

    public boolean authenticate(Principal principal) throws LoginException {
        boolean ret=false;

        try {
            String password=new String(principal.getPassword());
            String username=principal.getUserId();
            AuthenticationDomain ad=getAuthenticationDomain();
            String domain=null;
            int ix=username.indexOf("@");
            if (ix>0) {
                domain=username.substring(ix+1);
                username=username.substring(0,ix);
            } else {
                domain=ad.getDomain();
            }
			String dcs[]=StringUtils.split(domain,'.');
            
			if (!isLdapAD) {
				String dn="uid="+username+","+searchBase; //dc="+dc2+",dc="+dc1;
				//if (isLdapAD) dn="cn="+username+","+searchBase;
				for(String dc: dcs) {
					dn+=",dc="+dc;
				}

				LDAPConnection conn = new LDAPConnection();
				conn.connect(host, port);
				if (!password.equals("")){
					//verify user password first
					byte[] pw=password.getBytes();
					conn.bind(conn.LDAP_V3, dn,pw);
					conn.disconnect();				

					//now rebind with admin to get info from ldap
					conn.connect(host, port);

					String adn="cn="+ad.getAdminUser();
					String sb=searchBase;
					for(String dc: dcs) {
						adn+=",dc="+dc;
						sb+=",dc="+dc;
					}
					//if (isLdapAD) adn=ad.getAdminUser()+"@"+ad.getDomain();
					conn.connect(host, port);
					String adminpass=ad.getAdminPassword();
					if (adminpass!=null  && !adminpass.equals("")){
						adminpass=decipher(adminpass,"password");
						pw=adminpass.getBytes();
						conn.bind(conn.LDAP_V3, adn,pw);
						String description=getUserDescription(conn,sb,username);
						if (description!=null) principal.setDescription(description);
						//System.out.println("getting attribute mail for dn "+dn);
						//String email=getAttribute(conn,dn,"mail");
						//if (email==null) email=username+"@"+ad.getDomain();

						//principal.setEmail(email);

						ret=true;
					}

				}
				conn.disconnect();
			} else { //ActiveDirectory
				String uri=ad.getAuthUri();
				String authuri=uri;
				ix=uri.indexOf("/",uri.indexOf("://")+3);
				if (ix>0){
					authuri=uri.substring(0,ix);
				}  
				authuri=authuri.replace("ldapAD", "ldap");
				Hashtable<String, String> contextParams = new Hashtable<String, String>();
				contextParams.put(Context.PROVIDER_URL,authuri);
				contextParams.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
				contextParams.put(Context.SECURITY_AUTHENTICATION, "simple");
				contextParams.put( Context.SECURITY_PRINCIPAL,username+"@"+ad.getDomain());
				contextParams.put( Context.SECURITY_CREDENTIALS,password);
				DirContext dirContext =new InitialDirContext(contextParams);
				String filter="(&(sAMAccountName="+username+")(objectClass=user)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))";
				
				String dn=searchBase;
				for(String dc: dcs) {
					dn+=",dc="+dc;
				}
				
                SearchControls sc= new SearchControls();
                sc.setSearchScope(SearchControls.SUBTREE_SCOPE);
                NamingEnumeration<SearchResult> search = dirContext.search(dn,filter,sc);
                while (search != null && search.hasMore()){
					SearchResult sr=(SearchResult)search.next();
					Attribute attr=sr.getAttributes().get("cn");
					if (attr != null) {
						Enumeration vals = attr.getAll();
						while (vals.hasMoreElements()) {            
							principal.setDescription(vals.nextElement().toString());
						}
					}
					ret=true;
                } 
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
    
    public String getUserDescription(LDAPConnection ld,String dn, String username){
        String[] attr    = {"cn"};
        String filter = "uid="+username;
		if (isLdapAD) filter="cn="+username;
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
    
    public String getEmail(LDAPConnection ld,String dn){
        String[] attr    = {"mail"};
        String filter = "mail=*";
        String val="";
        try{
            LDAPSearchResults res = ld.search(dn,ld.SCOPE_SUB,filter,attr,false);
            if (res.hasMore()) {
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
    
    public String getAttribute(LDAPConnection ld,String dn, String attr){
        String filter = attr+"=*";
		String attrs[] = new String[1];
		attrs[0]=attr;
        String val=null;
        try{
            LDAPSearchResults res = ld.search(dn,ld.SCOPE_SUB,filter,attrs,false);
            if (res.hasMore()) {
                LDAPEntry entry = res.next();
				LDAPAttribute attrn = entry.getAttribute(attr);
				if (attrn != null) {
					String vals[]=attrn.getStringValueArray();
					for(int i=0;i<vals.length;++i)
						System.out.println("LDAP getAttribute "+attr+" found value "+i+" = "+vals[i]);
					if (vals.length>0) val=vals[0];
				}
            }
        }catch(Exception ex){
            ex.printStackTrace();
        }

        return val;
    }
	
	public boolean validateUser(String user) {
		if(userPattern.matcher(user).matches()) return true;
		return false;
	}
	
	public String decipher(String cpass, String key) throws Exception {
		DESKeySpec ks=new DESKeySpec(key.getBytes("UTF-8"));
		SecretKey sk=SecretKeyFactory.getInstance("DES").generateSecret(ks);
		Cipher cipher=Cipher.getInstance("DES");
		cipher.init(Cipher.DECRYPT_MODE,sk);
		byte[] dec = new BASE64Decoder().decodeBuffer(cpass);
		byte[] utf8 = cipher.doFinal(dec);
		return new String(utf8, "UTF-8");
	}
	
}
