/*
 * Credentials.java
 *
 * Created on 12 agosto 2006, 12.02
 *
 * To change this template, choose Tools | Template Manager
 * and open the template in the editor.
 */

package com.sonicle.security;

import com.novell.ldap.util.Base64;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;

//import org.apache.commons.logging.*;

/**
 *
 * @author gbulfon
 */
public class Credentials {
  
//  private static Log log = LogFactory.getLog(Credentials.class);
    
  public static boolean compare(String ecred, CredentialAlgorithm algorithm, String cred) 
        throws UnsupportedEncodingException, InvalidKeyException, InvalidKeySpecException, 
          NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, IOException {
      boolean result=false;
//      if (log.isDebugEnabled()) log.debug("CredentialAlgorithm="+algorithm);
      String xcred=null;
      if (algorithm==CredentialAlgorithm.PLAIN) xcred=cred;
      else if (algorithm==CredentialAlgorithm.DES) xcred=cipherDES(cred,cred);
      else if (algorithm==CredentialAlgorithm.SHA) xcred=encryptDigestBASE64(cred,"SHA");
      result=xcred.equals(ecred);
//      if (log.isDebugEnabled()) log.debug("ecred='"+ecred+"', cred='"+cred+"' -> xcred='"+xcred+"', xcred.equals(ecred)="+result);
      return result;
  }
    
  private static String encryptDigestBASE64(String s, String algorithm) 
        throws NoSuchAlgorithmException, UnsupportedEncodingException {
    MessageDigest md = MessageDigest.getInstance(algorithm);
    md.update(s.getBytes("UTF-8"));
	return Base64.encode(md.digest());
  }
  
  private static String decipherDES(String cpass, String key) 
        throws UnsupportedEncodingException, InvalidKeyException, InvalidKeySpecException, 
          NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, IOException {
    DESKeySpec ks=new DESKeySpec(key.getBytes("UTF-8"));
    SecretKey sk=SecretKeyFactory.getInstance("DES").generateSecret(ks);
    Cipher cipher=Cipher.getInstance("DES");
    cipher.init(Cipher.DECRYPT_MODE,sk);
	byte[] dec = Base64.decode(cpass);
    byte[] utf8 = cipher.doFinal(dec);
    return new String(utf8, "UTF-8");
  }

  private static String cipherDES(String pass, String key) 
        throws UnsupportedEncodingException, InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException,
            NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
    DESKeySpec ks=new DESKeySpec(key.getBytes("UTF-8"));
    SecretKey sk=SecretKeyFactory.getInstance("DES").generateSecret(ks);
    Cipher cipher=Cipher.getInstance("DES");
    cipher.init(Cipher.ENCRYPT_MODE,sk);
	return Base64.encode(cipher.doFinal(pass.getBytes("UTF-8")));
  }

}
