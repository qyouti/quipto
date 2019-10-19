/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.quipto.passwords;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Properties;
import java.util.UUID;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import org.bouncycastle.util.Arrays;
import org.quipto.QuiptoStandards;
import org.quipto.compositefile.EncryptedCompositeFilePasswordHandler;
import org.quipto.key.impl.StandardRSAKeyBuilderSigner;
import org.qyouti.winselfcert.WindowsCertificateGenerator;
import static org.qyouti.winselfcert.WindowsCertificateGenerator.CRYPT_USER_PROTECTED;
import static org.qyouti.winselfcert.WindowsCertificateGenerator.MS_ENH_RSA_AES_PROV;
import static org.qyouti.winselfcert.WindowsCertificateGenerator.PROV_RSA_AES;

/**
 *
 * @author maber01
 */
public class WindowsPasswordHandler implements EncryptedCompositeFilePasswordHandler
{
  
  Properties encryptionproperties;
  String name;
  PrivateKey privatekey;
  PublicKey publickey;
  
  

  /**
   * This constructor wants a name - other implementations might ask
   * for other stuff. This is not part of the interface so its whatever
   * the implementation needs. For example, there may be a pass phrase.
   * 
   * @param name 
   */
  public WindowsPasswordHandler() throws KeyStoreException
  {
    encryptionproperties = new Properties();
    encryptionproperties.setProperty( "windowspasswordhandler", "true" );
    name = System.getProperty("user.name");
    initKeys( name );
  }
  
  @Override
  public char[] decryptPassword(byte[] cipher, Properties properties)
  {
    String prop = properties.getProperty("windowspasswordhandler");
    if ( prop == null || !(prop.equals("true")) )
      return null;  // wrong handler

    // decrypt
    return this.decryptWindowsPassphrase( this.name, cipher );
  }

  @Override
  public byte[] encryptPassword(char[] plaintext)
  {
    return this.encryptWindowsPassphrase(plaintext);
  }

  @Override
  public Properties getEncryptionProperties()
  {
    return encryptionproperties;
  }




  private static String getWindowsKeyAlias( String userid )
  {
    final String preamble = "Quipto password guard for ";
    return preamble + userid;
  }
  
  
  /**
   * This Windows key pair is ONLY used to encrypt a password which in turn is
   * used to decrypt a standard OpenPGP encrypted private key.
   * @param alias
   * @return 
   */
  private static boolean createWindowsKeyPair( String alias )
  {
    try
    {
      BigInteger serial;
      WindowsCertificateGenerator wcg = new WindowsCertificateGenerator();
      
      serial = wcg.generateSelfSignedCertificate(
              "CN=" + alias,
              "qyouti-" + UUID.randomUUID().toString(),
              MS_ENH_RSA_AES_PROV,
              PROV_RSA_AES,
              true,
              2048,
              CRYPT_USER_PROTECTED
      );
      if (serial == null)
      {
        System.out.println("Failed to make certificate.");
        return false;
      }
      else
      {
        System.out.println("Serial number = " + serial.toString(16) );
        System.out.println("As long = " + Long.toHexString( serial.longValue() ) );        
      }

      return true;
    }
    catch (Exception e)
    {
      System.out.println( "Unable to create Windows password guard." );
      return false;
    }
  }

  private void initKeys( String userid ) throws KeyStoreException
  {
    final String preamble = "Quipto password guard for ";
    String alias = preamble + userid;
    getWindowsKeys( alias );
    if ( publickey == null )
    {
      createWindowsKeyPair( alias );
      getWindowsKeys( alias );
    }
  }
  
  private void getWindowsKeys( String alias ) throws KeyStoreException
  {
    try
    {
      publickey = null;
      privatekey = null;
      KeyStore keystore = KeyStore.getInstance("Windows-MY");
      keystore.load(null, null);  // Load keystore 
      Certificate[] chain = keystore.getCertificateChain(alias);
      if ( chain == null || chain.length == 0 )
        return;
      Certificate certificate = chain[chain.length - 1];
      publickey = certificate.getPublicKey();
      privatekey = (PrivateKey)keystore.getKey( alias, null );
    }
    catch ( IOException | NoSuchAlgorithmException | CertificateException | UnrecoverableKeyException ex )
    {
      Logger.getLogger(StandardRSAKeyBuilderSigner.class.getName()).log(Level.SEVERE, null, ex);
      publickey = null;
      privatekey = null;
    }
  }
  
  private byte[] encryptWindowsPassphrase( char[] p )
  {
    try
    {
      Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
      cipher.init( Cipher.ENCRYPT_MODE, publickey );
      return cipher.doFinal( new String(p).getBytes() );
    }
    catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException ex)
    {
      Logger.getLogger(StandardRSAKeyBuilderSigner.class.getName()).log(Level.SEVERE, null, ex);
    }
    return null;
  }
  
  private char[] decryptWindowsPassphrase( String alias, String base64encrypted )
  {
    byte[] encrypted = java.util.Base64.getDecoder().decode(base64encrypted);
    return decryptWindowsPassphrase( privatekey, encrypted );
  }
  
  public char[] decryptWindowsPassphrase( String alias, byte[] encrypted )
  {
    return decryptWindowsPassphrase( privatekey, encrypted );
  }
  
  public static char[] decryptWindowsPassphrase( PrivateKey prikey, byte[] encrypted )
  {
    try
    {
      Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
      cipher.init( Cipher.DECRYPT_MODE, prikey );
      byte[] decrypt = cipher.doFinal( encrypted );
      System.out.println( "Password is: " + new String( decrypt, "UTF8" ) );
      return new String( decrypt, "UTF8" ).toCharArray();
    }
    catch ( UnsupportedEncodingException | InvalidKeyException | NoSuchAlgorithmException | BadPaddingException | IllegalBlockSizeException | NoSuchPaddingException e )
    {
      e.printStackTrace();
    }
    
    return null;
  }

  
}
