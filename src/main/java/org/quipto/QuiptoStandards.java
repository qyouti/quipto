/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.quipto;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * A holder for constants relating to quipto protocols
 * @author maber01
 */
public class QuiptoStandards
{
  /**
   * Notation name for signatures on OpenPGP public keys. Indicates the Windows digital certificate that has
   * the private key that can be used to decrypt the password protecting the private key paired with
   * this OpenPGP public key.  EXPERIMENTAL
   */
  public final static String NOTATION_NAME_WINDOWS_ALIAS = "windowsalias@github.com/qyouti/quipto";
  
  /**
   * Notation name for signatures on OpenPGP public keys. Contains base64 encoded, RSA encrypted password
   * that can be used to unlock the paired OpenPGP private key.  EXPERIMENTAL
   */
  public final static String NOTATION_NAME_ENCRYPTED_PASSPHRASE = "windowsencryptedpassphrase@github.com/qyouti/quipto";  
  
  
  public final static String ENCRYPTION_BOOTSTRAP_PROPERTIES_FILENAME  = ".encryption/bootstrap/properties.xml";
  public final static String ENCRYPTION_BOOTSTRAP_PRIVATE_KEY_FILENAME = ".encryption/bootstrap/privatekey.bin";
  public final static String ENCRYPTION_BOOTSTRAP_PUBLIC_KEY_FILENAME  = ".encryption/bootstrap/publickey.bin";
  
  /**
   * 
   */
  public final static String ENCRYPTION_BOOTSTRAP_METHOD_PROPERTYNAME     = "org.quipto.compositefile.encryptionbootstrapmethod";
  public final static String ENCRYPTION_BOOTSTRAP_ALIAS_PROPERTYNAME      = "org.quipto.compositefile.encryptionbootstrapalias";
  public final static String ENCRYPTION_BOOTSTRAP_FILENAME_PROPERTYNAME   = "org.quipto.compositefile.encryptionbootstrapfilename";
  public final static String ENCRYPTION_BOOTSTRAP_METHOD_WINDOWS          = "windows";  
  public final static String ENCRYPTION_BOOTSTRAP_METHOD_EMAILANDPASSWORD = "password";  
  
  
  public final static char[] SECRET_KEY_STANDARD_PASS = "This does not need to be secure because the whole secret key ring collection is encrypted.".toCharArray();

  private static SecureRandom sr = null;
  static
  {
    try
    {
      sr = SecureRandom.getInstanceStrong();
    }
    catch (NoSuchAlgorithmException ex)
    {
      Logger.getLogger(QuiptoStandards.class.getName()).log(Level.SEVERE, null, ex);
    }
  }
  
  private static final String PASSCHARS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNPQRSTUVWXYZ0123456789.,;:[]}{=+-_)(*&%$";  
  public static char[] generateRandomPassphrase()
  {
    return generateRandomCharArray( PASSCHARS, 30 );
  }
  
  private static char[] generateRandomCharArray( String chars, int length )
  {
    char[] str = new char[length];
    for (int i = 0; i < str.length; i++)
      str[i] = chars.charAt(sr.nextInt(chars.length()));
    return str;
  }
  
  public static String generateRandomId( int bits )
  {
    return generateRandomNumberAsString( (bits+7)/8 );
  }
  
  public static String generateRandomNumberAsString( int bytelength )
  {
    byte[] buffer = new byte[bytelength];
    sr.nextBytes(buffer);
    BigInteger big = new BigInteger( 1, buffer );
    return big.toString(16);
  }
}
