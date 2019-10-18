/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.quipto.compositefile;

import java.util.Properties;

/**
 * Used to provide plug-in password encryption and decryption functionality.
 * Assumed to be for and by the same person. I.e. unlike the use of public/private
 * key pairs it isn't possible for one person to encrypt a password for another 
 * person using this mechanism.
 * 
 * @author maber01
 */
public interface EncryptedCompositeFilePasswordHandler
{
  /**
   * Asks handler to decrypt the password which comes with some
   * plaintext properties.
   * 
   * @param cipher
   * @param properties
   * @return Either the decrypted password or null to indicate that this is the wrong kind of handler
   */
  public char[] decryptPassword( byte[] cipher, Properties properties );
  
  /**
   * Asks handler to encrypt using its own properties
   * @param plaintext
   * @return 
   */
  public byte[] encryptPassword( char[] plaintext );
  
  /**
   * Return the properties this handler uses to encrypt.
   * @return 
   */
  public Properties getEncryptionProperties();  
}
