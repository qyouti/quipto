/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.quipto.passwords;

import java.util.Properties;
import org.bouncycastle.util.Arrays;
import org.quipto.compositefile.EncryptedCompositeFilePasswordHandler;

/**
 *
 * @author maber01
 */
public class SillyPasswordHandler implements EncryptedCompositeFilePasswordHandler
{
  private static final String SUFFIX = " pretend encryption";
  
  Properties encryptionproperties;
  String name;

  /**
   * This constructor wants a name - other implementations might ask
   * for other stuff. This is not part of the interface so its whatever
   * the implementation needs. For example, there may be a pass phrase.
   * 
   * @param name 
   */
  public SillyPasswordHandler( String name )
  {
    this.name = name;
    encryptionproperties = new Properties();
    encryptionproperties.setProperty( "sillypasswordhandler", "true" );
    encryptionproperties.setProperty( "sillypasswordhandlername", name );
  }
  
  @Override
  public char[] decryptPassword(byte[] cipher, Properties properties)
  {
    String prop = properties.getProperty("sillypasswordhandler");
    if ( prop == null || !(prop.equals("true")) )
      return null;  // wrong handler

    String foundname = properties.getProperty( "sillypasswordhandlername" );
    if ( !name.equals(foundname) )
      return null; // wrong instance
    
    String s = new String( cipher );
    if ( !s.endsWith(SUFFIX) )
      return null; // encryption looks wrong
    
    // decrypt
    return s.substring(0, s.length() - SUFFIX.length() ).toCharArray();
  }

  @Override
  public byte[] encryptPassword(char[] plaintext)
  {
    byte[] suffix = " pretend encryption".getBytes();
    byte[] p = new String( plaintext ).getBytes();
    return Arrays.concatenate(p, suffix);
  }

  @Override
  public Properties getEncryptionProperties()
  {
    return encryptionproperties;
  }
  
}
