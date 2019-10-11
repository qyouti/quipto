/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.quipto;

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
}
