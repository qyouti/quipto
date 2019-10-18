/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.quipto.compositefile;

import java.util.Properties;
import org.bouncycastle.openpgp.PGPPrivateKey;

/**
 * Implementations of this interface provide a way to obtain a key pair from the
 * composite file without having to have already loaded a keypair from somewhere 
 * else first.  For example, the user knows a password or the user has exclusive
 * access to a cryptographic resource.
 * 
 * @author maber01
 */
public interface EncryptionBootstrapHandler
{
  PGPPrivateKey loadBootstrapPrivateKey( byte[] raw, Properties props );
  PGPPrivateKey loadBootstrapPublicKey( byte[] raw, Properties props );
}
