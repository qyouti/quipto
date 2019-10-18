/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.quipto.trust;

import org.bouncycastle.openpgp.PGPPublicKey;

/**
 * Implementations of this interface represent a context within which some keys may or
 * may not be trusted. Different instantiations will be used to check the trust of keys
 * in different situations.  For example, working with encrypted files in two different 
 * folders may require use of two different trust contexts. 
 * 
 * @author maber01
 */
public interface TrustContext
{
  TrustContextReport checkTrusted( long signerkeyid );
}
