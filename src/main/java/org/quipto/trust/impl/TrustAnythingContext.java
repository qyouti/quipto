/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.quipto.trust.impl;

import org.bouncycastle.openpgp.PGPPublicKey;
import org.quipto.trust.TrustContext;
import org.quipto.trust.TrustContextReport;

/**
 * Silly implementation that trusts any public key
 * 
 * @author maber01
 */
public class TrustAnythingContext implements TrustContext
{
  /**
   * Is the public key trusted. Yes, always!
   * @param pubkey
   * @return 
   */
  @Override
  public TrustContextReport checkTrusted( long signerkeyid )
  {
    return new TrustContextReport( true, "Trusted." );
  }
  
}
