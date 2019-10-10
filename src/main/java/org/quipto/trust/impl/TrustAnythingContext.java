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
 *
 * @author maber01
 */
public class TrustAnythingContext implements TrustContext
{

  @Override
  public TrustContextReport checkTrusted(PGPPublicKey pubkey)
  {
    return new TrustContextReport( true, "Trusted." );
  }
  
}
