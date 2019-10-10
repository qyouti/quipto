/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.quipto.trust;

/**
 *
 * @author maber01
 */
public class TrustContextReport
{
  final boolean trusted;
  final String message;

  public TrustContextReport(boolean trusted, String message)
  {
    this.trusted = trusted;
    this.message = message;
  }

  public boolean isTrusted()
  {
    return trusted;
  }

  public String getMessage()
  {
    return message;
  }
  
  
}
