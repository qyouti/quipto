/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.quipto.trust;

import java.io.IOException;

/**
 * An IOException that wraps a TrustContextReport
 * @author maber01
 */
public class TrustContextException
        extends IOException
{
  TrustContextReport report;
  
  /**
   * Creates a new instance of <code>TrustContextException</code> without detail message.
   */
  public TrustContextException( TrustContextReport report )
  {
    super( report.getMessage() );
    this.report = report;
  }

  public TrustContextReport getReport()
  {
    return report;
  }
  
  
}
