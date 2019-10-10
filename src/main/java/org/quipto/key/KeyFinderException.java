/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.quipto.key;

/**
 *
 * @author maber01
 */
public class KeyFinderException
        extends Exception
{

  /**
   * Creates a new instance of <code>QuiptoKeyFinderException</code> without detail message.
   */
  public KeyFinderException()
  {
  }

  /**
   * Constructs an instance of <code>QuiptoKeyFinderException</code> with the specified detail message.
   *
   * @param msg the detail message.
   */
  public KeyFinderException(String msg)
  {
    super(msg);
  }
}
