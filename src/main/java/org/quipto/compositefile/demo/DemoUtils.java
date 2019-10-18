/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.quipto.compositefile.demo;

import java.io.IOException;
import java.io.InputStream;

/**
 *
 * @author maber01
 */
public class DemoUtils
{
  public static void dumpStream( InputStream in ) throws IOException
  {
    int x;
    System.out.print( "0  :  " );
    for ( int i=0; (x = in.read()) >= 0; i++ )
    {
      if ( x>15 )
        System.out.print( Character.toString((char)x) /*Integer.toHexString(x)*/ );
      else
        System.out.print( "[0x" +Integer.toHexString(x) + "]" );
      if ( i%64 == 63 )
        System.out.print( "\n" +  Integer.toHexString(i+1) + "  :  " );
    }    
  }
}
