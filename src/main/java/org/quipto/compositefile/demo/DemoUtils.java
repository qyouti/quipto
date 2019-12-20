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
  
  // To test the use of file system access rights edit these aliases to match real
  // users of the filesystem where demo files are created. Windows style users will
  // be found by adding the user name from inside parentheses to the domain name
  // from the email address.
  
  public static class DemoUser
  {
    public String alias;
    public String folder;
    public char[] password;
    public DemoUser( String alias, String folder, String pass )
    {
      this.alias = alias;
      this.folder = folder;
      this.password = pass.toCharArray();
    }
  }
  
  public static final DemoUser ALICE = new DemoUser( "Alice (maber01) <alice@leedsbeckett.ac.uk>", "demo/home_of_alice", "alice" );
  public static final DemoUser BOB = new DemoUser( "Bob (barrow01) <bob@leedsbeckett.ac.uk>", "demo/home_of_bob", "bob" );
  public static final DemoUser CHARLIE = new DemoUser( "Charlie (croft01) <charlie@leedsbeckett.ac.uk>", "demo/home_of_charlie", "charlie" );
  public static final DemoUser DEBBIE = new DemoUser( "Debbie (gilber11) <debbie@leedsbeckett.ac.uk>", "demo/home_of_debbie", "debbie" );
  public static final DemoUser EDWARD = new DemoUser( "Edward (caden01) <edward@leedsbeckett.ac.uk>", "demo/home_of_edward", "edward" );
  public static final DemoUser FRED = new DemoUser( "Fred (mccann03) <fred@leedsbeckett.ac.uk>", "demo/home_of_fred", "fred" );
    
  
  
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
