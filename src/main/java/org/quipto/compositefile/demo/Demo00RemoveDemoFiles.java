/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.quipto.compositefile.demo;

import java.io.File;

/**
 *
 * @author jon
 */
public class Demo00RemoveDemoFiles
{

  public static void removeFiles( File directory )
  {
    File[] list = directory.listFiles();
    for ( File item : list )
    {
      if ( item.isDirectory() )
        removeFiles( item );
      else
      {
        if ( !item.getName().startsWith( "readme" ) )
          item.delete();
      }
    }
  }
  
  /**
   * @param args the command line arguments
   */
  public static void main(String[] args)
  {
    File base = new File( "demo" );
    removeFiles( base );
  }
  
}
