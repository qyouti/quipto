/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.quipto.key.impl;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Properties;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.operator.KeyFingerPrintCalculator;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.quipto.compositefile.EncryptedCompositeFile;
import org.quipto.compositefile.EncryptedCompositeFileUser;

/**
 *
 * @author maber01
 */
public class CompositeFileKeyStore
{
  private static final String INDEXFILENAME = "keysindexedbyuserid.xml";
  private static final KeyFingerPrintCalculator fingerprintcalc = new BcKeyFingerprintCalculator();
  
  EncryptedCompositeFile compositefile;
  EncryptedCompositeFileUser compositefileuser;
  Properties index;

  public CompositeFileKeyStore( EncryptedCompositeFile compositefile, EncryptedCompositeFileUser compositefileuser ) throws IOException, NoSuchProviderException, NoSuchAlgorithmException
  {
    this.compositefile = compositefile;
    this.compositefileuser = compositefileuser;
    if ( compositefileuser.getPasswordHandler() != null )
      compositefile.addCustomUser(compositefileuser);
    else if ( compositefileuser.getKeyFinder() != null )
    {
      PGPPublicKey publickey = compositefileuser.getKeyFinder().getSecretKeyForDecryption().getPublicKey();
      compositefile.addPublicKey(compositefileuser, publickey);
    }
    
    index = new Properties();
    if ( compositefile.exists(INDEXFILENAME) )
      loadIndices();
    
  }
  
  public void close()
  {
    try
    {
      compositefile.close();
    }
    catch (IOException ex)
    {
      Logger.getLogger(CompositeFileKeyStore.class.getName()).log(Level.SEVERE, null, ex);
    }
    compositefile = null;
  }
  
  private void saveIndices()
  {
    try ( OutputStream out = compositefile.getEncryptingOutputStream(compositefileuser, INDEXFILENAME, true, false) )
    {
      index.storeToXML( out, "Index of keys" );
    }
    catch (IOException ex)
    {
      Logger.getLogger(CompositeFileKeyStore.class.getName()).log(Level.SEVERE, null, ex);
    }
  }
  
  private void loadIndices()
  {
    try ( InputStream in = compositefile.getDecryptingInputStream(compositefileuser, INDEXFILENAME) )
    {
      //System.out.println( "loading indices");
      index.loadFromXML(in);
      //System.out.println( "loaded indices");
    }
    catch (IOException ex)
    {
      Logger.getLogger(CompositeFileKeyStore.class.getName()).log(Level.SEVERE, null, ex);
    }    
  }

  public void addAccessToPublicKey( PGPPublicKey publickey ) throws IOException, NoSuchProviderException, NoSuchAlgorithmException
  {
    compositefile.addPublicKey(compositefileuser, publickey);
  }
  
  public static PGPPublicKey getMasterPublicKey( PGPPublicKeyRing keyring )
  {
    Iterator<PGPPublicKey> iter = keyring.getPublicKeys();
    while ( iter.hasNext() )
    {
      PGPPublicKey publickey = iter.next();
      if ( publickey.isMasterKey() )
        return publickey;
    }
    return null;
  }
  
  public static PGPSecretKey getMasterSecretKey( PGPSecretKeyRing keyring )
  {
    Iterator<PGPSecretKey> iter = keyring.getSecretKeys();
    while ( iter.hasNext() )
    {
      PGPSecretKey secretkey = iter.next();
      if ( secretkey.isMasterKey() )
        return secretkey;
    }
    return null;
  }
  
  private void indexPublicUserIDs( PGPPublicKeyRing publickeyring, String strmasterkeyid )
  {
    indexUserIDs( publickeyring.getPublicKeys(), strmasterkeyid );
  } 
  
  private void indexSecretUserIDs( PGPSecretKeyRing secretkeyring, String strmasterkeyid )
  {
    indexUserIDs( secretkeyring.getPublicKeys(), strmasterkeyid );
  } 
  
  private void indexUserIDs( Iterator<PGPPublicKey> keyiter, String strmasterkeyid )
  {
    while ( keyiter.hasNext() )
    {
      PGPPublicKey key = keyiter.next();
      Iterator<String> useriditer = key.getUserIDs();
      while ( useriditer.hasNext() )
      {
        String userid = useriditer.next();
        index.setProperty(userid, strmasterkeyid);
      }
    }    
    saveIndices();    
  }
  
  public void setPublicKeyRing( PGPPublicKeyRing keyring ) throws IOException
  {
    PGPPublicKey key = CompositeFileKeyStore.getMasterPublicKey(keyring);
    if ( key == null )
      throw new IOException( "Cannot store a keyring that lacks a master key.");
    long masterkeyid = key.getKeyID();
    String strkeyid = Long.toHexString( masterkeyid );
    String filename = getPublicKeyFilename( masterkeyid );
    
    
    try ( OutputStream out = compositefile.getEncryptingOutputStream(compositefileuser, filename, true, false) )
    {
      keyring.encode(out);
    }
    catch (IOException ex)
    {
      Logger.getLogger(CompositeFileKeyStore.class.getName()).log(Level.SEVERE, null, ex);
    }
    
    indexPublicUserIDs( keyring, strkeyid );
  }

  public void setSecretKeyRing( PGPSecretKeyRing keyring ) throws IOException
  {
    PGPSecretKey key = CompositeFileKeyStore.getMasterSecretKey(keyring);
    if ( key == null )
      throw new IOException( "Cannot store a keyring that lacks a master key.");
    long masterkeyid = key.getKeyID();
    String strkeyid = Long.toHexString( masterkeyid );
    String filename = getSecretKeyFilename( masterkeyid );    
    
    try ( OutputStream out = compositefile.getEncryptingOutputStream(compositefileuser, filename, true, false) )
    {
      keyring.encode(out);
    }
    catch (IOException ex)
    {
      Logger.getLogger(CompositeFileKeyStore.class.getName()).log(Level.SEVERE, null, ex);
    }

    indexSecretUserIDs( keyring, strkeyid );
  }

  
  public PGPPublicKeyRing getPublicKeyRing( long masterid )
  {
    String filename = getPublicKeyFilename( masterid );
    if ( !compositefile.exists(filename) )
      return null;

    //System.out.println( "Loading public key ring collection" );
    try ( InputStream in = compositefile.getDecryptingInputStream(compositefileuser, filename) )
    {
      return new PGPPublicKeyRing( in, fingerprintcalc );
    }
    catch (IOException ex)
    {
      Logger.getLogger(CompositeFileKeyStore.class.getName()).log(Level.SEVERE, null, ex);
    }
    
    return null;
  }

  public PGPSecretKeyRing getSecretKeyRing( long masterid )
  {
    String filename = getSecretKeyFilename( masterid );
    if ( !compositefile.exists(filename) )
      return null;

    try ( InputStream in = compositefile.getDecryptingInputStream(compositefileuser, filename) )
    {
      return new PGPSecretKeyRing( in, fingerprintcalc );
    }
    catch (IOException | PGPException ex)
    {
      Logger.getLogger(CompositeFileKeyStore.class.getName()).log(Level.SEVERE, null, ex);
    }
    
    return null;
  }
  
  public PGPPublicKeyRing getPublicKeyRing( String userid )
  {
    String strkeyid = index.getProperty(userid);
    if ( strkeyid == null ) return null;
    return getPublicKeyRing( Long.parseUnsignedLong(strkeyid, 16) );
  }  
  
  public PGPSecretKeyRing getSecretKeyRing( String userid )
  {
    String strkeyid = index.getProperty(userid);
    if ( strkeyid == null ) return null;
    return getSecretKeyRing( Long.parseUnsignedLong(strkeyid, 16) );
  }  
  
  public List<PGPPublicKeyRing> getAllPublicKeyRings()
  {
    ArrayList<PGPPublicKeyRing> list = new ArrayList<>();
    for ( String name : compositefile.getComponentNames() )
    {
      String[] parts = name.split("/");
      if ( parts.length == 2 && "publickeys".equals(parts[0]) )
      {
        String[] subparts = parts[1].split( "\\." );
        if ( subparts.length == 2 && "gpg".equals(subparts[1]) )
        {
          long masterkeyid = Long.parseUnsignedLong( subparts[0], 16 );
          PGPPublicKeyRing keyring = getPublicKeyRing( masterkeyid );
          if ( keyring != null )
            list.add(keyring);
        }
      }
    }
    return list;
  }
  
  
  public String getPublicKeyFilename( long id )
  {
    return "publickeys/" + Long.toHexString(id) + ".gpg";
  }

  public String getSecretKeyFilename( long id )
  {
    return "secretkeys/" + Long.toHexString(id) + ".gpg";
  }
}
