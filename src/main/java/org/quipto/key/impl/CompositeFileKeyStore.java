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
import java.util.Iterator;
import java.util.Properties;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
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
    
    index = new Properties();
    if ( compositefile.exists(INDEXFILENAME) )
      loadIndices();
    
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
      index.loadFromXML(in);
    }
    catch (IOException ex)
    {
      Logger.getLogger(CompositeFileKeyStore.class.getName()).log(Level.SEVERE, null, ex);
    }    
  }

  private PGPPublicKeyRing getFirstPublicKeyRing( PGPPublicKeyRingCollection coll )
  {
    Iterator<PGPPublicKeyRing> iter = coll.getKeyRings();
    if ( !iter.hasNext() ) return null;
    return iter.next();
  }
  
  private PGPSecretKeyRing getFirstSecretKeyRing( PGPSecretKeyRingCollection coll )
  {
    Iterator<PGPSecretKeyRing> iter = coll.getKeyRings();
    if ( !iter.hasNext() ) return null;
    return iter.next();
  }
  
  private void indexPublicUserIDs( Iterator<PGPPublicKeyRing> iter, String strkeyid )
  {
    while ( iter.hasNext() )
    {
      PGPPublicKeyRing keyring = iter.next();
      Iterator<PGPPublicKey> keyiter = keyring.getPublicKeys();
      indexUserIDs( keyiter, strkeyid );
    }
    saveIndices();    
  } 
  
  private void indexSecretUserIDs( Iterator<PGPSecretKeyRing> iter, String strkeyid )
  {
    while ( iter.hasNext() )
    {
      PGPSecretKeyRing keyring = iter.next();
      Iterator<PGPPublicKey> keyiter = keyring.getPublicKeys();
      indexUserIDs( keyiter, strkeyid );
    }
    saveIndices();    
  } 
  
  private void indexUserIDs( Iterator<PGPPublicKey> keyiter, String strkeyid )
  {
    while ( keyiter.hasNext() )
    {
      PGPPublicKey key = keyiter.next();
      Iterator<String> useriditer = key.getUserIDs();
      while ( useriditer.hasNext() )
      {
        String userid = useriditer.next();
        index.setProperty(userid, strkeyid);
      }
    }    
  }
  
  public void setPublicKeyRingCollection( PGPPublicKeyRingCollection coll )
  {
    PGPPublicKeyRing first = getFirstPublicKeyRing( coll );
    if ( first == null ) return;
    long firstkeyid = first.getPublicKey().getKeyID();
    String strkeyid = Long.toHexString( firstkeyid );
    String filename = getPublicKeyFilename( firstkeyid );
    
    try ( OutputStream out = compositefile.getEncryptingOutputStream(compositefileuser, filename, true, false) )
    {
      coll.encode(out);
    }
    catch (IOException ex)
    {
      Logger.getLogger(CompositeFileKeyStore.class.getName()).log(Level.SEVERE, null, ex);
    }
    
    indexPublicUserIDs( coll.getKeyRings(), strkeyid );
  }

  public void setSecretKeyRingCollection( PGPSecretKeyRingCollection coll )
  {
    PGPSecretKeyRing first = getFirstSecretKeyRing( coll );
    if ( first == null ) return;
    long firstkeyid = first.getPublicKey().getKeyID();
    String strkeyid = Long.toHexString( firstkeyid );
    String filename = getSecretKeyFilename( firstkeyid );
    
    try ( OutputStream out = compositefile.getEncryptingOutputStream(compositefileuser, filename, true, false) )
    {
      coll.encode(out);
    }
    catch (IOException ex)
    {
      Logger.getLogger(CompositeFileKeyStore.class.getName()).log(Level.SEVERE, null, ex);
    }

    indexSecretUserIDs( coll.getKeyRings(), strkeyid );
  }

  
  public PGPPublicKeyRingCollection getPublicKeyRingCollection( long id )
  {
    String filename = getPublicKeyFilename( id );
    if ( !compositefile.exists(filename) )
      return null;

    try ( InputStream in = compositefile.getDecryptingInputStream(compositefileuser, filename) )
    {
      return new PGPPublicKeyRingCollection( in, fingerprintcalc );
    }
    catch (IOException | PGPException ex)
    {
      Logger.getLogger(CompositeFileKeyStore.class.getName()).log(Level.SEVERE, null, ex);
    }
    
    return null;
  }

  public PGPSecretKeyRingCollection getSecretKeyRingCollection( long id )
  {
    String filename = getSecretKeyFilename( id );
    if ( !compositefile.exists(filename) )
      return null;

    try ( InputStream in = compositefile.getDecryptingInputStream(compositefileuser, filename) )
    {
      return new PGPSecretKeyRingCollection( in, fingerprintcalc );
    }
    catch (IOException | PGPException ex)
    {
      Logger.getLogger(CompositeFileKeyStore.class.getName()).log(Level.SEVERE, null, ex);
    }
    
    return null;
  }
  
  public PGPPublicKeyRingCollection getPublicKeyRingCollection( String userid )
  {
    String strkeyid = index.getProperty(userid);
    if ( strkeyid == null ) return null;
    return getPublicKeyRingCollection( Long.parseUnsignedLong(strkeyid, 16) );
  }  
  
  public PGPSecretKeyRingCollection getSecretKeyRingCollection( String userid )
  {
    String strkeyid = index.getProperty(userid);
    if ( strkeyid == null ) return null;
    return getSecretKeyRingCollection( Long.parseUnsignedLong(strkeyid, 16) );
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
