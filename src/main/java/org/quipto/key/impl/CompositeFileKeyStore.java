/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.quipto.key.impl;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Properties;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.operator.KeyFingerPrintCalculator;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.quipto.compositefile.EncryptedCompositeFile;
import org.quipto.compositefile.EncryptedCompositeFileUser;
import org.quipto.compositefile.WrongPasswordException;

/**
 *
 * @author maber01
 */
public class CompositeFileKeyStore
{
  private static final String INDEXFILENAME = "keyindex.xml";
  private static final KeyFingerPrintCalculator fingerprintcalc = new BcKeyFingerprintCalculator();
  
  protected File file;
  protected EncryptedCompositeFileUser eu;
  //protected EncryptedCompositeFile compositefile=null;
  Properties index;

  long filedate=0L;
  long filesize=0L;
  
  //ArrayList<PGPPublicKeyRing>     publiclist = new ArrayList<>();
  HashMap<Long,PGPPublicKeyRing> publictable = new HashMap<>();
  //ArrayList<PGPSecretKeyRing>     secretlist = new ArrayList<>();
  HashMap<Long,PGPSecretKeyRing> secrettable = new HashMap<>();
  
  
  public CompositeFileKeyStore( File file ) throws IOException
  {
    this.file = file;
    this.eu = eu;
  }

  public String getCustomPassphraseType() throws IOException
  {
    try ( EncryptedCompositeFile compositefile = new EncryptedCompositeFile( file, true, false ) )
    {
      return compositefile.getCustomPassphraseType();
    }
    catch ( IOException ex)
    {
      Logger.getLogger(CompositeFileKeyStore.class.getName()).log(Level.SEVERE, null, ex);
      throw ex;
    }
  }
  
  public void setUser( EncryptedCompositeFileUser eu ) throws IOException, WrongPasswordException
  {
    this.eu = eu;
    openAndLoadAll();
  }
  
  private void openAndLoadAll() throws IOException, WrongPasswordException
  {
    try ( EncryptedCompositeFile compositefile = new EncryptedCompositeFile( file, true, false ) )
    {
      index = new Properties();
      compositefile.setUser( eu );    
      if ( compositefile.exists(INDEXFILENAME) )
        loadIndices(compositefile);
      
      loadAllSecretKeyRings( compositefile );
      loadAllPublicKeyRings( compositefile );
    }
    catch ( IOException ex)
    {
      Logger.getLogger(CompositeFileKeyStore.class.getName()).log(Level.SEVERE, null, ex);
      throw ex;
    }
    catch (NoSuchProviderException | NoSuchAlgorithmException ex)
    {
      Logger.getLogger(CompositeFileKeyStore.class.getName()).log(Level.SEVERE, null, ex);
    }
    
  }
  


  public void loadAllPublicKeyRings( EncryptedCompositeFile compositefile ) throws IOException
  {
    //publiclist.clear();
    publictable.clear();
    for ( String name : compositefile.getComponentNames() )
    {
      String[] parts = name.split("/");
      if ( parts.length == 2 && "publickeys".equals(parts[0]) )
      {
        String[] subparts = parts[1].split( "\\." );
        if ( subparts.length == 2 && "gpg".equals(subparts[1]) )
        {
          long masterkeyid = Long.parseUnsignedLong( subparts[0], 16 );
          try ( InputStream in = compositefile.getDecryptingInputStream( name ) )
          {
            publictable.put( masterkeyid, new PGPPublicKeyRing( in, fingerprintcalc ) );
          }
        }
      }
    }
  }
  
  public void loadAllSecretKeyRings( EncryptedCompositeFile compositefile ) throws IOException
  {
    //secretlist.clear();
    secrettable.clear();
    for ( String name : compositefile.getComponentNames() )
    {
      String[] parts = name.split("/");
      if ( parts.length == 2 && "secretkeys".equals(parts[0]) )
      {
        String[] subparts = parts[1].split( "\\." );
        if ( subparts.length == 2 && "gpg".equals(subparts[1]) )
        {
          long masterkeyid = Long.parseUnsignedLong( subparts[0], 16 );
          try ( InputStream in = compositefile.getDecryptingInputStream( name ) )
          {
            secrettable.put( masterkeyid, new PGPSecretKeyRing( in, fingerprintcalc ) );
          }
          catch (PGPException ex)
          {
            Logger.getLogger(CompositeFileKeyStore.class.getName()).log(Level.SEVERE, null, ex);
            throw new IOException( "Decryption problem. ", ex );
          }
        }
      }
    }
  }


  
  public void close()
  {
  }
  
  
  private void saveIndices( EncryptedCompositeFile compositefile )
  {
    try ( OutputStream out = compositefile.getEncryptingOutputStream(INDEXFILENAME, true, false) )
    {
      index.storeToXML( out, "Index of keys" );
    }
    catch (IOException ex)
    {
      Logger.getLogger(CompositeFileKeyStore.class.getName()).log(Level.SEVERE, null, ex);
    }
  }
  
  private void loadIndices( EncryptedCompositeFile compositefile )
  {
    try ( InputStream in = compositefile.getDecryptingInputStream(INDEXFILENAME) )
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

  public void addAccessToPublicKey( PGPPublicKey publickey ) throws IOException, NoSuchProviderException, NoSuchAlgorithmException, WrongPasswordException
  {
    try ( EncryptedCompositeFile compositefile = new EncryptedCompositeFile( file, true, false ) )
    {
      compositefile.setUser( eu );    
      compositefile.addPublicKey(publickey);
    }
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
  
  private void indexPublicUserIDs( EncryptedCompositeFile compositefile, PGPPublicKeyRing publickeyring, String strmasterkeyid )
  {
    indexUserIDs( compositefile, publickeyring.getPublicKeys(), strmasterkeyid );
  } 
  
  private void indexSecretUserIDs( EncryptedCompositeFile compositefile, PGPSecretKeyRing secretkeyring, String strmasterkeyid )
  {
    indexUserIDs( compositefile, secretkeyring.getPublicKeys(), strmasterkeyid );
  } 
  
  private void indexUserIDs( EncryptedCompositeFile compositefile, Iterator<PGPPublicKey> keyiter, String strmasterkeyid )
  {
    while ( keyiter.hasNext() )
    {
      PGPPublicKey key = keyiter.next();
      String strkeyid = Long.toHexString(key.getKeyID());
      Iterator<String> useriditer = key.getUserIDs();
      while ( useriditer.hasNext() )
      {
        String userid = useriditer.next();
        index.setProperty("userid_" + userid, strmasterkeyid);
      }
      Iterator<PGPSignature> sigiter = key.getSignatures();
      while ( sigiter.hasNext() )
      {
        PGPSignature sig = sigiter.next();
        String signerkeyid = Long.toHexString( sig.getKeyID() );
        String currentvalue = index.getProperty("signer_" + signerkeyid);
        if ( currentvalue == null )
          currentvalue = "";
        else
          currentvalue = currentvalue + ",";
        index.setProperty("signer_" + signerkeyid, currentvalue + strkeyid);
      }
    }    
    saveIndices( compositefile );    
  }
  
  /**
   * Find the IDs of keys in this store that have signatures made with the specified signing key.
   * @param signerkeyid
   * @return 
   */
  public Set<Long> getSignedKeyIds( long signerkeyid )
  {
    HashSet<Long> set = new HashSet<>();
    String strsignerkeyid = Long.toHexString( signerkeyid );
    String currentvalue = index.getProperty("signer_" + strsignerkeyid);
    if ( currentvalue == null || currentvalue == "" )
      return set;
    String[] strkeyid = currentvalue.split(",");
    for ( int i=0; i<strkeyid.length; i++ )
      set.add( Long.parseUnsignedLong(strkeyid[i], 16) );
    return set;
  }
  
  public void setPublicKeyRing( PGPPublicKeyRing keyring ) throws IOException, WrongPasswordException
  {
    PGPPublicKey key = CompositeFileKeyStore.getMasterPublicKey(keyring);
    if ( key == null )
      throw new IOException( "Cannot store a keyring that lacks a master key.");
    long masterkeyid = key.getKeyID();
    
    // put all the new keys in a list
    ArrayList<PGPPublicKey> mergedkeylist = new ArrayList<>();
    ArrayList<PGPPublicKey> newkeylist = new ArrayList<>();
    Iterator<PGPPublicKey> iter = keyring.getPublicKeys();
    while ( iter.hasNext() )
      newkeylist.add( iter.next() );
    
    // what key ring is already in the store?
    PGPPublicKeyRing existingkeyring = getPublicKeyRing( masterkeyid );
    
    for ( PGPPublicKey newkey : newkeylist )
    {
      PGPPublicKey existingkey=null;
      if ( existingkeyring != null )
        existingkey = existingkeyring.getPublicKey( newkey.getKeyID() );
      PGPPublicKey mergedkey;
      if ( existingkey == null )
        mergedkey = newkey;
      else
      {
        mergedkey = existingkey;
        // add signatures from new key to the existing key
        Iterator<PGPSignature> itersig = newkey.getSignatures();
        while ( itersig.hasNext() )
        {
          PGPSignature newsig = itersig.next();
          Iterator<PGPSignature> existingsigiter = existingkey.getSignatures();
          boolean found = false;
          while ( existingsigiter.hasNext() )
          {
            PGPSignature existingsig = existingsigiter.next();
            if ( Arrays.equals( newsig.getEncoded(), existingsig.getEncoded() ) )
            {
              found = true;
              break;
            }
          }
          if ( !found )
            mergedkey = PGPPublicKey.addCertification( mergedkey , newsig );
        }
      }
      mergedkeylist.add(mergedkey);
    }
    
    PGPPublicKeyRing mergedpublickeyring = new PGPPublicKeyRing( mergedkeylist );
    storePublicKeyRing( mergedpublickeyring, masterkeyid );
  }

  public void setSecretKeyRing( PGPSecretKeyRing keyring ) throws IOException, WrongPasswordException
  {
    PGPSecretKey key = CompositeFileKeyStore.getMasterSecretKey(keyring);
    if ( key == null )
      throw new IOException( "Cannot store a keyring that lacks a master key.");
    long masterkeyid = key.getKeyID();

    storeSecretKeyRing( keyring, masterkeyid );
  }

  
  private void storePublicKeyRing( PGPPublicKeyRing mergedpublickeyring, long masterkeyid ) throws IOException, WrongPasswordException
  {
    String strkeyid = Long.toHexString( masterkeyid );
    String filename = getPublicKeyFilename( masterkeyid );
    try ( EncryptedCompositeFile compositefile = new EncryptedCompositeFile( file, true, false ) )
    {
      compositefile.setUser( eu );
      try ( OutputStream out = compositefile.getEncryptingOutputStream(filename, true, false) )
      {
        mergedpublickeyring.encode(out);
      }
      catch (IOException ex)
      {
        Logger.getLogger(CompositeFileKeyStore.class.getName()).log(Level.SEVERE, null, ex);
      }

      indexPublicUserIDs( compositefile, mergedpublickeyring, strkeyid );
      publictable.put( masterkeyid, mergedpublickeyring );
    }
    catch (NoSuchProviderException | NoSuchAlgorithmException ex)
    {
      Logger.getLogger(CompositeFileKeyStore.class.getName()).log(Level.SEVERE, null, ex);
      throw new IOException( ex );
    }    
  }
  
  private void storeSecretKeyRing( PGPSecretKeyRing keyring, long masterkeyid ) throws IOException, WrongPasswordException
  {
    String strkeyid = Long.toHexString( masterkeyid );
    String filename = getSecretKeyFilename( masterkeyid );
    try ( EncryptedCompositeFile compositefile = new EncryptedCompositeFile( file, true, false ) )
    {
      compositefile.setUser( eu );
      try ( OutputStream out = compositefile.getEncryptingOutputStream(filename, true, false) )
      {
        keyring.encode(out);
      }
      catch (IOException ex)
      {
        Logger.getLogger(CompositeFileKeyStore.class.getName()).log(Level.SEVERE, null, ex);
        throw ex;
      }

      indexSecretUserIDs( compositefile, keyring, strkeyid );
      secrettable.put( masterkeyid, keyring );
    }
    catch (NoSuchProviderException | NoSuchAlgorithmException ex)
    {
      Logger.getLogger(CompositeFileKeyStore.class.getName()).log(Level.SEVERE, null, ex);
      throw new IOException( ex );
    }    
  }
    
  
  public boolean doesPublicKeyRingExist( long masterid )
  {
    return publictable.containsKey( masterid );
  }

  
  public PGPPublicKeyRing getPublicKeyRing( long masterid )
  {
    return publictable.get( masterid );
  }

  public PGPSecretKeyRing getSecretKeyRing( long masterid )
  {
    return secrettable.get( masterid );
  }
  
  public PGPPublicKeyRing getPublicKeyRing( String userid )
  {
    String strkeyid = index.getProperty("userid_" + userid);
    if ( strkeyid == null ) return null;
    return getPublicKeyRing( Long.parseUnsignedLong(strkeyid, 16) );
  }  
  
  public PGPSecretKeyRing getSecretKeyRing( String userid )
  {
    String strkeyid = index.getProperty("userid_" + userid);
    if ( strkeyid == null ) return null;
    return getSecretKeyRing( Long.parseUnsignedLong(strkeyid, 16) );
  }  
  
  public List<PGPPublicKeyRing> getAllPublicKeyRings()
  {
    ArrayList<PGPPublicKeyRing> list = new ArrayList<>();
    list.addAll( publictable.values() );
    return list;
  }
  
  public List<PGPSecretKeyRing> getAllSecretKeyRings()
  {
    ArrayList<PGPSecretKeyRing> list = new ArrayList<>();
    list.addAll( secrettable.values() );
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
