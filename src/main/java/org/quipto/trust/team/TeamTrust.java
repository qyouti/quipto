/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.quipto.trust.team;

import java.io.File;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSignature;
import org.quipto.compositefile.EncryptedCompositeFile;
import org.quipto.compositefile.EncryptedCompositeFilePasswordHandler;
import org.quipto.compositefile.EncryptedCompositeFileUser;
import org.quipto.key.KeyFinder;
import org.quipto.key.KeyFinderException;
import org.quipto.key.impl.CompositeFileKeyFinder;
import org.quipto.key.impl.CompositeFileKeyStore;
import org.quipto.trust.TrustContext;
import org.quipto.trust.TrustContextException;
import org.quipto.trust.TrustContextReport;
import org.quipto.trust.impl.TrustAnythingContext;

/**
 *
 * @author maber01
 */
public class TeamTrust implements TrustContext, KeyFinder
{
  static final int PERSONAL = 0;
  static final int TEAM     = 1;
  
  EncryptedCompositeFileUser[] eu = new EncryptedCompositeFileUser[2];
  CompositeFileKeyStore[] keystore = new CompositeFileKeyStore[2];
  CompositeFileKeyFinder[] keyfinder = new CompositeFileKeyFinder[2];

  public TeamTrust( String alias, EncryptedCompositeFilePasswordHandler passhandler, File personalkeystorefile, File teamkeystorefile ) throws IOException, NoSuchProviderException, NoSuchAlgorithmException, PGPException
  {
    try
    {
      File[] files = new File[2];
      files[0] = personalkeystorefile;
      files[1] = teamkeystorefile;
      eu[PERSONAL] = new EncryptedCompositeFileUser( passhandler );  // personal store uses password
      eu[TEAM]     = new EncryptedCompositeFileUser( keyfinder[0], new TrustAnythingContext() ); // shared store uses key from personal store
      for ( int i=0; i<2; i++ )
      {
        EncryptedCompositeFile compfile = EncryptedCompositeFile.getCompositeFile( files[i] );
        if ( i==PERSONAL )
          eu[PERSONAL] = new EncryptedCompositeFileUser( passhandler );  // personal store uses password
        if ( i==TEAM )
          eu[TEAM]     = new EncryptedCompositeFileUser( keyfinder[PERSONAL], new TrustAnythingContext() ); // shared store uses key from personal store        
        keystore[i] = new CompositeFileKeyStore( compfile, eu[i] );
        keyfinder[i] = new CompositeFileKeyFinder( keystore[i], alias, alias );
        keyfinder[i].init();
      }
    }
    catch (IOException ex)
    {
      Logger.getLogger(TeamTrust.class.getName()).log(Level.SEVERE, null, ex);
    }
  }

  public void close()
  {
    for ( int i=PERSONAL; i<TEAM; i++ )
      if ( keystore[i] != null )
        keystore[i].close();
  }
  
  public void addPublicKeyToTeamStore( PGPPublicKey publickey ) throws IOException, NoSuchProviderException, NoSuchAlgorithmException
  {
    ArrayList<PGPPublicKey> list = new ArrayList<>();
    list.add(publickey);
    keystore[TEAM].addAccessToPublicKey(publickey);
    keystore[TEAM].setPublicKeyRing( new PGPPublicKeyRing(list) );
  }
  
  public void addPublicKeyToPersonalStore( PGPPublicKey publickey ) throws IOException, NoSuchProviderException, NoSuchAlgorithmException
  {
    ArrayList<PGPPublicKey> list = new ArrayList<>();
    list.add(publickey);
    keystore[PERSONAL].setPublicKeyRing( new PGPPublicKeyRing(list) );
  }
  
  public void addAllTeamKeysToEncryptedCompositeFile( EncryptedCompositeFile compositefile, EncryptedCompositeFileUser eu ) throws IOException, NoSuchProviderException, NoSuchAlgorithmException
  {
    List<PGPPublicKeyRing> fulllist = keystore[TEAM].getAllPublicKeyRings();
    for ( PGPPublicKeyRing keyring : fulllist )
    {
      keyring.getPublicKey();  // the master key
      compositefile.addPublicKey( eu, keyring.getPublicKey() );
    }
  }
  
  @Override
  public TrustContextReport checkTrusted( long signerkeyid )
  {
    PGPPublicKey[] trustkeylist;
    try
    {
      trustkeylist = loadTrustChainPublicKeys( signerkeyid );
    }
    catch (TrustContextException ex)
    {
      Logger.getLogger(TeamTrust.class.getName()).log(Level.SEVERE, null, ex);
      return ex.getReport();
    }
    
    System.out.println( "Trust chain...");
    for ( PGPPublicKey key : trustkeylist )
    {
      System.out.println( "ID: " + Long.toHexString( key.getKeyID() ) + " First UserID " + key.getUserIDs().next() );    
    }
    System.out.println( "...End of Trust chain");
    
    return checkTrustChainPublicKeys( trustkeylist );
  }
  
  public PGPPublicKey[] loadTrustChainPublicKeys( long signerkeyid )
          throws TrustContextException
  {
    // Just load them by keyid without verification or other checks
    PGPPublicKey publickey;
    Iterator<PGPSignature> sigiter;
    PGPSignature sig;
    ArrayList<PGPPublicKey> list = new ArrayList<>();
    boolean selfsign=false;
    
    long keyid = signerkeyid;
    do
    {
      publickey = keyfinder[TEAM].findPublicKey( keyid );
      if ( publickey == null )
        throw new TrustContextException( new TrustContextReport( false, "Signing key that is not listed in the Trust file." ) );
      sigiter = publickey.getSignatures();
      if ( !sigiter.hasNext() )
        throw new TrustContextException( new TrustContextReport( false, "Signing key is not itself signed and cannot be trusted." ) );
      sig = sigiter.next();
      if ( sigiter.hasNext() )
        throw new TrustContextException( new TrustContextReport( false, "Signing key itself has more than one signature. This software cannot handle that." ) );
      list.add(publickey);
      if ( sig.getKeyID() == keyid )
        selfsign = true;
      keyid = sig.getKeyID();
    }
    while ( selfsign == false );
    
    return list.toArray( new PGPPublicKey[list.size()] );
  }
  
  public TrustContextReport checkTrustChainPublicKeys( PGPPublicKey[] trustkeylist )
  {
    // Check that each signature is kosher
    // Check that current user has a signed copy of one of the keys in the chain
    
    return new TrustContextReport( true, null );
  }
  
  
  @Override
  public String getPreferredAlias(PGPSecretKey secretkey)
  {
    return keyfinder[PERSONAL].getPreferredAlias(secretkey);
  }

  @Override
  public PGPPrivateKey getPrivateKey(PGPSecretKey secretkey)
  {
    return keyfinder[PERSONAL].getPrivateKey(secretkey);
  }

  @Override
  public PGPSecretKey getSecretKeyForDecryption()
  {
    return keyfinder[PERSONAL].getSecretKeyForDecryption();
  }

  @Override
  public PGPSecretKey getSecretKeyForSigning()
  {
    return keyfinder[PERSONAL].getSecretKeyForSigning();
  }

  @Override
  public PGPPublicKey findPublicKey(long keyid)
  {
    PGPPublicKey pubkey = keyfinder[TEAM].findPublicKey(keyid);
    if ( pubkey != null )
      return pubkey;
    return keyfinder[PERSONAL].findPublicKey(keyid);
  }

  @Override
  public PGPPublicKey findPublicKey(long keyid, String userid)
  {
    PGPPublicKey pubkey = keyfinder[TEAM].findPublicKey(keyid,userid);
    if ( pubkey != null )
      return pubkey;
    return keyfinder[PERSONAL].findPublicKey(keyid,userid);
  }

  @Override
  public PGPPublicKey findPublicKey(long keyid, String userid, byte[] fingerprint)
          throws KeyFinderException
  {
    PGPPublicKey pubkey = keyfinder[TEAM].findPublicKey(keyid,userid,fingerprint);
    if ( pubkey != null )
      return pubkey;
    return keyfinder[PERSONAL].findPublicKey(keyid,userid,fingerprint);
  }

  @Override
  public PGPPublicKey findFirstPublicKey(String userid)
  {
    PGPPublicKey pubkey = keyfinder[TEAM].findFirstPublicKey(userid);
    if ( pubkey != null )
      return pubkey;
    return keyfinder[PERSONAL].findFirstPublicKey(userid);
  }
  
}
