/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.quipto.trust.team;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.quipto.compositefile.EncryptedCompositeFile;
import org.quipto.compositefile.EncryptedCompositeFileUser;
import org.quipto.key.KeyFinder;
import org.quipto.key.KeyFinderException;
import org.quipto.key.impl.OldPGPFileKeyFinder;
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
  File basefile;
  EncryptedCompositeFile compositebasefile;
  EncryptedCompositeFileUser encfileuser;
  OldPGPFileKeyFinder keyfinder;

  public TeamTrust(File basefile, OldPGPFileKeyFinder keyfinder)
  {
    this.basefile = basefile;
    this.keyfinder = keyfinder;
    try
    {
      compositebasefile = EncryptedCompositeFile.getCompositeFile( basefile );
      encfileuser = new EncryptedCompositeFileUser( keyfinder, new TrustAnythingContext() );
    }
    catch (IOException ex)
    {
      Logger.getLogger(TeamTrust.class.getName()).log(Level.SEVERE, null, ex);
    }
  }

  public void init()
  {
    // Create various empty files in the archive....
  }
  
  public void load()
  {
    
  }
  
  public void addPublicKeyToTeam( PGPPublicKey publickey )
  {
    PGPPublicKey currentpublickey = loadPublicKey( publickey.getKeyID() );
    try
    {
      compositebasefile.addPublicKey(encfileuser, publickey);
    }
    catch (IOException | NoSuchProviderException | NoSuchAlgorithmException ex)
    {
      Logger.getLogger(TeamTrust.class.getName()).log(Level.SEVERE, null, ex);
    }
    savePublicKey( publickey );
  }
  
  private void savePublicKey( PGPPublicKey publickey )
  {
    String name = "publickeys/" + Long.toHexString(publickey.getKeyID()) + ".pgp";
    try (OutputStream output = compositebasefile.getEncryptingOutputStream(encfileuser, name, true, false))
    {
      byte[] enckey = publickey.getEncoded();
      output.write(enckey);
    }
    catch (IOException ex)
    {
      Logger.getLogger(TeamTrust.class.getName()).log(Level.SEVERE, null, ex);
    }
  }
  
  private PGPPublicKey loadPublicKey( long keyid )
  {
    String name = "publickeys/" + Long.toHexString(keyid) + ".pgp";
    if ( !compositebasefile.exists( name ) )
      return null; 
    try ( InputStream in = compositebasefile.getDecryptingInputStream(encfileuser, name); )
    {
      PGPPublicKeyRing keyring = new PGPPublicKeyRing( in, new BcKeyFingerprintCalculator() );
      if ( keyring == null )
        return null;
      return keyring.getPublicKey();
    }
    catch (IOException ex)
    {
      Logger.getLogger(TeamTrust.class.getName()).log(Level.SEVERE, null, ex);
      return null;
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
    PGPPublicKey publickey = null;
    Iterator<PGPSignature> sigiter;
    PGPSignature sig;
    ArrayList<PGPPublicKey> list = new ArrayList<>();
    boolean selfsign=false;
    
    long keyid = signerkeyid;
    do
    {
      publickey = loadPublicKey( keyid );
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
    return keyfinder.getPreferredAlias(secretkey);
  }

  @Override
  public PGPPrivateKey getPrivateKey(PGPSecretKey secretkey)
  {
    return keyfinder.getPrivateKey(secretkey);
  }

  @Override
  public PGPSecretKey getSecretKeyForDecryption()
  {
    return keyfinder.getSecretKeyForDecryption();
  }

  @Override
  public PGPSecretKey getSecretKeyForSigning()
  {
    return keyfinder.getSecretKeyForSigning();
  }

  @Override
  public PGPPublicKey findPublicKey(long keyid)
  {
    return keyfinder.findPublicKey(keyid);
  }

  @Override
  public PGPPublicKey findPublicKey(long keyid, String userid)
  {
    return keyfinder.findPublicKey(keyid,userid);
  }

  @Override
  public PGPPublicKey findPublicKey(long keyid, String userid, byte[] fingerprint)
          throws KeyFinderException
  {
    return keyfinder.findPublicKey(keyid,userid,fingerprint);
  }

  @Override
  public PGPPublicKey findFirstPublicKey(String userid)
  {
    return keyfinder.findFirstPublicKey(userid);
  }
  
}
