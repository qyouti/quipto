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
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.swing.tree.TreeModel;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSignature;
import org.quipto.compositefile.EncryptedCompositeFile;
import org.quipto.compositefile.EncryptedCompositeFilePasswordHandler;
import org.quipto.compositefile.EncryptedCompositeFileUser;
import org.quipto.compositefile.WrongPasswordException;
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
  EncryptedCompositeFileUser eu;
  CompositeFileKeyStore personalkeystore;
  CompositeFileKeyFinder personalkeyfinder;
  
  TeamKeyStore teamkeystore;  
  CompositeFileKeyFinder teamkeyfinder;

  PGPSecretKey ownsecretkeysigning, ownsecretkeydecryption;

  
  public TeamTrust( 
          String alias, 
          CompositeFileKeyStore personalkeystore,
          CompositeFileKeyFinder personalkeyfinder, 
          File teamkeystorefile
  ) throws IOException, NoSuchProviderException, NoSuchAlgorithmException, PGPException, WrongPasswordException
  {
    this.personalkeystore = personalkeystore;
    this.personalkeyfinder = personalkeyfinder;
    ownsecretkeysigning = personalkeyfinder.getSecretKeyForSigning();
    ownsecretkeydecryption = personalkeyfinder.getSecretKeyForDecryption();
    
    eu     = new EncryptedCompositeFileUser( this, new TrustAnythingContext() ); // shared store uses key from personal store
    teamkeystore = new TeamKeyStore( teamkeystorefile, eu, personalkeyfinder );
    teamkeyfinder = new CompositeFileKeyFinder( teamkeystore, alias, alias );
    teamkeyfinder.init();

    updatePersonallyTrusted();
  }

  public boolean isController()
  {
    return teamkeystore.isController( eu.getKeyFinder().getSecretKeyForSigning().getKeyID() );
  }
  
  public TreeModel getTreeModel()
  {
    return teamkeystore.getTreeModel();
  }
  
  public void close()
  {
    teamkeystore.close();
  }
  
  private void updatePersonallyTrusted()
  {
    // TODO
    // this needs to tell teamkeystore to invalidate its list of
    // nodes that are recorded as having no personal signatures.
    
    // really?  Can it keep it's own record?
  }
  
  public void addRootPublicKeyToTeamStore( PGPPublicKey publickey ) throws IOException, NoSuchProviderException, NoSuchAlgorithmException, WrongPasswordException
  {
    ArrayList<PGPPublicKey> list = new ArrayList<>();
    list.add(publickey);
    teamkeystore.addAccessToPublicKey(publickey);
    teamkeystore.setPublicKeyRing( new PGPPublicKeyRing(list) );
    teamkeystore.setRootKey(publickey);
    updatePersonallyTrusted();
  }
  
  public void addPublicKeyToTeamStore( PGPPublicKey parentkey, PGPPublicKey publickey, boolean controller ) throws IOException, NoSuchProviderException, NoSuchAlgorithmException, WrongPasswordException
  {
    if ( !isController() )
      throw new IOException( "Attempt to edit team store with a key that lacks controller access." );
    ArrayList<PGPPublicKey> list = new ArrayList<>();
    list.add(publickey);
    teamkeystore.addAccessToPublicKey(publickey);
    teamkeystore.setPublicKeyRing( new PGPPublicKeyRing(list) );
    teamkeystore.addKey(parentkey, publickey, controller);
    updatePersonallyTrusted();
  }
  
  public void addParentCertificationToTeamStore( PGPPublicKey parentkey ) throws IOException, NoSuchProviderException, NoSuchAlgorithmException, WrongPasswordException
  {
    ArrayList<PGPPublicKey> list = new ArrayList<>();
    list.add(parentkey);
    teamkeystore.setPublicKeyRing( new PGPPublicKeyRing(list) );
    updatePersonallyTrusted();
  }
  
  public void dumpTeam()
  {
    teamkeystore.dumpTeam();
  }  
  
  public void addPublicKeyToPersonalStore( PGPPublicKey publickey ) throws IOException, NoSuchProviderException, NoSuchAlgorithmException, WrongPasswordException
  {
    ArrayList<PGPPublicKey> list = new ArrayList<>();
    list.add(publickey);
    personalkeystore.setPublicKeyRing( new PGPPublicKeyRing(list) );
  }
  
  public void addAllTeamKeysToEncryptedCompositeFile( EncryptedCompositeFile compositefile ) throws IOException, NoSuchProviderException, NoSuchAlgorithmException
  {
    List<PGPPublicKeyRing> fulllist = teamkeystore.getAllPublicKeyRings();
    for ( PGPPublicKeyRing keyring : fulllist )
    {
      keyring.getPublicKey();  // the master key
      compositefile.addPublicKey( keyring.getPublicKey() );
      compositefile.setPermission( keyring.getPublicKey(), EncryptedCompositeFile.ALL_PERMISSIONS );
    }
  }
  
  private static String getUserID( PGPPublicKey key )
  {
    String userid = "unknown";
    Iterator<String> iter = key.getUserIDs();
    if ( iter.hasNext() ) userid = iter.next();
    return userid;
  }
  
  @Override
  public TrustContextReport checkTrusted( long signerkeyid )
  {
    return teamkeystore.verifyTeamKeyChain(signerkeyid);
  }
  
  
 
  @Override
  public String getPreferredAlias(PGPSecretKey secretkey)
  {
    return personalkeyfinder.getPreferredAlias(secretkey);
  }

  @Override
  public PGPPrivateKey getPrivateKey(PGPSecretKey secretkey)
  {
    return personalkeyfinder.getPrivateKey(secretkey);
  }

  @Override
  public PGPSecretKey getSecretKeyForDecryption()
  {
    return ownsecretkeydecryption;
  }

  @Override
  public PGPSecretKey getSecretKeyForSigning()
  {
    return ownsecretkeysigning;
  }

  @Override
  public PGPPublicKey findPublicKey(long keyid)
  {
    if ( teamkeyfinder != null )
    {
      PGPPublicKey pubkey = teamkeyfinder.findPublicKey(keyid);
      if ( pubkey != null )
        return pubkey;
    }
    return personalkeyfinder.findPublicKey(keyid);
  }

  @Override
  public PGPPublicKey findPublicKey(long keyid, String userid)
  {
    PGPPublicKey pubkey = teamkeyfinder.findPublicKey(keyid,userid);
    if ( pubkey != null )
      return pubkey;
    return personalkeyfinder.findPublicKey(keyid,userid);
  }

  @Override
  public PGPPublicKey findPublicKey(long keyid, String userid, byte[] fingerprint)
          throws KeyFinderException
  {
    PGPPublicKey pubkey = teamkeyfinder.findPublicKey(keyid,userid,fingerprint);
    if ( pubkey != null )
      return pubkey;
    return personalkeyfinder.findPublicKey(keyid,userid,fingerprint);
  }

  @Override
  public PGPPublicKey findFirstPublicKey(String userid)
  {
    PGPPublicKey pubkey = teamkeyfinder.findFirstPublicKey(userid);
    if ( pubkey != null )
      return pubkey;
    return personalkeyfinder.findFirstPublicKey(userid);
  }
 
  public List<PGPPublicKeyRing> getAllTeamPublicKeyRings()
  {
    return teamkeystore.getAllPublicKeyRings();
  }
}
