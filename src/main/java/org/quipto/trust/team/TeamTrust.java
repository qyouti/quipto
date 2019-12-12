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

  ArrayList<Long> personallytrustedteamkeyids = new ArrayList<>();
  
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
    teamkeystore = new TeamKeyStore( teamkeystorefile, eu );
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
    // List all keys personally trusted
    long[] personallytrusted = personalkeystore.getSignedKeyIds( ownsecretkeysigning.getKeyID() );
    // Narrow to those that are controllers in the team store.
    for ( long keyid : personallytrusted )
    {
      if ( teamkeystore.isController(keyid) && !personallytrustedteamkeyids.contains( keyid ) )
        personallytrustedteamkeyids.add(keyid);
    }    
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
    
//    System.out.println( "Team trust chain...");
//    for ( PGPPublicKey key : trustkeylist )
//      System.out.println( "ID: " + Long.toHexString( key.getKeyID() ) + " First UserID " + getUserID( key ) );
//    System.out.println( "...End of Team Trust chain");
    
    int personallysignedpublickey=-1;
    for ( int i=0; i<trustkeylist.length; i++ )
    {
      PGPPublicKey personalpublickey = personalkeyfinder.findPublicKey( trustkeylist[i].getKeyID() );
      if ( personalpublickey != null )
      {
        personallysignedpublickey = i;
        break;
      }
    }
    //if ( personallysignedpublickey >= 0 )
    //  System.out.println( "Found in personal key store: " + Long.toHexString( trustkeylist[personallysignedpublickey].getKeyID() ) );
    return checkTrustChainPublicKeys( trustkeylist, personallysignedpublickey );
  }
  
  private PGPPublicKey[] loadTrustChainPublicKeys( long signerkeyid )
          throws TrustContextException
  {
    PGPPublicKey[] keys = teamkeystore.getTeamKeyChain(signerkeyid, personallytrustedteamkeyids );
    if ( keys == null )
      throw new TrustContextException( new TrustContextReport( false, "The key that signed the data file is not listed in the Trust file." ) );
    return keys;
    /*
    PGPPublicKey publickey;
    Iterator<PGPSignature> sigiter;
    PGPSignature sig, selfsig, othersig;
    ArrayList<PGPPublicKey> list = new ArrayList<>();
    boolean selfsign=false;
    
    long keyid = signerkeyid;
    do
    {
      publickey = keyfinder[TEAM].findPublicKey( keyid );
      if ( publickey == null )
        throw new TrustContextException( new TrustContextReport( false, "Signing key that is not listed in the Trust file." ) );
      
      sigiter = publickey.getSignatures();
      selfsig = null;
      othersig = null;
      while ( sigiter.hasNext() )
      {
        sig = sigiter.next();
        if ( sig.getKeyID() == keyid )
          selfsig = sig;
        else
        {
          if ( othersig != null )
            throw new TrustContextException( new TrustContextReport( false, "A team key was found with more than one certification. This software cannot handle that." ) );
          othersig = sig;
        }
      }
      
      if ( selfsig == null && othersig == null )
        throw new TrustContextException( new TrustContextReport( false, "Signing key is not itself signed and cannot be trusted." ) );
      
      list.add(publickey);
      if ( othersig == null )
      {
        selfsign = true;
        keyid = selfsig.getKeyID();
      }
      else
        keyid = othersig.getKeyID();
    }
    while ( selfsign == false );
    
    return list.toArray( new PGPPublicKey[list.size()] );
    */
  }
  
  /**
   * 
   * @param trustkeylist list of keys from the one that signed the data to the team trust root
   * @param personallysignedpublickey which in the list has been personally signed. Is negative if none were signed
   * @return 
   */
  private TrustContextReport checkTrustChainPublicKeys( PGPPublicKey[] trustkeylist, int personallysignedpublickey )
  {
    if ( personallysignedpublickey < 0 )
      return new TrustContextReport( false, "Neither the key used to sign the data file, nor the keys used to certify that key can be found in your personal trusted key store." );
    
    TrustContextReport report;
    report = checkKeySignature( trustkeylist[personallysignedpublickey], ownsecretkeysigning.getPublicKey() );
    if ( !report.isTrusted() ) return report;
    for ( int i=personallysignedpublickey; i>0; i-- )
    {
      report = checkKeySignature( trustkeylist[i-1], trustkeylist[i] );
      if ( !report.isTrusted() ) return report;      
    }
    
    return new TrustContextReport( true, null );
  }
  
  private TrustContextReport checkKeySignature( PGPPublicKey signed, PGPPublicKey signer )
  {
    //System.out.print( " Checking ID: " + Long.toHexString( signed.getKeyID() ) + ", " + getUserID( signed ) );
    //System.out.println( " signed by " + Long.toHexString( signer.getKeyID() ) + ", " + getUserID( signer ) );
    
    return new TrustContextReport( true, null );
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
