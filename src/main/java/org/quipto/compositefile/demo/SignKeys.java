/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.quipto.compositefile.demo;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.bouncycastle.bcpg.sig.KeyFlags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.operator.KeyFingerPrintCalculator;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.quipto.compositefile.EncryptedCompositeFilePasswordHandler;
import org.quipto.compositefile.EncryptedCompositeFileUser;
import org.quipto.compositefile.WrongPasswordException;
import org.quipto.key.impl.CompositeFileKeyFinder;
import org.quipto.key.impl.CompositeFileKeyStore;
import org.quipto.key.impl.StandardRSAKeyBuilderSigner;
import org.quipto.trust.team.TeamTrust;

/**
 *
 * @author maber01
 */
public class SignKeys
{
  private static final KeyFingerPrintCalculator fingerprintcalc = new BcKeyFingerprintCalculator();
  
  public static void signKeysAndImport( 
          DemoUtils.DemoUser signerdemouser, 
          EncryptedCompositeFilePasswordHandler passhandler, 
          boolean initteam, 
          DemoUtils.DemoUser[] subjectdemousers, 
          boolean[] addtoteam, 
          boolean[] controller, 
          boolean[] isparent ) throws WrongPasswordException
  {
    Security.addProvider(new BouncyCastleProvider());
    
    try
    {
      File personalkeystorefile = new File( signerdemouser.folder + "/keyring.tar");
      File teamkeystorefile = new File( "demo/shared/teamkeyring.tar" );
          
      EncryptedCompositeFileUser personaleu = new EncryptedCompositeFileUser( passhandler );
      CompositeFileKeyStore personalkeystore = new CompositeFileKeyStore( personalkeystorefile );
      personalkeystore.setUser(personaleu);
      CompositeFileKeyFinder personalkeyfinder = new CompositeFileKeyFinder( personalkeystore, signerdemouser.alias, signerdemouser.alias );
      personalkeyfinder.init();
      
      TeamTrust teamtrust = new TeamTrust( signerdemouser.alias, personalkeystore, personalkeyfinder, teamkeystorefile );
      EncryptedCompositeFileUser eu = new EncryptedCompositeFileUser( teamtrust, teamtrust );
      StandardRSAKeyBuilderSigner signer = new StandardRSAKeyBuilderSigner();
      
      PGPPublicKey mypublickey = teamtrust.getSecretKeyForSigning().getPublicKey();
      if ( initteam )
        teamtrust.addRootPublicKeyToTeamStore( mypublickey );
      
      for ( int i=0; i<subjectdemousers.length; i++ )
      {
        DemoUtils.DemoUser user = subjectdemousers[i];
        File subjectkeyfile = new File( user.folder + "/myselfsignedpublickey.gpg" );
        FileInputStream fin = new FileInputStream( subjectkeyfile );
        PGPPublicKeyRing keyring = new PGPPublicKeyRing( fin, fingerprintcalc );
        fin.close();
        PGPPublicKey pubkey = keyring.getPublicKey();
        pubkey = signer.signKey(
                teamtrust.getPrivateKey(teamtrust.getSecretKeyForSigning()), 
                pubkey, 
                KeyFlags.CERTIFY_OTHER | KeyFlags.ENCRYPT_STORAGE | KeyFlags.SIGN_DATA,
                StandardRSAKeyBuilderSigner.INCLUDE_SELF_SIGNATURE );
        teamtrust.addPublicKeyToPersonalStore(pubkey);
        
        if ( addtoteam != null && i<addtoteam.length && addtoteam[i] )
        {
          if ( isparent[i] )
            teamtrust.addParentCertificationToTeamStore( pubkey );
          else
            teamtrust.addPublicKeyToTeamStore(mypublickey,pubkey,controller[i]);
        }
      }
      
      teamtrust.close();
    }
    catch (IOException ex)
    {
      Logger.getLogger(SignKeys.class.getName()).log(Level.SEVERE, null, ex);
    }
    catch (NoSuchProviderException ex)
    {
      Logger.getLogger(SignKeys.class.getName()).log(Level.SEVERE, null, ex);
    }
    catch (NoSuchAlgorithmException ex)
    {
      Logger.getLogger(SignKeys.class.getName()).log(Level.SEVERE, null, ex);
    }
    catch (PGPException ex)
    {
      Logger.getLogger(SignKeys.class.getName()).log(Level.SEVERE, null, ex);
    }
  }  
}
