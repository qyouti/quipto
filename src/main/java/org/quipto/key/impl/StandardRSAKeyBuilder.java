/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.quipto.key.impl;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Date;
import java.util.UUID;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.bcpg.sig.Features;
import org.bouncycastle.bcpg.sig.KeyFlags;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPKeyRingGenerator;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator;
import org.bouncycastle.openpgp.operator.PBESecretKeyEncryptor;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyEncryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider;
import org.bouncycastle.openpgp.operator.bc.BcPGPKeyPair;
import org.quipto.QuiptoStandards;
import org.quipto.key.KeyBuilder;
import org.qyouti.winselfcert.WindowsCertificateGenerator;
import static org.qyouti.winselfcert.WindowsCertificateGenerator.CRYPT_USER_PROTECTED;
import static org.qyouti.winselfcert.WindowsCertificateGenerator.MS_ENH_RSA_AES_PROV;
import static org.qyouti.winselfcert.WindowsCertificateGenerator.PROV_RSA_AES;

/**
 *
 * @author maber01
 */
public class StandardRSAKeyBuilder implements KeyBuilder
{
 
  
  /**
   * 
   * @param userid
   * @param passphrase
   * @param windowsprotection
   * @return 
   */
  @Override
  public PGPSecretKey buildSecretKey(String userid, char[] passphrase, boolean windowsprotection )
  {
    String encryptedpassphrase=null;
    PublicKey windowspublickey;
    if ( windowsprotection )
    {
      windowspublickey = StandardRSAKeyBuilder.getOrCreateWindowsPublicKey( userid );
      // is it available?
      if ( windowspublickey != null)
      {
        passphrase = StandardRSAKeyBuilder.generateRandomPassphraseForPrivateKey();
        byte[] b = StandardRSAKeyBuilder.encryptWindowsPassphrase( windowspublickey, passphrase );
        encryptedpassphrase = java.util.Base64.getEncoder().encodeToString( b );
      }
    }
    return createNewPGPKeys( userid, passphrase, encryptedpassphrase, 0xc0);
  }



  // Note: s2kcount is a number between 0 and 0xff that controls the
  // number of times to iterate the password hash before use. More
  // iterations are useful against offline attacks, as it takes more
  // time to check each password. The actual number of iterations is
  // rather complex, and also depends on the hash function in use.
  // Refer to Section 3.7.1.3 in rfc4880.txt. Bigger numbers give
  // you more iterations.  As a rough rule of thumb, when using
  // SHA256 as the hashing function, 0x10 gives you about 64
  // iterations, 0x20 about 128, 0x30 about 256 and so on till 0xf0,
  // or about 1 million iterations. The maximum you can go to is
  // 0xff, or about 2 million iterations.  I'll use 0xc0 as a
  // default -- about 130,000 iterations.
  public PGPSecretKey createNewPGPKeys(String userid, char[] pass, String encryptedpassphrase, int s2kcount)
  {
    PGPPublicKeyRing pkr;
    PGPSecretKeyRing skr;
    
    try
    {
      // This object generates individual key-pairs.
      RSAKeyPairGenerator kpg = new RSAKeyPairGenerator();
      
      // Boilerplate RSA parameters, no need to change anything
      // except for the RSA key-size (2048). You can use whatever
      // key-size makes sense for you -- 4096, etc.
      kpg.init(new RSAKeyGenerationParameters(BigInteger.valueOf(0x10001), new SecureRandom(), 2048, 12));
      
      // First create the master (signing) key with the generator.
      PGPKeyPair rsakp_sign = new BcPGPKeyPair(PGPPublicKey.RSA_GENERAL, kpg.generateKeyPair(), new Date());
      
      // Add a self-signature on the id
      PGPSignatureSubpacketGenerator signhashgen = new PGPSignatureSubpacketGenerator();
      
      // Add signed metadata on the signature.
      // 1) Declare its purpose
      signhashgen.setKeyFlags(false, KeyFlags.SIGN_DATA | KeyFlags.CERTIFY_OTHER | KeyFlags.ENCRYPT_COMMS | KeyFlags.ENCRYPT_STORAGE );
      // 2) Set preferences for secondary crypto algorithms to use
      //    when sending messages to this key.
      signhashgen.setPreferredSymmetricAlgorithms(false, new int[]
      {
        SymmetricKeyAlgorithmTags.AES_256,
        SymmetricKeyAlgorithmTags.AES_192,
        SymmetricKeyAlgorithmTags.AES_128
      });
      signhashgen.setPreferredHashAlgorithms(false, new int[]
      {
        HashAlgorithmTags.SHA256,
        HashAlgorithmTags.SHA1,
        HashAlgorithmTags.SHA384,
        HashAlgorithmTags.SHA512,
        HashAlgorithmTags.SHA224,
      });
      // 3) Request senders add additional checksums to the
      //    message (useful when verifying unsigned messages.)
      signhashgen.setFeature(false, Features.FEATURE_MODIFICATION_DETECTION);
      
      if ( encryptedpassphrase != null )
      {
        signhashgen.setNotationData( false, true, QuiptoStandards.NOTATION_NAME_WINDOWS_ALIAS, StandardRSAKeyBuilder.getWindowsKeyAlias(userid) );
        signhashgen.setNotationData( false, true, QuiptoStandards.NOTATION_NAME_ENCRYPTED_PASSPHRASE, encryptedpassphrase );        
      }
      
      // Objects used to encrypt the secret key.
      PGPDigestCalculator sha1Calc
              = new BcPGPDigestCalculatorProvider()
                      .get(HashAlgorithmTags.SHA1);
      PGPDigestCalculator sha256Calc
              = new BcPGPDigestCalculatorProvider()
                      .get(HashAlgorithmTags.SHA256);
      
      // bcpg 1.48 exposes this API that includes s2kcount. Earlier
      // versions use a default of 0x60.
      PBESecretKeyEncryptor pske
              = (new BcPBESecretKeyEncryptorBuilder(PGPEncryptedData.AES_256, sha256Calc, s2kcount))
                      .build(pass);
      
      // Finally, create the keyring itself. The constructor
      // takes parameters that allow it to generate the self
      // signature.
      PGPKeyRingGenerator keyRingGen = new PGPKeyRingGenerator(PGPSignature.POSITIVE_CERTIFICATION, rsakp_sign,
                      userid, sha1Calc, signhashgen.generate(), null,
                      new BcPGPContentSignerBuilder(rsakp_sign.getPublicKey().getAlgorithm(),HashAlgorithmTags.SHA1),
                      pske);
      
      pkr = keyRingGen.generatePublicKeyRing();
      skr = keyRingGen.generateSecretKeyRing();
    }
    catch (PGPException ex)
    {
      ex.printStackTrace( System.out );
      return null;
    }

    return skr.getSecretKey();
  }

  
  private static String getWindowsKeyAlias( String userid )
  {
    final String preamble = "Quipto password guard for ";
    return preamble + userid;
  }
  
  
  /**
   * This Windows key pair is ONLY used to encrypt a password which in turn is
   * used to decrypt a standard OpenPGP encrypted private key.
   * @param alias
   * @return 
   */
  private static boolean createWindowsKeyPair( String alias )
  {
    try
    {
      BigInteger serial;
      WindowsCertificateGenerator wcg = new WindowsCertificateGenerator();
      
      serial = wcg.generateSelfSignedCertificate(
              "CN=" + alias,
              "qyouti-" + UUID.randomUUID().toString(),
              MS_ENH_RSA_AES_PROV,
              PROV_RSA_AES,
              true,
              2048,
              CRYPT_USER_PROTECTED
      );
      if (serial == null)
      {
        System.out.println("Failed to make certificate.");
        return false;
      }
      else
      {
        System.out.println("Serial number = " + serial.toString(16) );
        System.out.println("As long = " + Long.toHexString( serial.longValue() ) );        
      }

      return true;
    }
    catch (Exception e)
    {
      System.out.println( "Unable to create Windows password guard." );
      return false;
    }
  }

  private static PublicKey getOrCreateWindowsPublicKey( String userid )
  {
    final String preamble = "Quipto password guard for ";
    String alias = preamble + userid;
    PublicKey key = getWindowsPublicKey( alias );
    if ( key != null ) return key;
    if ( !createWindowsKeyPair( alias ) )
      return null;
    return getWindowsPublicKey( alias );
  }
  
  public static PublicKey getWindowsPublicKey( String alias )
  {
    try
    {
      KeyStore keystore = KeyStore.getInstance("Windows-MY");
      keystore.load(null, null);  // Load keystore 
      Certificate[] chain = keystore.getCertificateChain(alias);
      if ( chain == null || chain.length == 0 )
        return null;
      Certificate certificate = chain[chain.length - 1];
      return certificate.getPublicKey();
    }
    catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException ex)
    {
      Logger.getLogger(StandardRSAKeyBuilder.class.getName()).log(Level.SEVERE, null, ex);
    }

    return null;
  }
  
  public static PrivateKey getWindowsPrivateKey( String alias )
  {
    try
    {
      KeyStore keyStore = KeyStore.getInstance("Windows-MY");
      keyStore.load(null, null);  // Load keystore 
      return (PrivateKey)keyStore.getKey( alias, null );
    }
    catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException | UnrecoverableKeyException ex)
    {
      Logger.getLogger(StandardRSAKeyBuilder.class.getName()).log(Level.SEVERE, null, ex);
    }
    return null;
  }
  


  
  public static final String PASSCHARS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNPQRSTUVWXYZ0123456789.,;:[]}{=+-_)(*&%$";

  public static char[] generateRandomPassphraseForPrivateKey()
  {
    try
    {
      SecureRandom sr = SecureRandom.getInstanceStrong();
      char[] passphrase = new char[30];
      for (int i = 0; i < passphrase.length; i++)
      {
        passphrase[i] = PASSCHARS.charAt(sr.nextInt(PASSCHARS.length()));
      }
      return passphrase;
    }
    catch (NoSuchAlgorithmException ex)
    {
      Logger.getLogger(StandardRSAKeyBuilder.class.getName()).log(Level.SEVERE, null, ex);
    }
    return null;
  }

  public static byte[] encryptWindowsPassphrase( PublicKey pubk, char[] p )
  {
    try
    {
      Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
      cipher.init( Cipher.ENCRYPT_MODE, pubk );
      return cipher.doFinal( new String(p).getBytes() );
    }
    catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException ex)
    {
      Logger.getLogger(StandardRSAKeyBuilder.class.getName()).log(Level.SEVERE, null, ex);
    }
    return null;
  }
  
  public static char[] decryptWindowsPassphrase( String alias, String base64encrypted )
  {
    PrivateKey prikey = getWindowsPrivateKey( alias );
    byte[] encrypted = java.util.Base64.getDecoder().decode(base64encrypted);
    return decryptWindowsPassphrase( prikey, encrypted );
  }
  
  public static char[] decryptWindowsPassphrase( String alias, byte[] encrypted )
  {
    PrivateKey prikey = getWindowsPrivateKey( alias );
    return decryptWindowsPassphrase( prikey, encrypted );
  }
  
  public static char[] decryptWindowsPassphrase( PrivateKey prikey, byte[] encrypted )
  {
    try
    {
      Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
      cipher.init( Cipher.DECRYPT_MODE, prikey );
      byte[] decrypt = cipher.doFinal( encrypted );
      System.out.println( "Password is: " + new String( decrypt, "UTF8" ) );
      return new String( decrypt, "UTF8" ).toCharArray();
    }
    catch ( UnsupportedEncodingException | InvalidKeyException | NoSuchAlgorithmException | BadPaddingException | IllegalBlockSizeException | NoSuchPaddingException e )
    {
      e.printStackTrace();
    }
    
    return null;
  }
}
