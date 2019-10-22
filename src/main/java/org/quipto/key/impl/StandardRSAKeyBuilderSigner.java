/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.quipto.key.impl;

import java.math.BigInteger;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Date;
import java.util.Iterator;
import java.util.logging.Level;
import java.util.logging.Logger;
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
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator;
import org.bouncycastle.openpgp.operator.PBESecretKeyEncryptor;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyEncryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider;
import org.bouncycastle.openpgp.operator.bc.BcPGPKeyPair;
import org.quipto.key.KeyBuilder;
import org.quipto.key.KeySigner;

/**
 *
 * @author maber01
 */
public class StandardRSAKeyBuilderSigner implements KeyBuilder, KeySigner
{
 
  
  /**
   * 
   * @param userid
   * @param pass
   * @return 
   */
  @Override
  public PGPSecretKey buildSecretKey(String userid, char[] pass )
  {
    return createNewPGPKeys( userid, pass, 0xc0);
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
  public PGPSecretKey createNewPGPKeys(String userid, char[] pass, int s2kcount)
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

  /**
   * 
   * @param signerprivatekey
   * @param publickey
   * @param keyflags 
   * @return 
   */
  @Override
  public PGPPublicKey signKey(PGPPrivateKey signerprivatekey, PGPPublicKey publickey, int keyflags )
  {
    
    try
    {
      // make a copy without signatures
      PGPPublicKey signedpublickey = new PGPPublicKey( publickey.getPublicKeyPacket(), new BcKeyFingerprintCalculator() );
      // get self signatures only
      Iterator<PGPSignature> selfsigiter = publickey.getSignaturesForKeyID( publickey.getKeyID() );
      // add them to the new copy
      while ( selfsigiter.hasNext() )
        PGPPublicKey.addCertification( signedpublickey, selfsigiter.next() );

      PGPSignatureSubpacketGenerator signhashgen = new PGPSignatureSubpacketGenerator();
      signhashgen.setKeyFlags(false, keyflags );
      
      PGPSignatureGenerator siggen = new PGPSignatureGenerator( 
        new BcPGPContentSignerBuilder(PGPPublicKey.RSA_GENERAL,HashAlgorithmTags.SHA1) );
      siggen.setHashedSubpackets(signhashgen.generate());
      siggen.init(PGPSignature.DIRECT_KEY, signerprivatekey);
      PGPSignature signature = siggen.generateCertification(signedpublickey);
      PGPPublicKey.addCertification( signedpublickey, signature );      
      return signedpublickey;
    }
    catch (PGPException ex)
    {
      Logger.getLogger(StandardRSAKeyBuilderSigner.class.getName()).log(Level.SEVERE, null, ex);
    }
    
    return null;
  }
  
  
}
