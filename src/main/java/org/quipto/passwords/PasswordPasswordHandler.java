/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.quipto.passwords;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Date;
import java.util.Properties;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPLiteralDataGenerator;
import org.bouncycastle.openpgp.PGPPBEEncryptedData;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePBEDataDecryptorFactoryBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePBEKeyEncryptionMethodGenerator;
import org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder;
import org.bouncycastle.util.Arrays;
import org.quipto.compositefile.EncryptedCompositeFile;
import org.quipto.compositefile.EncryptedCompositeFilePasswordHandler;

/**
 *
 * @author maber01
 */
public class PasswordPasswordHandler implements EncryptedCompositeFilePasswordHandler
{
  
  Properties encryptionproperties;
  String emailaddress;
  char[] masterpass;
  
  PrivateKey privatekey;
  PublicKey publickey;
  
  

  /**
   * This constructor wants a name - other implementations might ask
   * for other stuff. This is not part of the interface so its whatever
   * the implementation needs. For example, there may be a pass phrase.
   * 
   * @param name 
   */
  public PasswordPasswordHandler(String emailaddress, char[] masterpass )
  {
    this.emailaddress = emailaddress;
    this.masterpass = Arrays.copyOf( masterpass, masterpass.length );
    
    encryptionproperties = new Properties();
    encryptionproperties.setProperty( "passwordpasswordhandler", "true" );
  }
  
  @Override
  public char[] decryptPassword(byte[] cipher, Properties properties)
  {
    ByteArrayInputStream bain = new ByteArrayInputStream( cipher );
    
    String prop = properties.getProperty("passwordpasswordhandler");
    if ( prop == null || !(prop.equals("true")) )
      return null;  // wrong handler
    try
    {
      InputStream in = PGPUtil.getDecoderStream( bain );
      JcaPGPObjectFactory pgpF = new JcaPGPObjectFactory(in);
      PGPEncryptedDataList enc;
      Object o = pgpF.nextObject();
      System.out.println( "o = " + o.getClass() );
      if (o instanceof PGPEncryptedDataList)
        enc = (PGPEncryptedDataList) o;
      else
      {
        enc = (PGPEncryptedDataList) pgpF.nextObject();
        System.out.println( "o = " + o.getClass() );
      }
      PGPPBEEncryptedData pbe = (PGPPBEEncryptedData) enc.get(0);
      InputStream clearin = pbe.getDataStream(
              new JcePBEDataDecryptorFactoryBuilder(
                      new JcaPGPDigestCalculatorProviderBuilder().setProvider("BC").build()
              ).setProvider("BC").build( masterpass ) );
      JcaPGPObjectFactory pgpFact = new JcaPGPObjectFactory(clearin);
      o = pgpFact.nextObject();
      System.out.println( "Object class " + o.getClass().toString() );
      PGPLiteralData ld = (PGPLiteralData) o;
      InputStream literalin = ld.getInputStream();
      
      ByteArrayOutputStream baout = new ByteArrayOutputStream();
      int b;
      for ( int i=0; i<(1024*64) && (b=literalin.read()) >= 0; i++ )
        baout.write(b);

      literalin.close();
      clearin.close();
      return new String( baout.toByteArray(), "UTF-8" ).toCharArray();
    } catch (PGPException ex)
    {
      Logger.getLogger(EncryptedCompositeFile.class.getName()).log(Level.SEVERE, null, ex);
    }
    catch (IOException ex)
    {
      Logger.getLogger(PasswordPasswordHandler.class.getName()).log(Level.SEVERE, null, ex);
    }
    return null;
  }

  @Override
  public byte[] encryptPassword(char[] plaintext)
  {
    ByteArrayOutputStream baout = new ByteArrayOutputStream();
    PGPEncryptedDataGenerator encryptiongen = new PGPEncryptedDataGenerator(
            new JcePGPDataEncryptorBuilder(PGPEncryptedData.CAST5)
              .setWithIntegrityPacket( true )   
              .setSecureRandom(new SecureRandom())
              .setProvider("BC")
    );
    encryptiongen.addMethod(new JcePBEKeyEncryptionMethodGenerator(masterpass).setProvider("BC"));
    OutputStream encryptedoutput;
    try
    {
      encryptedoutput = encryptiongen.open(baout, new byte[1 << 16]);
      PGPLiteralDataGenerator literalgen = new PGPLiteralDataGenerator();
      OutputStream literalout = literalgen.open(encryptedoutput, PGPLiteralData.BINARY, "password.txt", new Date(System.currentTimeMillis()), new byte[1 << 16]);
      literalout.write( new String( plaintext ).getBytes("UTF-8") );
      literalout.close();
      encryptedoutput.close();
    }
    catch (PGPException | IOException ex)
    {
      Logger.getLogger(PasswordPasswordHandler.class.getName()).log(Level.SEVERE, null, ex);
    }
    
    return baout.toByteArray();
  }

  @Override
  public Properties getEncryptionProperties()
  {
    return encryptionproperties;
  }


}
