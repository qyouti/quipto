/*
 * Copyright 2019 Leeds Beckett University.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.quipto.compositefile;


import java.io.ByteArrayOutputStream;
import java.io.File;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Properties;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.bouncycastle.bcpg.CompressionAlgorithmTags;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPCompressedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPLiteralDataGenerator;
import org.bouncycastle.openpgp.PGPOnePassSignature;
import org.bouncycastle.openpgp.PGPOnePassSignatureList;
import org.bouncycastle.openpgp.PGPPBEEncryptedData;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.PGPSignatureList;
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.operator.bc.BcPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPContentVerifierBuilderProvider;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePBEDataDecryptorFactoryBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePBEKeyEncryptionMethodGenerator;
import org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyDataDecryptorFactoryBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyKeyEncryptionMethodGenerator;
import org.bouncycastle.util.io.Streams;
import org.quipto.QuiptoStandards;
import org.quipto.key.KeyFinder;
import org.quipto.trust.TrustContextException;
import org.quipto.trust.TrustContextReport;

/**
 * Subclasses CompositeFile to provide encryption for team work.
 * @author maber01
 */
public class EncryptedCompositeFile
        extends CompositeFile
{
  static final public int TYPE_UNKNOWN   = 0;
  static final public int TYPE_EXCLUSIVE = 1;
  static final public int TYPE_SHARED    = 2;
  static final public int TYPE_SHARED_AC = 3;
  
  
  static final public int UNKNOWN_PASS_STATUS = -1;
  static final public int PASS_NONE = 0;
  static final public int PASS_HIDDEN = 1;
  static final public int PASS_KNOWN = 2;

  static final public int HAS_PERMISSION              = 1;
  static final public int READ_PERMISSION             = 2;
  static final public int WRITE_PERMISSION            = 4;
  static final public int WRITE_PERMISSION_PERMISSION = 8;
  
  static final public int ALL_PERMISSIONS             = 0x0f;

  
  int type;
  boolean accesscontrol;
  EncryptedCompositeFileUser eu;

  Properties custompassphraseproperties = null;
  
  boolean ignoresignatures;
  
  final HashMap<String,Integer> permissiontable = new HashMap<>();
  
  
  /**
   * Constructor.
   * 
   * @param file
   * @param create
   * @param accesscontrol
   * @param eu
   * @throws IOException 
   */
  public EncryptedCompositeFile( File file, boolean create, boolean accesscontrol, EncryptedCompositeFileUser eu )
          throws IOException
  {
    super(file, create);
    this.eu = eu;
    this.accesscontrol = accesscontrol;
    ignoresignatures = true;
  }

  public void initA() throws IOException
  {
    try
    {
      initAPrivate();
    }
    catch ( NoSuchAlgorithmException | NoSuchProviderException e )
    {
      throw new IOException( "Cryptography problem.", e );
    }
  }
  
  private void initAPrivate() throws IOException, NoSuchProviderException, NoSuchAlgorithmException
  {
    if ( isNewlyCreated() )
    {
      // add user's own password with appropriate encryption
      if ( eu.isExclusive() )
      {
        addCustomUser();
        setConfiguration( TYPE_EXCLUSIVE );
      }
      else
      {
        addPublicKeyPrivately( eu.getKeyFinder().getSecretKeyForDecryption().getPublicKey() );
        setPermission( eu.getKeyFinder().getSecretKeyForSigning().getPublicKey(), ALL_PERMISSIONS, false );
        setConfiguration( accesscontrol?TYPE_SHARED_AC:TYPE_SHARED );
      }
    }
    else
    {
      String propsname = getCustomPassphraseFileName()+".properties";
      if ( exists(propsname) )
      {
        try ( InputStream in = super.getInputStream( propsname ) )
        {
          custompassphraseproperties = new Properties();
          custompassphraseproperties.loadFromXML(in);
        }
        catch ( IOException ioex )
        {
          custompassphraseproperties = null;
          throw ioex;
        }
      }
      
      type = getConfiguration();    
      if ( type == TYPE_EXCLUSIVE )
      {
        if ( custompassphraseproperties == null )
          throw new IOException( "Archive should be exclusive access but lacks a passphrase properties entry." );
      }
    }
  }

  
  public void initB()
  {
    ignoresignatures = false;
  }

  public String getCustomPassphraseType()
  {
    if ( custompassphraseproperties == null ) return "none";
    return custompassphraseproperties.getProperty("type","none");
  }
  
  private static String getConfigurationFileName()
  {
    return ".encryption/configuration.bin";
  }

  private int getConfiguration() throws IOException
  {
    String name = getConfigurationFileName();
    if ( !exists( name ) )
      return TYPE_UNKNOWN;
    try ( InputStream in = getDecryptingInputStream(name,false) )
    {
      int b = in.read();
      if ( b < 0 ) return TYPE_UNKNOWN;
      return b;
    }  
  }

  private void setConfiguration( int c ) throws IOException
  {
    String name = getConfigurationFileName();
    try ( OutputStream out = this.getEncryptingOutputStream( name, true, c == TYPE_SHARED | c == TYPE_SHARED_AC, false ) )
    {
      out.write(c);
    }
    catch ( Exception e )
    {
      throw e;
    }
    type = c;
  }
  
  
  private static String getPassphraseFileName( PGPPublicKey publickey )
  {
    long keyid = publickey.getKeyID();
    String strkeyid = Long.toHexString(keyid);
    return ".encryption/passwords/" + strkeyid + ".gpg";
  }

  private static String getPermissionFileName( PGPPublicKey publickey )
  {
    long keyid = publickey.getKeyID();
    String strkeyid = Long.toHexString(keyid);
    return ".encryption/permissions/" + strkeyid + ".bin";
  }

//  private static boolean isPermissionFileName( String name )
//  {
//    return name.startsWith(".encryption/permissions/") && name.endsWith(".bin");
//  }

  public int getPermission( PGPPublicKey publickey ) throws IOException
  {
    if ( type == 0 )
      throw new IOException("Encrypted composite file not initialised");
    
    if ( type != TYPE_SHARED_AC )
      return ALL_PERMISSIONS;
    
    String name = getPermissionFileName( publickey );
    if ( !exists( name ) )
      return 0;
    
    Integer i = permissiontable.get(name);
    if ( i != null )
      return i.intValue();
    
    try ( InputStream in = getDecryptingInputStream(name,false) )
    {
      int b = in.read();
      if ( b < 0 )
        i = new Integer(0);
      else
        return i = new Integer(b);
    }
    catch (IOException ex)
    {
      Logger.getLogger(EncryptedCompositeFile.class.getName()).log(Level.SEVERE, null, ex);
      i = new Integer(0);
    }
    
    try ( InputStream in = getDecryptingInputStream(name,true) )
    {
    }
    catch (IOException ex)
    {
      Logger.getLogger(EncryptedCompositeFile.class.getName()).log(Level.SEVERE, null, ex);
    }
    
    permissiontable.put(name, i);
    return i.intValue();
  }
  
  public void setPermission( PGPPublicKey publickey, int p ) throws IOException
  {
    if ( type != TYPE_SHARED_AC )
      throw new IOException("This encrypted composite file does not record permissions.");
    // public interface enforces check...
    setPermission( publickey, p, !ignoresignatures );
  }
  
  private void setPermission( PGPPublicKey publickey, int p, boolean check ) throws IOException
  {
    if ( check )
    {
      int selfpermission = getPermission( eu.keyfinder.getSecretKeyForSigning().getPublicKey() );
      if ( (selfpermission & WRITE_PERMISSION_PERMISSION) == 0 )
        throw new IOException( "User does not have permission to set permissions for " + getCanonicalPath() );
    }
    String name = getPermissionFileName( publickey );
    try ( OutputStream out = this.getEncryptingOutputStream( name, true, true, false ) )
    {
      out.write(p);
    }
    catch ( Exception e )
    {
      throw e;
    }
  }
  
  private String getCustomPassphraseFileName()
  {
    return ".encryption/custompasswords/pass.bin";
  }

  private static boolean isOpenPGPPassphraseFileName( String name )
  {
    return name.startsWith(".encryption/passwords/") && name.endsWith(".gpg");
  }
  
  
  private static boolean isCustomPassphraseFileName( String name )
  {
    return name.startsWith(".encryption/custompasswords/") && name.endsWith(".bin");
  }
  
  
  /**
   * Finds this composite file's passphrase. The alias is used
   * to find an entry with correct name, the private key is
   * used to decrypt it.
   * 
   * @throws IOException
   * @throws NoSuchProviderException 
   */
  private void initPassphraseForThisCompositeFile()
          throws IOException, NoSuchProviderException
  {
    int passphrasestatus = eu.getPassPhraseStatus( getCanonicalPath() );
    char[] passphrase=null;
    
    if ( passphrasestatus == PASS_KNOWN || passphrasestatus == PASS_HIDDEN )
      return;
    
    String name;
    KeyFinder keyfinder = eu.getKeyFinder();
    EncryptedCompositeFilePasswordHandler passhandler = eu.getPasswordHandler();
    if ( keyfinder != null )
    {
      PGPPublicKey mypublickey = eu.getKeyFinder().getSecretKeyForDecryption().getPublicKey();

      for (ComponentEntry entry : componentmap.values())
      {
        name = entry.tararchiveentry.getName();
        if ( isOpenPGPPassphraseFileName(name) )
        {
          if (passphrasestatus != PASS_KNOWN)
          {
            passphrasestatus = PASS_HIDDEN;
          }

          if (name.equals( getPassphraseFileName(mypublickey) ) )
          {
            InputStream in = super.getInputStream(name);
            passphrase = decryptPassphraseUsingOpenPGP(eu,in);
            in.close();
            //System.out.println("Password is " + new String(passphrase));
            passphrasestatus = PASS_KNOWN;
          }
        }
      }
    }
    else if ( passhandler != null && custompassphraseproperties != null )
    {
      name = getCustomPassphraseFileName();
      if ( exists( name ) )
      {
        if (passphrasestatus != PASS_KNOWN)
        {
          passphrasestatus = PASS_HIDDEN;
        }

        InputStream in = super.getInputStream(name);
        ByteArrayOutputStream baout = new ByteArrayOutputStream();
        int b;
        for ( int i=0; (b=in.read()) >= 0 && i<(1024*64); i++ )
          baout.write(b);
        in.close();
        baout.close();
        byte[] cipher = baout.toByteArray();


        passphrase = passhandler.decryptPassword(cipher, custompassphraseproperties);
        if ( passphrase != null )
          passphrasestatus = PASS_KNOWN;
      }
    }
    if (passphrasestatus == UNKNOWN_PASS_STATUS)
      passphrasestatus = PASS_NONE;
    
    eu.setPassPhraseStatus( getCanonicalPath(), passphrasestatus );
    eu.setPassPhrase( getCanonicalPath(), passphrase );
  }
  
  
  public synchronized OutputStream getEncryptingOutputStream(String name, boolean replace, boolean sign )
          throws IOException
  {
    if ( type == 0 )
      throw new IOException("Encrypted composite file not initialised");
    return getEncryptingOutputStream( name, replace, sign, true );
  }  
  
  /**
   * Retrieves an output stream for a new entry in the composite file.As data is sent to
 the stream it is encrypted using a symmetric key algorithm locked with this archive's passphrase
 and a random salt.
   * 
   * @param eu
   * @param name The relative path of the entry.
   * @param replace Should the operation go ahead if there is already an entry with the given name?
   * @param sign
   * @return The stream to write 'plain text' to.
   * @throws IOException 
   */
  private synchronized OutputStream getEncryptingOutputStream(String name, boolean replace, boolean sign, boolean check )
          throws IOException
  {
    KeyFinder keyfinder = eu.getKeyFinder();
    if ( keyfinder == null && sign )
      throw new IOException("Can't sign an entry in a composite file if the user doesn't specify OpenPGP keys.");
    try
    {
      initPassphraseForThisCompositeFile();
    }
    catch (NoSuchProviderException ex)
    {
      throw new IOException("Unable to determine password to use.",ex);
    }
    if ( eu.getPassPhraseStatus(getCanonicalPath()) != PASS_KNOWN )
      throw new IOException("Unable to initialise encrypted output because there are no recipients added.");
    char[] passphrase = eu.getPassPhrase(getCanonicalPath());
    if ( passphrase == null )
      throw new IOException("Unable to initialise encrypted output because no pass phrase has been generated.");

    if ( check && type == TYPE_SHARED_AC  )
    {
      int selfpermission = getPermission( keyfinder.getSecretKeyForSigning().getPublicKey() );
      if ( (selfpermission & WRITE_PERMISSION) == 0 )
        throw new IOException( "User does not have permission to write data into  " + getCanonicalPath() );
    }

    
    OutputStream taroutput = super.getOutputStream(name, replace);

    PGPEncryptedDataGenerator encryptiongen = new PGPEncryptedDataGenerator(
            new JcePGPDataEncryptorBuilder(PGPEncryptedData.CAST5)
              .setWithIntegrityPacket( !sign )   // no integrity check if there is a full signature
              .setSecureRandom(new SecureRandom())
              .setProvider("BC")
    );
    encryptiongen.addMethod(new JcePBEKeyEncryptionMethodGenerator(passphrase).setProvider("BC"));
    OutputStream encryptedoutput;
    try
    {
      encryptedoutput = encryptiongen.open(taroutput, new byte[1 << 16]);
    } catch (PGPException ex)
    {
      throw new IOException("Unable to initialise encrypted output.", ex);
    }
    PGPLiteralDataGenerator literalgen = new PGPLiteralDataGenerator();
    PGPCompressedDataGenerator compressiongen = new PGPCompressedDataGenerator(CompressionAlgorithmTags.ZIP);
    OutputStream compressingout = compressiongen.open(encryptedoutput);
    
    PGPSignatureGenerator siggen = null;
    if ( sign )
    {
      try
      {
        PGPSecretKey secretkey = keyfinder.getSecretKeyForSigning();
        PGPPublicKey publickey = secretkey.getPublicKey();
        PGPPrivateKey privatekey = keyfinder.getPrivateKey(secretkey);
        BcPGPContentSignerBuilder signerbuilder = new BcPGPContentSignerBuilder( publickey.getAlgorithm(), HashAlgorithmTags.SHA256);
        siggen = new PGPSignatureGenerator(signerbuilder);
        siggen.init( PGPSignature.BINARY_DOCUMENT, privatekey );
        PGPSignatureSubpacketGenerator subpackgen = new PGPSignatureSubpacketGenerator();
        subpackgen.setSignerUserID( false, keyfinder.getPreferredAlias(secretkey) );
        siggen.setHashedSubpackets( subpackgen.generate() );
        // create the header that must precede the data and send it to 
        // the tar entry before the compressed, encrypted content
        siggen.generateOnePassVersion(false).encode(compressingout);
      }
      catch (PGPException ex)
      {
        Logger.getLogger(EncryptedCompositeFile.class.getName()).log(Level.SEVERE, null, ex);
        throw new IOException("Unable to initialise encrypted output.", ex);
      }
    }    
    
    
    
    OutputStream literalout = literalgen.open(compressingout, PGPLiteralData.BINARY, name, new Date(System.currentTimeMillis()), new byte[1 << 16]);
    
    return new EncryptedOutputWrapper(taroutput, encryptedoutput, compressingout, compressiongen, siggen, literalout);
  }

  /**
   * Cleans up after entry has been created.
   * @throws IOException 
   */
  @Override
  synchronized void closeOutputStream() throws IOException
  {
    super.closeOutputStream();
  }

  /**
   * Opens the file and reads enough encrypted data to find the PGPOnePassSignatureList and obtain the
   * signer's key id. Then prematurely closes the stream. Then fetches the public key from the ID, possibly
   * from the same tar file as the signed data. Then the entry can be reopened to read the data and check the
   * signature against the loaded key.
   * This is all done so signed files and keys can be kept in the same tar file.
   * 
   * @param eu
   * @param name
   * @param passphrase
   * @return 
   */
  private synchronized long getSignerKeyId( String name, char[] passphrase ) throws IOException
  {
    try ( InputStream  tarin = super.getInputStream(name) )
    {
      InputStream in = PGPUtil.getDecoderStream(tarin);
      JcaPGPObjectFactory pgpF = new JcaPGPObjectFactory(in);
      PGPEncryptedDataList enc;
      Object o = pgpF.nextObject();
      //System.out.println( "o = " + o.getClass() );
      if (o instanceof PGPEncryptedDataList)
        enc = (PGPEncryptedDataList) o;
      else
      {
        enc = (PGPEncryptedDataList) pgpF.nextObject();
        //System.out.println( "o = " + o.getClass() );
      }
      PGPPBEEncryptedData pbe = (PGPPBEEncryptedData) enc.get(0);
      InputStream clearin = pbe.getDataStream(
              new JcePBEDataDecryptorFactoryBuilder(
                      new JcaPGPDigestCalculatorProviderBuilder().setProvider("BC").build()
              ).setProvider("BC").build(passphrase) );
      JcaPGPObjectFactory pgpFact = new JcaPGPObjectFactory(clearin);
      o = pgpFact.nextObject();
      //System.out.println( "Object class " + o.getClass().toString() );
      if (o instanceof PGPCompressedData)
      {
        PGPCompressedData cData = (PGPCompressedData) o;        
        pgpFact = new JcaPGPObjectFactory(cData.getDataStream());
        o = pgpFact.nextObject();
      }
      //System.out.println( "Object class " + o.getClass().toString() );
      
      if ( !(o instanceof PGPOnePassSignatureList) )
        return 0L;
      
      //System.out.println( "File was signed." );
      PGPOnePassSignatureList onepasssiglist = (PGPOnePassSignatureList)o;
      if ( onepasssiglist.size() != 1 )
        throw new IOException( "Invalid Signature Format in data file." );
      PGPOnePassSignature onepasssignature = onepasssiglist.get(0);
      return onepasssignature.getKeyID();  
    } catch (PGPException ex)
    {
      Logger.getLogger(EncryptedCompositeFile.class.getName()).log(Level.SEVERE, null, ex);
      return 0L;
    }
    // input stream is closed, ready to read from same store if necessary.
  }

  private synchronized PGPPublicKey getSignerPublicKey( String name, char[] passphrase ) throws IOException
  {
    long signerkeyid = getSignerKeyId( name, passphrase );
    if ( signerkeyid == 0L )
      return null;
    PGPPublicKey signerpubkey = eu.getKeyFinder().findPublicKey(signerkeyid);
    if ( signerpubkey == null )
      throw new IOException( "Unable to find public key used to sign this data file. Name = '" + name + "', signature key id = '" + Long.toHexString(signerkeyid) + "'." );        
    return signerpubkey;
  }

  public  synchronized InputStream getDecryptingInputStream( String name ) throws IOException
  {
    if ( type == 0 )
      throw new IOException("Encrypted composite file not initialised");
    return getDecryptingInputStream( name, true );
  }
  
  /**
   * Get input stream to read data from an entry.The data will be decrypted before being delivered to the stream.
   * 
   * @param eu
   * @param name
   * @return
   * @throws IOException 
   */
  private  synchronized InputStream getDecryptingInputStream( String name, boolean permission ) throws IOException
  {
    //System.out.println( "Reading " + name );
    try
    {
      initPassphraseForThisCompositeFile();
    }
    catch (NoSuchProviderException ex)
    {
      throw new IOException("Unable to determine password to use.",ex);
    }
    if ( eu.getPassPhraseStatus(getCanonicalPath()) != PASS_KNOWN )
      throw new IOException("The file is encrypted but not for the key that was just presented.");
    char[] passphrase = eu.getPassPhrase(getCanonicalPath());
    if ( passphrase == null )
      throw new IOException("Unable to initialise decryption input because no pass phrase has been generated.");
    
    PGPPublicKey signerpublickey=null;
    
    if ( !ignoresignatures )
    {
      signerpublickey = getSignerPublicKey( name, passphrase );
      if ( permission  && type == TYPE_SHARED_AC )
      {
        int signerpermission = getPermission( signerpublickey );
        if ( (signerpermission & WRITE_PERMISSION) == 0 )
          throw new IOException( "User who signed the data file does not have permission to write data into " + getCanonicalPath() );
      }
    }
    
    EncryptedInputWrapper inputwrapper = new EncryptedInputWrapper();
    try ( InputStream  tarin = super.getInputStream(name) )
    {
      inputwrapper.tarin = tarin;
      InputStream in = PGPUtil.getDecoderStream(inputwrapper.tarin);
      JcaPGPObjectFactory pgpF = new JcaPGPObjectFactory(in);
      PGPEncryptedDataList enc;
      Object o = pgpF.nextObject();
      //System.out.println( "o = " + o.getClass() );
      if (o instanceof PGPEncryptedDataList)
        enc = (PGPEncryptedDataList) o;
      else
      {
        enc = (PGPEncryptedDataList) pgpF.nextObject();
        //System.out.println( "o = " + o.getClass() );
      }
      inputwrapper.pbe = (PGPPBEEncryptedData) enc.get(0);
      inputwrapper.clearin = inputwrapper.pbe.getDataStream(
              new JcePBEDataDecryptorFactoryBuilder(
                      new JcaPGPDigestCalculatorProviderBuilder().setProvider("BC").build()
              ).setProvider("BC").build(passphrase) );
      JcaPGPObjectFactory pgpFact = new JcaPGPObjectFactory(inputwrapper.clearin);
      o = pgpFact.nextObject();
      //System.out.println( "Object class " + o.getClass().toString() );
      if (o instanceof PGPCompressedData)
      {
        PGPCompressedData cData = (PGPCompressedData) o;        
        pgpFact = new JcaPGPObjectFactory(cData.getDataStream());
        o = pgpFact.nextObject();
      }
      //System.out.println( "Object class " + o.getClass().toString() );
      
      if ( o instanceof PGPOnePassSignatureList )
      {
        if ( !ignoresignatures )
        {
          //System.out.println( "File " + name + " was signed." );
          inputwrapper.onepasssiglist = (PGPOnePassSignatureList)o;
          inputwrapper.onepasssignature = inputwrapper.onepasssiglist.get(0);
          long signerkeyid = inputwrapper.onepasssignature.getKeyID();

          if ( signerpublickey == null || signerkeyid != signerpublickey.getKeyID() )
            throw new IOException("Unable to determine the ID of the key that signed this data.");

          TrustContextReport report = eu.getTrustContext().checkTrusted( signerkeyid );
          if( !report.isTrusted() )
            throw new TrustContextException( report );
          BcPGPContentVerifierBuilderProvider converbuildprov = new BcPGPContentVerifierBuilderProvider();
          inputwrapper.onepasssignature.init( converbuildprov, signerpublickey );
        }
        o = pgpFact.nextObject();
        //System.out.println( "Object class " + o.getClass().toString() );
      }
      
      PGPLiteralData ld = (PGPLiteralData) o;
      inputwrapper.literalin = ld.getInputStream();
      inputwrapper.pgpobjectfactory = pgpFact;
      return inputwrapper;
      
    } catch (PGPException ex)
    {
      Logger.getLogger(EncryptedCompositeFile.class.getName()).log(Level.SEVERE, null, ex);
    }

    return null;
  }

  /**
   * Tidies up after entry has been read.
   */
  @Override
  synchronized void closeInputStream()
  {      
    super.closeInputStream();
  }

  /**
   * Close the composite file when access to entries in it is no longer needed.
   */
  @Override
  public void close()
  {
    super.close();
  }

  /**
   * Takes a password and encrypts it using a public key.
   * @param passphrase The passphrase to encrypt.
   * @param encKey The key to use in the encryption.
   * @param withIntegrityCheck Whether to add an integrity check to the encryption.
   * @return
   * @throws IOException
   * @throws NoSuchProviderException 
   */
  private static byte[] encryptPassphraseUsingOpenPGP(
          char[] passphrase,
          PGPPublicKey encKey,
          boolean withIntegrityCheck)
          throws IOException, NoSuchProviderException
  {
    try
    {
      byte[] pw = new String(passphrase).getBytes();
      ByteArrayOutputStream literal = new ByteArrayOutputStream();
      ByteArrayOutputStream encrypted = new ByteArrayOutputStream();

      PGPLiteralDataGenerator lData = new PGPLiteralDataGenerator();
      lData.open(literal, PGPLiteralData.BINARY, "passphrase.txt", pw.length, new Date(System.currentTimeMillis())).write(pw);
    
      PGPEncryptedDataGenerator encGen = new PGPEncryptedDataGenerator(
              new JcePGPDataEncryptorBuilder(PGPEncryptedData.CAST5).setWithIntegrityPacket(withIntegrityCheck).setSecureRandom(new SecureRandom()).setProvider("BC"));
      encGen.addMethod(new JcePublicKeyKeyEncryptionMethodGenerator(encKey).setProvider("BC"));
      OutputStream cOut = encGen.open(encrypted, literal.size());
      cOut.write(literal.toByteArray());
      cOut.flush();
      cOut.close();
      //System.out.println("Encrypted password length = " + encrypted.size());
      return encrypted.toByteArray();

    } catch (PGPException e)
    {
      System.err.println(e);
      if (e.getUnderlyingException() != null)
      {
        e.getUnderlyingException().printStackTrace();
      }
    }
    catch (Exception ex)
    {
      Logger.getLogger(EncryptedCompositeFile.class.getName()).log(Level.SEVERE, null, ex);
    }
    return null;
  }

  /**
   * Decrypt a passphrase using the user's private key.
   * @param in The passphrase will be read from this input stream which is assumed to contain PGP encrypted data in binary format.
   * @return The passphrase as array of chars.
   * @throws IOException
   * @throws NoSuchProviderException 
   */
  private char[] decryptPassphraseUsingOpenPGP( EncryptedCompositeFileUser eu, InputStream in )
          throws IOException, NoSuchProviderException
  {
    PGPSecretKey secretkey = eu.getKeyFinder().getSecretKeyForDecryption();
    PGPPrivateKey privatekey = eu.getKeyFinder().getPrivateKey(secretkey);
    long keyid = secretkey.getKeyID();
    String pw = null;
    in = PGPUtil.getDecoderStream(in);

    try
    {
      JcaPGPObjectFactory pgpF = new JcaPGPObjectFactory(in);
      PGPEncryptedDataList enc;
      Object o = pgpF.nextObject();
      //
      // the first object might be a PGP marker packet.
      //
      if (o instanceof PGPEncryptedDataList)
      {
        enc = (PGPEncryptedDataList) o;
      } else
      {
        enc = (PGPEncryptedDataList) pgpF.nextObject();
      }

      /*
      Find the secret pgpkey that matches our private key
      */
      Iterator it = enc.getEncryptedDataObjects();
      PGPPublicKeyEncryptedData pbe = null;
      boolean found=false;
      while ( !found && it.hasNext())
      {
        pbe = (PGPPublicKeyEncryptedData) it.next();
        //System.out.println( "Is " + Long.toHexString(pbe.getKeyID()) + " == " + Long.toHexString(keyid) + " ?");
        if ( pbe.getKeyID() == keyid )
          found = true;
      }

      if ( !found )
      {
        throw new IllegalArgumentException("secret key for message not found.");
      }

      InputStream clear;
      clear = pbe.getDataStream(new JcePublicKeyDataDecryptorFactoryBuilder().setProvider("BC").build(privatekey));
      
      JcaPGPObjectFactory plainFact = new JcaPGPObjectFactory(clear);
      Object message = plainFact.nextObject();

      if (message instanceof PGPCompressedData)
      {
        PGPCompressedData cData = (PGPCompressedData) message;
        JcaPGPObjectFactory pgpFact = new JcaPGPObjectFactory(cData.getDataStream());
        message = pgpFact.nextObject();
      }

      if (message instanceof PGPLiteralData)
      {
        PGPLiteralData ld = (PGPLiteralData) message;
        InputStream unc = ld.getInputStream();
        ByteArrayOutputStream fOut = new ByteArrayOutputStream();
        Streams.pipeAll(unc, fOut);
        fOut.close();
        pw = fOut.toString();
        //System.out.println("Pass " + pw);
      } else if (message instanceof PGPOnePassSignatureList)
      {
        throw new PGPException("encrypted message contains a signed message - not literal data.");
      } else
      {
        throw new PGPException("message is not a simple encrypted file - type unknown.");
      }

      if (pbe.isIntegrityProtected())
      {
        if (!pbe.verify())
        {
          System.out.println("message failed integrity check");
        } else
        {
          //System.err.println("message integrity check passed");
        }
      } else
      {
        //System.err.println("no message integrity check");
      }
    } catch (PGPException e)
    {
      System.out.println(e);
      if (e.getUnderlyingException() != null)
      {
        e.getUnderlyingException().printStackTrace();
      }
    }

    return pw.toCharArray();
  }

  public void addPublicKey(PGPPublicKey key) throws IOException, NoSuchProviderException, NoSuchAlgorithmException
  {
    if ( type == 0 )
      throw new IOException("Encrypted composite file not initialised");
    addPublicKeyPrivately( key );
  }  
  
  /**
   * Add a public key to the composite file which will be used to encrypt the passphrase.If this is the first public key then generate a random passphrase first.
   * @param eu
   * @param key
   * @throws IOException
   * @throws NoSuchProviderException
   * @throws NoSuchAlgorithmException 
   */
  private void addPublicKeyPrivately(PGPPublicKey key) throws IOException, NoSuchProviderException, NoSuchAlgorithmException
  {
    initPassphraseForThisCompositeFile();
    int passphrasestatus = eu.getPassPhraseStatus( getCanonicalPath() );
    if (passphrasestatus == PASS_HIDDEN)
    {
      throw new IOException("Cannot determine password so cannot add access to another user.");
    }

    if (passphrasestatus == PASS_NONE)
    {
      eu.setPassPhrase(getCanonicalPath(), QuiptoStandards.generateRandomPassphrase() );
      eu.setPassPhraseStatus(getCanonicalPath(), PASS_KNOWN );
    }

    OutputStream out = super.getOutputStream(getPassphraseFileName(key), true);
    byte[] encrypted = encryptPassphraseUsingOpenPGP( eu.getPassPhrase( getCanonicalPath() ), key, true);
    out.write(encrypted);
    out.close();
  }

  /**
   * Add single 'custom' encrypted password.
   * @param eu
   * @param key
   * @throws IOException
   * @throws NoSuchProviderException
   * @throws NoSuchAlgorithmException 
   */
  private void addCustomUser() throws IOException, NoSuchProviderException, NoSuchAlgorithmException
  {
    initPassphraseForThisCompositeFile();
    int passphrasestatus = eu.getPassPhraseStatus( getCanonicalPath() );
    if (passphrasestatus == PASS_HIDDEN)
    {
      throw new IOException("Cannot determine password so cannot add access to another user.");
    }

    if (passphrasestatus == PASS_NONE)
    {
      eu.setPassPhrase(getCanonicalPath(), QuiptoStandards.generateRandomPassphrase() );
      eu.setPassPhraseStatus(getCanonicalPath(), PASS_KNOWN );
    }

    custompassphraseproperties = eu.getPasswordHandler().getEncryptionProperties();
    byte[] encrypted = eu.getPasswordHandler().encryptPassword( eu.getPassPhrase( getCanonicalPath() ) );
    
    String filename = getCustomPassphraseFileName();
    
    OutputStream out = super.getOutputStream(filename+".properties", true);
    custompassphraseproperties.storeToXML(out, "");
    out.close();
    
    out = super.getOutputStream(filename, true);
    out.write(encrypted);
    out.close();
  }  
  
  /**
   * An input stream which is given to client code when attempting to read an encrypted entry.
   * It intercepts the close() method to clear up underlying classes that relate to the
   * decryption process.
   */
  class EncryptedInputWrapper
          extends InputStream
  {
    InputStream literalin;
    InputStream clearin;
    InputStream tarin;
    PGPPBEEncryptedData pbe;    
    PGPOnePassSignatureList onepasssiglist;
    PGPOnePassSignature onepasssignature;
    JcaPGPObjectFactory pgpobjectfactory;
    boolean closed = false;
    
    long sigcount=0;
    
    @Override
    public boolean markSupported()
    {
      return literalin.markSupported(); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public synchronized void reset() throws IOException
    {
      literalin.reset(); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public synchronized void mark(int readlimit)
    {
      literalin.mark(readlimit); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public void close() throws IOException
    {
      if ( closed ) return;
      closed = true;
      if (pbe.isIntegrityProtected())
      {
        try
        {
          if (!pbe.verify())
          {
            System.out.println("message failed integrity check");
          } else
          {
            //System.out.println("message integrity check passed");
          }
        } catch (PGPException ex)
        {
          System.out.println("unable to run integrity check");
        }
      } else
      {
        //System.out.println("no message integrity check");
      }
      closeInputStream();
      literalin.close();

      if ( !ignoresignatures && onepasssignature != null )
      {
        Object o = pgpobjectfactory.nextObject();
        //System.out.println( "\n\nObject class following literal data object." + o.getClass().toString() );
        if ( o instanceof PGPSignatureList )
        {
          PGPSignatureList siglist = (PGPSignatureList)o;
          if ( siglist.size() != 1 )
            throw new IOException( "Problem attempting to verify the digital signature on this data file." );
          PGPSignature signature = siglist.get(0);
          //System.out.println( "Verifying " + sigcount + " bytes of data" );
          try
          {
            boolean verified = onepasssignature.verify(signature);
            //System.out.println( "Signature verification " + verified );
          }
          catch (PGPException ex)
          {
            System.out.println( "Signature verification crashed"  );
            Logger.getLogger(EncryptedCompositeFile.class.getName()).log(Level.SEVERE, null, ex);
          }
        }
      }

    }

    @Override
    public int available() throws IOException
    {
      return literalin.available(); 
    }

    @Override
    public long skip(long n) throws IOException
    {
      return literalin.skip(n);
    }

    @Override
    public int read(byte[] b, int off, int len) throws IOException
    {
      int n = literalin.read(b, off, len);
      if ( onepasssignature != null )
      {
        onepasssignature.update(b, off, n);
        sigcount+=n;
      }
      return n;
    }

    @Override
    public int read(byte[] b) throws IOException
    {
      int n = literalin.read(b);
      if ( onepasssignature != null )
      {
        onepasssignature.update(b, 0, n);
        sigcount+=n;
      }
      return n;
    }

    @Override
    public int read() throws IOException
    {
      int b = literalin.read();
      if ( onepasssignature != null && b>=0 )
      {
        onepasssignature.update((byte)b);
        sigcount+=1;
      }
      return b;
    }
    
  }
  
  
  
  /**
   * An output stream which is given to client code when attempting to write an encrypted entry.
   * It intercepts the close() method to clear up underlying classes that relate to the
   * encryption process.
   */  
  class EncryptedOutputWrapper
          extends OutputStream
  {
    OutputStream taroutput;
    OutputStream encryptedoutput;
    OutputStream compressingoutput;
    PGPCompressedDataGenerator compressiongen;
    PGPSignatureGenerator siggen;
    OutputStream literaloutput;
    long sigcount=0;

    public EncryptedOutputWrapper(
            OutputStream taroutput, 
            OutputStream encryptedoutput,
            OutputStream compressingoutput, 
            PGPCompressedDataGenerator compressiongen, 
            PGPSignatureGenerator siggen, 
            OutputStream literaloutput)
    {
      this.taroutput = taroutput;
      this.encryptedoutput = encryptedoutput;
      this.compressingoutput = compressingoutput;
      this.compressiongen = compressiongen;
      this.siggen = siggen;
      this.literaloutput = literaloutput;
    }

    @Override
    public void close()
            throws IOException
    {
      flush();
      literaloutput.close();   // complete the literal data packet
      // now the encrypted data block has been flushed to taroutput
      // generate the signature packet and append it to stream.
      if ( siggen != null )
      {
        //System.out.println( "Signing " + sigcount + " bytes of data." );
        try {
          siggen.generate().encode(compressingoutput);          
        }
        catch (PGPException ex) {
          Logger.getLogger(EncryptedCompositeFile.class.getName()).log(Level.SEVERE, null, ex);
          throw new IOException( "Problem attempting to complete digital signature.", ex );
        }
      }
      //compressingoutput.close();
      compressiongen.close();  // complete the enclosing compression packet
      encryptedoutput.close(); // complete the enclosing encryption packet
      taroutput.close();       // now close the taroutput which encloses the whole lot.
    }

    @Override
    public void flush()
            throws IOException
    {
      literaloutput.flush();
    }

    @Override
    public void write(byte[] b, int off, int len)
            throws IOException
    {
      literaloutput.write(b, off, len);
      if ( siggen != null )
      {
        siggen.update(b, off, len);
        sigcount += len;
      }
    }

    @Override
    public void write(byte[] b)
            throws IOException
    {
      literaloutput.write(b, 0, b.length);
      if ( siggen != null )
      {
        siggen.update(b, 0, b.length);
        sigcount += b.length;
      }
    }

    @Override
    public void write(int b)
            throws IOException
    {
      literaloutput.write(b);
      if ( siggen != null )
      {
        siggen.update((byte)b);
        sigcount += 1;
      }
    }

  }

}
