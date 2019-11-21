/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.quipto.trust.team;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Stack;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.parsers.SAXParser;
import javax.xml.parsers.SAXParserFactory;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.quipto.QuiptoStandards;
import org.quipto.compositefile.EncryptedCompositeFile;
import org.quipto.compositefile.EncryptedCompositeFileUser;
import org.quipto.key.impl.CompositeFileKeyStore;
import org.xml.sax.Attributes;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;
import org.xml.sax.XMLReader;
import org.xml.sax.helpers.DefaultHandler;

/**
 *
 * @author maber01
 */
public class TeamKeyStore extends CompositeFileKeyStore
{
  static final String TEAMCONFIGFILENAME = "team.xml";
  
  String teamid=null;
  TeamNode rootteamnode=null;
  boolean waitingtoload = true;
  final HashMap<Long,TeamNode> nodesbyid = new HashMap<>();
  
  
  public TeamKeyStore(EncryptedCompositeFile compositefile)
          throws IOException, NoSuchProviderException, NoSuchAlgorithmException
  {
    super(compositefile);
    System.out.println( "CONSTRUCTED TeamKeyStore" );
  }

  
  public String getTrustId()
  {
    if ( waitingtoload )
      loadTree();
    return teamid;
  }
  
  
  public void setRootKey( PGPPublicKey key ) throws IOException
  {
    if ( waitingtoload )
      loadTree();
    teamid = QuiptoStandards.generateRandomId( 256 );
    addNode( null, key, true );
    saveTree();
  }
  
  public void addKey( PGPPublicKey parentkey, PGPPublicKey key, boolean controller ) throws IOException
  {
    if ( waitingtoload )
      loadTree();
    if ( rootteamnode == null )
      throw new IOException( "Attempt to add key to team key store when there is no root key in the store.");
    addNode( parentkey, key, controller );
    saveTree();
  }
  
  public boolean isController( long keyid )
  {
    if ( waitingtoload )
      loadTree();
    TeamNode node;
    node = nodesbyid.get(keyid);
    if ( node == null ) return false;
    return node.isController();
  }
  
  public PGPPublicKey[] getTeamKeyChain( long keyid, List<Long> trustedkeyids )
  {
    if ( waitingtoload )
      loadTree();
    ArrayList<List<PGPPublicKey>> candidates = new ArrayList<>();
    for ( long tkeyid : trustedkeyids )
    {
      List<List<PGPPublicKey>> listolists = getTeamKeyChain( keyid, tkeyid );
      if ( listolists != null )
        candidates.addAll(listolists);
    }
    
    if ( candidates.isEmpty() )
      return null;
    
    int best=0;
    for ( int i=0; i<candidates.size(); i++ )
      if ( candidates.get(i).size() < candidates.get(best).size() )
        best = i;
   
    List<PGPPublicKey> bestlist = candidates.get(best);
    return bestlist.toArray( new PGPPublicKey[bestlist.size()] );
  }

  /**
   * Find a line of trust from keyid to trustedkeyid
   * @param keyid
   * @param trustedkeyid
   * @return 
   */
  private List<List<PGPPublicKey>> getTeamKeyChain( long keyid, long trustedkeyid )
  {
    ArrayList<List<PGPPublicKey>> list = new ArrayList<>();
    
    List<PGPPublicKey> uplist;
    
    uplist= getTeamKeyChainPointToPoint( keyid, trustedkeyid );
    if ( uplist != null )
      list.add(uplist);
    
    uplist= getTeamKeyChainPointToPoint( trustedkeyid, keyid );
    if ( uplist != null )
      list.add(uplist);
    
    
    return list;
  }
  
  private List<PGPPublicKey> getTeamKeyChainPointToPoint( long keyida, long keyidb )
  {
    if ( waitingtoload )
      loadTree();
    
    ArrayList<PGPPublicKey> list = new ArrayList<>();
    long currentkeyid = keyida;
    TeamNode node;
    boolean foundtrust = false;
    do
    {
      node = nodesbyid.get(currentkeyid);
      if ( node == null ) return null;
      if ( currentkeyid == keyidb )
        foundtrust = true;
      list.add(node.publickey);
      currentkeyid = node.parentkeyid;
    }
    while ( !node.isRoot() && !foundtrust );
    
    if ( foundtrust )
      return list;
    
    return null;
  }
  
  public void dumpTeam()
  {
    try
    {
      InputStreamReader reader = new InputStreamReader(compositefile.getDecryptingInputStream(TEAMCONFIGFILENAME));
      int c;
      while ( (c = reader.read()) >= 0 )
        System.out.print( (char)c );
      System.out.println();
      reader.close();
    }
    catch (IOException ex)
    {
      Logger.getLogger(TeamKeyStore.class.getName()).log(Level.SEVERE, null, ex);
    }
  }
  
//  private void dumpNode( TeamNode node, int depth )
//  {
//    for ( int i=0; i<depth; i++ )
//      System.out.print( "  " );
//    System.out.println( "Node " + Long.toHexString(node.keyid) + " Signed:" );
//    for ( TeamNode child : node.childnodes )
//      dumpNode( child, depth+1 );
//  }
  
  private void loadTree()
  {
    System.out.println( "LOADING TREE" );
    waitingtoload = false;
    try
    {
      teamid=null;
      rootteamnode=null;
      
      if ( !compositefile.exists(TEAMCONFIGFILENAME) )
        return;
      
      //dumpTeam();
      
      InputStream in = compositefile.getDecryptingInputStream(TEAMCONFIGFILENAME);
      SAXParserFactory spf = SAXParserFactory.newInstance();    
      spf.setNamespaceAware(true);
      SAXParser saxParser = spf.newSAXParser();
      XMLReader xmlReader = saxParser.getXMLReader();
      xmlReader.setContentHandler( new TeamTreeParser() );
      xmlReader.parse( new InputSource(in) );
      in.close();
    }
    catch (ParserConfigurationException | SAXException | IOException ex)
    {
      rootteamnode=null;
      Logger.getLogger(TeamKeyStore.class.getName()).log(Level.SEVERE, null, ex);
    }
  }
  
  
  void saveTree() throws IOException
  {
    try (OutputStreamWriter writer = new OutputStreamWriter( compositefile.getEncryptingOutputStream(TEAMCONFIGFILENAME, true, true), "UTF-8" ))
    {
      writer.write("<?xml version=\"1.0\"?>\n");
      writer.write("<team id=\"" + (teamid==null?"":teamid) + "\">\n");
      saveNode( rootteamnode, writer, 1 );
      writer.write("</team>\n");
    }
  }
  
  void saveNode( TeamNode node, Writer writer, int depth ) throws IOException
  {
    int i;
    for ( i=0; i<depth; i++ )
      writer.write( "  " );
    writer.write("<node keyid=\"");
    writer.write( Long.toHexString( node.keyid ) );
    writer.write("\" role=\"");
    writer.write( Integer.toString( node.role ) );
    writer.write("\">\n");
    for ( TeamNode child : node.childnodes )
      saveNode( child, writer, depth+1 );
    for ( i=0; i<depth; i++ )
      writer.write( "  " );
    writer.write("</node>\n");
  }
  
  void addNode( PGPPublicKey parentkey, PGPPublicKey key, boolean controller )
  {
    if ( waitingtoload )
      loadTree();
    
    TeamNode parent = null;
    if ( parentkey != null )
      parent = nodesbyid.get(parentkey.getKeyID());
    
    TeamNode teamnode = new TeamNode();
    teamnode.role = (parent==null)?(TeamNode.ROLE_ROOT | TeamNode.ROLE_CONTROLLER):TeamNode.ROLE_OTHER;
    if ( controller ) teamnode.role |= TeamNode.ROLE_CONTROLLER;
    teamnode.keyid = key.getKeyID();
    teamnode.publickey = key;
    teamnode.parentkeyid = (parent==null)?key.getKeyID():parent.keyid;
    
    nodesbyid.put(teamnode.keyid, teamnode);
    if ( parent != null )
      parent.childnodes.add(teamnode);
    else
      rootteamnode = teamnode;
  }
  
  class TeamNode
  {
    final static int ROLE_ROOT = 2;
    final static int ROLE_CONTROLLER = 1;
    final static int ROLE_OTHER = 0;
    
    int role;
    long keyid;
    PGPPublicKey publickey;
    long parentkeyid;
    boolean signedparent;
    
    final ArrayList<TeamNode> childnodes = new ArrayList<>();
    
    public boolean isRoot()
    {
      return (role & ROLE_ROOT) != 0;
    }

    public boolean isController()
    {
      return (role & ROLE_CONTROLLER) != 0;
    }
  }
  
  class TeamTreeParser extends DefaultHandler
  {
    Stack<PGPPublicKey> stack = new Stack<>();
    
    
    @Override
    public void startElement(String uri, String localName, String qName, Attributes attributes)
            throws SAXException
    {
      if ( "team".equals( localName ) )
      {
        // read team properties...
        teamid = attributes.getValue("", "id");
        return;
      }
      
      if ( !"node".equals( localName ) )
        return;
      
      String strrole = attributes.getValue("", "role" );
      int role = Integer.parseInt(strrole);
      String strkeyid = attributes.getValue("", "keyid" );
      long keyid = Long.parseUnsignedLong(strkeyid, 16);
      PGPPublicKeyRing keyring = getPublicKeyRing( keyid );
      PGPPublicKey key = keyring.getPublicKey( keyid );
      PGPPublicKey parentkey = null;
      if ( !stack.empty() )
        parentkey = stack.peek();
      addNode( parentkey, key, (role & TeamNode.ROLE_CONTROLLER) != 0 );
      stack.push(key);
      // ready for children to start too
    }

    @Override
    public void endElement(String uri, String localName, String qName)
            throws SAXException
    {
      if ( !"node".equals(localName) )
        return;
      stack.pop();
    }

    
  }
}
