/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.quipto.trust.team;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import java.util.Stack;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.swing.event.TreeModelEvent;
import javax.swing.event.TreeModelListener;
import javax.swing.tree.TreeModel;
import javax.swing.tree.TreeNode;
import javax.swing.tree.TreePath;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.parsers.SAXParser;
import javax.xml.parsers.SAXParserFactory;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.operator.bc.BcPGPContentVerifierBuilderProvider;
import org.bouncycastle.util.Arrays;
import org.quipto.QuiptoStandards;
import org.quipto.compositefile.EncryptedCompositeFile;
import org.quipto.compositefile.EncryptedCompositeFileUser;
import org.quipto.compositefile.WrongPasswordException;
import org.quipto.key.KeyFinder;
import org.quipto.key.impl.CompositeFileKeyStore;
import org.quipto.trust.TrustContextException;
import org.quipto.trust.TrustContextReport;
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
  KeyFinder personalkeyfinder;
  final HashMap<Long,TeamNode> nodesbyid = new HashMap<>();
  TeamNode nodeofuser = null;
  
  TeamModel teammodel = new TeamModel();
  
  public TeamKeyStore( File file, EncryptedCompositeFileUser eu, KeyFinder personalkeyfinder )
          throws IOException, NoSuchProviderException, NoSuchAlgorithmException, WrongPasswordException
  {
    super( file );
    super.setUser(eu);
    this.personalkeyfinder = personalkeyfinder;
    //System.out.println( "CONSTRUCTED TeamKeyStore" );
  }

  public TreeModel getTreeModel()
  {
    return teammodel;
  }
  
  public String getTrustId()
  {
    if ( waitingtoload )
      loadTree();
    return teamid;
  }
  
  
  public void setRootKey( PGPPublicKey key ) throws IOException, WrongPasswordException
  {
    if ( waitingtoload )
      loadTree();
    teamid = QuiptoStandards.generateRandomId( 256 );
    addNode( null, key, true );
    saveTree();
  }
  
  public void addKey( PGPPublicKey parentkey, PGPPublicKey key, boolean controller ) throws IOException, WrongPasswordException
  {
    if ( waitingtoload )
      loadTree();
    if ( rootteamnode == null )
      throw new IOException( "Attempt to add key to team key store when there is no root key in the store.");
    if ( parentkey == null )
      throw new IOException( "Attempt to add key to team key store without a parent key.");
    TeamNode parent = this.nodesbyid.get( parentkey.getKeyID() );
    if ( parent == null )
      throw new IOException( "Attempt to add key to team key store with a parent key that is not already in the store.");
    addNode( parent, key, controller );
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
  
//  public PGPPublicKey[] getTeamCertifiedAncestors( long keyid, Set<Long> personallytrusted )
//  {
//    if ( waitingtoload )
//      loadTree();
//    ArrayList<PGPPublicKey> list = new ArrayList<>();
//    TeamNode currentnode = nodesbyid.get(keyid);
//    TeamNode parentnode;
//    while ( currentnode != null )
//    {
//      list.add( currentnode.publickey );
//      parentnode = currentnode.parent;
//      if ( currentnode.signedparent )
//        currentnode = parentnode;  // This team node signed its parent - continue to parent
//      else if ( parentnode != null && personallytrusted.contains(parentnode.keyid) )
//        currentnode = parentnode;  // Team parent node was personally signed by user
//      else
//        currentnode = null;        // trust ran out or we got to the root node
//    }
//    return list.toArray( new PGPPublicKey[list.size()] );
//  }
  
//  public PGPPublicKey[] getTeamKeyChain( long keyid, List<Long> trustedkeyids )
//  {
//    if ( waitingtoload )
//      loadTree();
//    ArrayList<List<PGPPublicKey>> candidates = new ArrayList<>();
//    for ( long tkeyid : trustedkeyids )
//    {
//      List<PGPPublicKey> listolists = getTeamKeyChain( keyid, tkeyid );
//      if ( listolists != null )
//        candidates.add(listolists);
//    }
//    
//    if ( candidates.isEmpty() )
//      return null;
//    
//    int best=0;
//    for ( int i=0; i<candidates.size(); i++ )
//      if ( candidates.get(i).size() < candidates.get(best).size() )
//        best = i;
//   
//    List<PGPPublicKey> bestlist = candidates.get(best);
//    return bestlist.toArray( new PGPPublicKey[bestlist.size()] );
//  }

  private TeamNode getCommonAncestor( long keyida, long keyidb )
  {
    if ( waitingtoload )
      loadTree();
    
    TeamNode currentnodea, currentnodeb;
    currentnodea = nodesbyid.get( keyida );
    currentnodeb = nodesbyid.get( keyidb );
    if ( currentnodea == null || currentnodeb == null )
      return null;
    
    while ( currentnodea != currentnodeb )
    {
      if ( currentnodea.depth > currentnodeb.depth )
        currentnodea = currentnodea.parent;
      else if ( currentnodeb.depth > currentnodea.depth )
        currentnodeb = currentnodeb.parent;
      else
      {
        currentnodea = currentnodea.parent;
        currentnodeb = currentnodeb.parent;        
      }
    }
    
    return currentnodea;
  }

  private void verifyKeySignature( SignatureStatus status )
  {
    try
    {
      status.sig.init( new BcPGPContentVerifierBuilderProvider(), status.signerkey );
      //status.sig.update( status.signedkey.getEncoded() );
      if ( status.sig.verifyCertification( status.signedkey ) )
        status.report = new TrustContextReport( true, "Verified" );
      else
        status.report = new TrustContextReport( false, "Invalid signature" );
    }
    catch (PGPException ex)
    {
      Logger.getLogger(TeamKeyStore.class.getName()).log(Level.SEVERE, null, ex);
      status.report = new TrustContextReport( false, "Technical fault attempting to verify signature." );
    }
  }
  
  private TrustContextReport verifySignature( TeamNode signednode, TeamNode signernode )
  {
    if ( signednode.signedpersonally.signed )
    {
      if ( signednode.signedpersonally.report == null )
        verifyKeySignature( signednode.signedpersonally );
      if ( signednode.signedpersonally.report.isTrusted() )
        return signednode.signedpersonally.report;
    }

    if ( signednode.parent == signernode && signednode.signedbyparent.signed )
    {
      if ( signednode.signedbyparent.report == null )
        verifyKeySignature( signednode.signedbyparent );
      return signednode.signedbyparent.report;
    }
    
    if ( signernode.parent == signednode && signernode.signedparent.signed )
    {
      if ( signernode.signedparent.report == null )
        verifyKeySignature( signernode.signedparent );
      return signernode.signedparent.report;
    }
    
    return new TrustContextReport( false, "Unable to find appropriate signatures." );
  }
  
 
  /**
   * Find a line of trust from signerkeyid to ownkeyid
   * @param signerkeyid
   * @param personalkeyfinder
   * @return 
   */
  public TrustContextReport verifyTeamKeyChain( long signerkeyid )
  {
    if ( waitingtoload )
      loadTree();
    
    List<TeamNode> uplist, downlist, list;
    list = new ArrayList<>();
    
    if ( nodeofuser == null )
      return new TrustContextReport( false, "Unable to find current user's public key in the team file." );
    
    TeamNode commonancestor = getCommonAncestor( signerkeyid, nodeofuser.keyid );
    if ( commonancestor == null )
      return new TrustContextReport( false, "Unable to find team controller that trusts both the user signature and data signer." );
    
    uplist= getTeamKeyChainPointToPoint( signerkeyid, commonancestor.keyid );
    if ( uplist == null || uplist.isEmpty() )
      return new TrustContextReport( false, "Unable to find chain of trust between data signer and a team controller signature." );

      
    for ( int i=0; i<(uplist.size()-1); i++ )
    {
      TeamNode node = uplist.get( i );
      TeamNode parent = uplist.get( i+1 );
      TrustContextReport report = verifySignature( node, parent );
      if ( !report.isTrusted() )
        return report;
    }
    
    list.addAll(uplist);

    if ( commonancestor.keyid != nodeofuser.keyid )
    {
      downlist= getTeamKeyChainPointToPoint( nodeofuser.keyid, commonancestor.keyid );
      if ( downlist == null || downlist.isEmpty() )
        return new TrustContextReport( false, "Unable to find chain of trust between team controller signature data signer." );
        
      for ( int i=0; i<(downlist.size()-1); i++ )
      {
        TeamNode node = downlist.get( i );
        TeamNode parent = downlist.get( i+1 );
        TrustContextReport report = verifySignature( parent, node );
        if ( !report.isTrusted() )
          return report;
      }

      // list up instead of down
      Collections.reverse(downlist);
      // remove duplicate of commonancestor
      downlist.remove(0);
      list.addAll(downlist);
    }

    if ( list.isEmpty() )
    {
      return new TrustContextReport( false, "Unable to find chain of trust in the team file for the data." );
    }
    
    return new TrustContextReport( true, "Verified all signatures." );
  }
  
  private List<TeamNode> getTeamKeyChainPointToPoint( long keyida, long keyidb )
  {
    if ( waitingtoload )
      loadTree();
    
    ArrayList<TeamNode> list = new ArrayList<>();
    long currentkeyid = keyida;
    TeamNode node;
    boolean foundtrust = false;
    do
    {
      node = nodesbyid.get(currentkeyid);
      if ( node == null ) return null;
      if ( currentkeyid == keyidb )
        foundtrust = true;
      list.add(node);
      currentkeyid = node.parentkeyid;
    }
    while ( !node.isRoot() && !foundtrust );
    
    if ( foundtrust )
      return list;
    
    return null;
  }
  
  public void dumpTeam()
  {
//    try
//    {
//      InputStreamReader reader = new InputStreamReader(compositefile.getDecryptingInputStream(TEAMCONFIGFILENAME));
//      int c;
//      while ( (c = reader.read()) >= 0 )
//        System.out.print( (char)c );
//      System.out.println();
//      reader.close();
//    }
//    catch (IOException ex)
//    {
//      Logger.getLogger(TeamKeyStore.class.getName()).log(Level.SEVERE, null, ex);
//    }
  }
  
//  private void dumpNode( TeamNode node, int depth )
//  {
//    for ( int i=0; i<depth; i++ )
//      System.out.print( "  " );
//    System.out.println( "Node " + Long.toHexString(node.keyid) + " Signed:" );
//    for ( TeamNode child : node.childnodes )
//      dumpNode( child, depth+1 );
//  }
  
  public void loadTree()
  {
    //System.out.println( "LOADING TREE" );
    waitingtoload = false;
    try ( EncryptedCompositeFile compositefile = new EncryptedCompositeFile( file, true, false ) )
    {
      compositefile.setUser( eu );
      teamid=null;
      rootteamnode=null;
      
      if ( !compositefile.exists(TEAMCONFIGFILENAME) )
        return;
      
      try ( InputStream in = compositefile.getDecryptingInputStream(TEAMCONFIGFILENAME) )
      {
        SAXParserFactory spf = SAXParserFactory.newInstance();    
        spf.setNamespaceAware(true);
        SAXParser saxParser = spf.newSAXParser();
        XMLReader xmlReader = saxParser.getXMLReader();
        xmlReader.setContentHandler( new TeamTreeParser() );
        xmlReader.parse( new InputSource(in) );
      }
      
    }
    catch (ParserConfigurationException | SAXException | IOException | NoSuchProviderException | NoSuchAlgorithmException | WrongPasswordException ex )
    {
      rootteamnode=null;
      Logger.getLogger(TeamKeyStore.class.getName()).log(Level.SEVERE, null, ex);
    }
  }
  
  
  void saveTree() throws IOException, WrongPasswordException
  {
    try ( EncryptedCompositeFile compositefile = new EncryptedCompositeFile( file, true, false ) )
    {
      compositefile.setUser( eu );
      try (OutputStreamWriter writer = new OutputStreamWriter( compositefile.getEncryptingOutputStream(TEAMCONFIGFILENAME, true, true), "UTF-8" ))
      {
        writer.write("<?xml version=\"1.0\"?>\n");
        writer.write("<team id=\"" + (teamid==null?"":teamid) + "\">\n");
        saveNode( rootteamnode, writer, 1 );
        writer.write("</team>\n");
      }
    }
    catch (NoSuchProviderException | NoSuchAlgorithmException ex)
    {
      Logger.getLogger(TeamKeyStore.class.getName()).log(Level.SEVERE, null, ex);
      throw new IOException( ex );
    }
    teammodel.fireTreeStructureChanged();
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
  
  TeamNode addNode( TeamNode parentnode, PGPPublicKey key, boolean controller )
  {
    Iterator<PGPSignature> sigit;
    TeamNode teamnode = new TeamNode();
    teamnode.role = (parentnode==null)?(TeamNode.ROLE_ROOT | TeamNode.ROLE_CONTROLLER):TeamNode.ROLE_OTHER;
    if ( controller ) teamnode.role |= TeamNode.ROLE_CONTROLLER;
    teamnode.keyid = key.getKeyID();
    if ( personalkeyfinder.getSecretKeyForSigning().getKeyID() == teamnode.keyid )
      nodeofuser = teamnode;
    teamnode.publickey = key;
    teamnode.parent = parentnode;
    teamnode.parentkeyid = (parentnode==null)?key.getKeyID():parentnode.keyid;
    teamnode.depth = (parentnode==null)?0:parentnode.depth+1;
    if ( parentnode != null )
    {
      // is parent signed by this node?
      teamnode.signedparent.searched=true;
      sigit = parentnode.publickey.getSignaturesForKeyID( teamnode.keyid );
      if ( sigit.hasNext() )
      {
        teamnode.signedparent.signed = true;
        teamnode.signedparent.sig = sigit.next();
        teamnode.signedparent.signedkey = parentnode.publickey;
        teamnode.signedparent.signerkey = teamnode.publickey;
      }
      // is this node signed by parent?
      teamnode.signedbyparent.searched=true;
      sigit = teamnode.publickey.getSignaturesForKeyID( parentnode.keyid );
      if ( sigit.hasNext() )
      {
        teamnode.signedbyparent.signed = true;
        teamnode.signedbyparent.sig = sigit.next();
        teamnode.signedbyparent.signedkey = teamnode.publickey;
        teamnode.signedbyparent.signerkey = parentnode.publickey;
      }
    }

    teamnode.signedpersonally.searched = true;
    PGPPublicKey personalcopy = personalkeyfinder.findPublicKey( teamnode.keyid );
    if ( personalcopy != null && Arrays.areEqual( personalcopy.getFingerprint(), teamnode.publickey.getFingerprint() ))
    {
      PGPPublicKey personalsigner = personalkeyfinder.getSecretKeyForSigning().getPublicKey();
      sigit = personalcopy.getSignaturesForKeyID( personalsigner.getKeyID() );
      if ( sigit.hasNext() )
      {
        teamnode.signedpersonally.signed = true;
        teamnode.signedpersonally.sig = sigit.next();
        teamnode.signedpersonally.signedkey = personalcopy;
        teamnode.signedpersonally.signerkey = personalsigner;
      }
    }
    
    nodesbyid.put(teamnode.keyid, teamnode);
    if ( parentnode != null )
      parentnode.childnodes.add(teamnode);
    else
      rootteamnode = teamnode;
    
    return teamnode;
  }
  
  class SignatureStatus
  {
    boolean searched=false;
    boolean signed=false;
    PGPSignature sig = null;
    PGPPublicKey signedkey = null;
    PGPPublicKey signerkey = null;
    TrustContextReport report;
  }
  
  class TeamNode implements TreeNode
  {
    final static int ROLE_ROOT = 2;
    final static int ROLE_CONTROLLER = 1;
    final static int ROLE_OTHER = 0;
    
    int depth;
    private int role;
    long keyid;
    PGPPublicKey publickey;
    TeamNode parent;
    long parentkeyid;
    
    SignatureStatus signedparent     = new SignatureStatus();
    SignatureStatus signedbyparent   = new SignatureStatus();
    SignatureStatus signedpersonally = new SignatureStatus();
    
    String name=null;
    
    final ArrayList<TeamNode> childnodes = new ArrayList<>();

    public String toString()
    {
      if ( name == null )
        name = publickey.getUserIDs().next(); // + " " + Long.toUnsignedString(keyid, 16);
      return name;
    }
    
    public boolean isRoot()
    {
      return (role & ROLE_ROOT) != 0;
    }

    public boolean isController()
    {
      return (role & ROLE_CONTROLLER) != 0;
    }

    @Override
    public TreeNode getChildAt(int childIndex)
    {
      return childnodes.get( childIndex );
    }

    @Override
    public int getChildCount()
    {
      return childnodes.size();
    }

    @Override
    public TreeNode getParent()
    {
      return parent;
    }

    @Override
    public int getIndex(TreeNode node)
    {
      for ( int i=0; i<childnodes.size(); i++ )
      {
        if ( childnodes.get(i) == node )
          return i;
      }
      return -1;
    }

    @Override
    public boolean getAllowsChildren()
    {
      return (role & ROLE_CONTROLLER) != 0;
    }

    @Override
    public boolean isLeaf()
    {
      return !getAllowsChildren();
    }

    @Override
    public Enumeration children()
    {
      return Collections.enumeration(childnodes);
    }
  }

  class TeamModel implements TreeModel
  {
    ArrayList<TreeModelListener> listeners = new ArrayList<>();
    
    
    @Override
    public Object getRoot()
    {
      return rootteamnode;
    }

    @Override
    public Object getChild(Object parent, int index)
    {
      TeamNode parentnode = (TeamNode)parent;
      return parentnode.getChildAt(index);
    }

    @Override
    public int getChildCount(Object parent)
    {
      TeamNode parentnode = (TeamNode)parent;
      return parentnode.getChildCount();
    }

    @Override
    public boolean isLeaf(Object node)
    {
      TeamNode parentnode = (TeamNode)node;
      return parentnode.isLeaf();
    }

    @Override
    public void valueForPathChanged(TreePath path, Object newValue)
    {
      
    }

    @Override
    public int getIndexOfChild(Object parent, Object child)
    {
      TeamNode parentnode = (TeamNode)parent;
      TeamNode childnode = (TeamNode)child;
      return parentnode.getIndex(childnode);
    }

    @Override
    public void addTreeModelListener(TreeModelListener l)
    {
      listeners.add(l);
    }

    @Override
    public void removeTreeModelListener(TreeModelListener l)
    {
      listeners.remove(l);
    }
    
    public void fireTreeStructureChanged()
    {
      TreeModelEvent e;
      TreeNode[] nodepath = new TreeNode[1];
      nodepath[0] = rootteamnode;
      e = new TreeModelEvent( this, nodepath );
      for ( TreeModelListener l : listeners )
        l.treeStructureChanged(e);
    }
  }
  
  class TeamTreeParser extends DefaultHandler
  {
    Stack<TeamNode> stack = new Stack<>();
    
    
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
      TeamNode parent = null;
      if ( !stack.empty() )
        parent = stack.peek();
      TeamNode node = addNode( parent, key, (role & TeamNode.ROLE_CONTROLLER) != 0 );
      stack.push( node );
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
