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
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.quipto.QuiptoStandards;
import org.quipto.compositefile.EncryptedCompositeFile;
import org.quipto.compositefile.EncryptedCompositeFileUser;
import org.quipto.compositefile.WrongPasswordException;
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
  
  TeamModel teammodel = new TeamModel();
  
  public TeamKeyStore( File file, EncryptedCompositeFileUser eu )
          throws IOException, NoSuchProviderException, NoSuchAlgorithmException, WrongPasswordException
  {
    super( file );
    super.setUser(eu);
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
  
  public PGPPublicKey[] getTeamCertifiedAncestors( long keyid, Set<Long> personallytrusted )
  {
    if ( waitingtoload )
      loadTree();
    ArrayList<PGPPublicKey> list = new ArrayList<>();
    TeamNode currentnode = nodesbyid.get(keyid);
    TeamNode parentnode;
    while ( currentnode != null )
    {
      list.add( currentnode.publickey );
      parentnode = currentnode.parent;
      if ( currentnode.signedparent )
        currentnode = parentnode;  // This team node signed its parent - continue to parent
      else if ( parentnode != null && personallytrusted.contains(parentnode.keyid) )
        currentnode = parentnode;  // Team parent node was personally signed by user
      else
        currentnode = null;        // trust ran out or we got to the root node
    }
    return list.toArray( new PGPPublicKey[list.size()] );
  }
  
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

  private Long getCommonAncestor( long keyida, long keyidb )
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
    
    return currentnodea.keyid;
  }
  
  /**
   * Find a line of trust from keyid to trustedkeyid
   * @param signerkeyid
   * @param ownkeyid
   * @return 
   */
  public PGPPublicKey[] getTeamKeyChain( long signerkeyid, long ownkeyid )
  {
    List<PGPPublicKey> uplist, downlist, list;
    list = new ArrayList<PGPPublicKey>();
    
    Long commonancestor = getCommonAncestor( signerkeyid, ownkeyid );
    if ( commonancestor == null )
      return new PGPPublicKey[0];
    
    uplist= getTeamKeyChainPointToPoint( signerkeyid, commonancestor );
    if ( uplist != null )
      list.addAll(uplist);

    if ( commonancestor != ownkeyid )
    {
      downlist= getTeamKeyChainPointToPoint( ownkeyid, commonancestor );
      if ( downlist == null )
        return new PGPPublicKey[0];
      // list up instead of down
      Collections.reverse(downlist);
      // remove duplicate of commonancestor
      downlist.remove(0);
      list.addAll(downlist);
    }
    
    return list.toArray( new PGPPublicKey[list.size()] );
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
  
  TeamNode addNode( TeamNode parent, PGPPublicKey key, boolean controller )
  {
    if ( waitingtoload )
      loadTree();
    
    TeamNode teamnode = new TeamNode();
    teamnode.role = (parent==null)?(TeamNode.ROLE_ROOT | TeamNode.ROLE_CONTROLLER):TeamNode.ROLE_OTHER;
    if ( controller ) teamnode.role |= TeamNode.ROLE_CONTROLLER;
    teamnode.keyid = key.getKeyID();
    teamnode.publickey = key;
    teamnode.parent = parent;
    teamnode.parentkeyid = (parent==null)?key.getKeyID():parent.keyid;
    teamnode.depth = (parent==null)?0:parent.depth+1;
    teamnode.signedparent = false;
    if ( parent != null )
    {
      Iterator<PGPSignature> sigit = parent.publickey.getSignaturesForKeyID( teamnode.keyid );
      while ( sigit.hasNext() )
      {
        PGPSignature sig = sigit.next();
        if ( true )  // TODO validate the signature
        {
          teamnode.signedparent = true;
          break;
        }
      }
    }
    
    nodesbyid.put(teamnode.keyid, teamnode);
    if ( parent != null )
      parent.childnodes.add(teamnode);
    else
      rootteamnode = teamnode;
    
    return teamnode;
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
    boolean signedparent;
    
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
