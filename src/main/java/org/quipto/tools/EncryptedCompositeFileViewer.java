/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.quipto.tools;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.security.Security;
import java.util.ArrayList;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.swing.DefaultListModel;
import javax.swing.JFileChooser;
import javax.swing.JOptionPane;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.io.Streams;
import org.quipto.compositefile.EncryptedCompositeFile;
import org.quipto.compositefile.EncryptedCompositeFilePasswordHandler;
import org.quipto.compositefile.EncryptedCompositeFileUser;
import org.quipto.key.impl.CompositeFileKeyFinder;
import org.quipto.key.impl.CompositeFileKeyStore;
import org.quipto.passwords.PasswordPasswordHandler;
import org.quipto.passwords.WindowsPasswordHandler;
import org.quipto.trust.impl.TrustAnythingContext;
import org.quipto.trust.team.TeamKeyStore;
import org.quipto.trust.team.TeamTrust;

/**
 *
 * @author maber01
 */
public class EncryptedCompositeFileViewer
        extends javax.swing.JFrame
{
  EncryptedCompositeFilePasswordHandler personalkeystorepasshandler;
  File personalkeystorefile;

  TeamTrust teamtrust;
  
  String alias;
  EncryptedCompositeFileUser euser;

  EncryptedCompositeFile compfile;
      
  DefaultListModel<String> listmodel;
  
  /**
   * Creates new form CompositeFileViewer
   */
  public EncryptedCompositeFileViewer()
  {
    initComponents();
    this.setTitle( "Encrypted Composite File Viewer" );
    listmodel = new DefaultListModel<>();
    entrylist.setModel(listmodel);
  }

  /**
   * This method is called from within the constructor to initialize the form. WARNING: Do NOT modify this code. The
   * content of this method is always regenerated by the Form Editor.
   */
  @SuppressWarnings("unchecked")
  // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
  private void initComponents()
  {

    jPanel1 = new javax.swing.JPanel();
    jLabel2 = new javax.swing.JLabel();
    aliaslabel = new javax.swing.JLabel();
    jLabel1 = new javax.swing.JLabel();
    keystorelabel = new javax.swing.JLabel();
    jLabel4 = new javax.swing.JLabel();
    teamlabel = new javax.swing.JLabel();
    jLabel3 = new javax.swing.JLabel();
    datastorelabel = new javax.swing.JLabel();
    jPanel2 = new javax.swing.JPanel();
    jSplitPane1 = new javax.swing.JSplitPane();
    jScrollPane1 = new javax.swing.JScrollPane();
    entrylist = new javax.swing.JList<>();
    jPanel3 = new javax.swing.JPanel();
    jScrollPane2 = new javax.swing.JScrollPane();
    contenttextarea = new javax.swing.JTextArea();
    jMenuBar1 = new javax.swing.JMenuBar();
    jMenu1 = new javax.swing.JMenu();
    openkeyringmenuitem = new javax.swing.JMenuItem();
    openteammenutiem = new javax.swing.JMenuItem();
    openmenuitem = new javax.swing.JMenuItem();
    extractentrymenuitem = new javax.swing.JMenuItem();
    jSeparator1 = new javax.swing.JPopupMenu.Separator();
    exitmenuitem = new javax.swing.JMenuItem();

    setDefaultCloseOperation(javax.swing.WindowConstants.EXIT_ON_CLOSE);

    jPanel1.setLayout(new java.awt.GridLayout(4, 2, 8, 4));

    jLabel2.setFont(new java.awt.Font("Tahoma", 1, 11)); // NOI18N
    jLabel2.setHorizontalAlignment(javax.swing.SwingConstants.TRAILING);
    jLabel2.setText("Alias:");
    jPanel1.add(jLabel2);
    jPanel1.add(aliaslabel);

    jLabel1.setFont(new java.awt.Font("Tahoma", 1, 11)); // NOI18N
    jLabel1.setHorizontalAlignment(javax.swing.SwingConstants.TRAILING);
    jLabel1.setText("Personal Key Store:");
    jPanel1.add(jLabel1);
    jPanel1.add(keystorelabel);

    jLabel4.setFont(new java.awt.Font("Tahoma", 1, 11)); // NOI18N
    jLabel4.setHorizontalAlignment(javax.swing.SwingConstants.TRAILING);
    jLabel4.setText("Team Key Store:");
    jPanel1.add(jLabel4);
    jPanel1.add(teamlabel);

    jLabel3.setFont(new java.awt.Font("Tahoma", 1, 11)); // NOI18N
    jLabel3.setHorizontalAlignment(javax.swing.SwingConstants.TRAILING);
    jLabel3.setText("Data Store:");
    jPanel1.add(jLabel3);
    jPanel1.add(datastorelabel);

    getContentPane().add(jPanel1, java.awt.BorderLayout.NORTH);

    jPanel2.setLayout(new java.awt.BorderLayout());

    jScrollPane1.setBorder(javax.swing.BorderFactory.createTitledBorder("Entries"));

    entrylist.setSelectionMode(javax.swing.ListSelectionModel.SINGLE_SELECTION);
    entrylist.addListSelectionListener(new javax.swing.event.ListSelectionListener()
    {
      public void valueChanged(javax.swing.event.ListSelectionEvent evt)
      {
        entrylistValueChanged(evt);
      }
    });
    jScrollPane1.setViewportView(entrylist);

    jSplitPane1.setLeftComponent(jScrollPane1);

    jPanel3.setLayout(new java.awt.BorderLayout());

    jScrollPane2.setBorder(javax.swing.BorderFactory.createTitledBorder("Content"));

    contenttextarea.setEditable(false);
    contenttextarea.setColumns(20);
    contenttextarea.setRows(5);
    jScrollPane2.setViewportView(contenttextarea);

    jPanel3.add(jScrollPane2, java.awt.BorderLayout.CENTER);

    jSplitPane1.setRightComponent(jPanel3);

    jPanel2.add(jSplitPane1, java.awt.BorderLayout.CENTER);

    getContentPane().add(jPanel2, java.awt.BorderLayout.CENTER);

    jMenu1.setText("File");

    openkeyringmenuitem.setText("Open Personal Key Ring...");
    openkeyringmenuitem.addActionListener(new java.awt.event.ActionListener()
    {
      public void actionPerformed(java.awt.event.ActionEvent evt)
      {
        openkeyringmenuitemActionPerformed(evt);
      }
    });
    jMenu1.add(openkeyringmenuitem);

    openteammenutiem.setText("Open Team Key Ring...");
    openteammenutiem.addActionListener(new java.awt.event.ActionListener()
    {
      public void actionPerformed(java.awt.event.ActionEvent evt)
      {
        openteammenutiemActionPerformed(evt);
      }
    });
    jMenu1.add(openteammenutiem);

    openmenuitem.setText("Open...");
    openmenuitem.addActionListener(new java.awt.event.ActionListener()
    {
      public void actionPerformed(java.awt.event.ActionEvent evt)
      {
        openmenuitemActionPerformed(evt);
      }
    });
    jMenu1.add(openmenuitem);

    extractentrymenuitem.setText("Extract Entry...");
    extractentrymenuitem.addActionListener(new java.awt.event.ActionListener()
    {
      public void actionPerformed(java.awt.event.ActionEvent evt)
      {
        extractentrymenuitemActionPerformed(evt);
      }
    });
    jMenu1.add(extractentrymenuitem);
    jMenu1.add(jSeparator1);

    exitmenuitem.setText("Exit");
    exitmenuitem.addActionListener(new java.awt.event.ActionListener()
    {
      public void actionPerformed(java.awt.event.ActionEvent evt)
      {
        exitmenuitemActionPerformed(evt);
      }
    });
    jMenu1.add(exitmenuitem);

    jMenuBar1.add(jMenu1);

    setJMenuBar(jMenuBar1);

    pack();
  }// </editor-fold>//GEN-END:initComponents

  private void openkeyringmenuitemActionPerformed(java.awt.event.ActionEvent evt)//GEN-FIRST:event_openkeyringmenuitemActionPerformed
  {//GEN-HEADEREND:event_openkeyringmenuitemActionPerformed
    JFileChooser fc = new JFileChooser();
    fc.setCurrentDirectory( new File(".") );
    int result = fc.showOpenDialog( rootPane );
    if ( result != JFileChooser.APPROVE_OPTION )
      return;
    
    File file = fc.getSelectedFile();
    if ( !file.isFile() )
    {
      JOptionPane.showMessageDialog( rootPane, "You need to select a file, not a folder." );
      return;
    }
    
    keystorelabel.setText( file.getAbsolutePath() );
    
    alias = JOptionPane.showInputDialog( rootPane, "Please enter the alias for the key you will use to decrypt data files." );
    if ( alias == null || alias.trim().length() == 0 )
    {
      keystorelabel.setText( "" );
      aliaslabel.setText( "" );
      return;
    }
    aliaslabel.setText(alias);
    
    int choice = JOptionPane.showConfirmDialog(rootPane, "Use windows crypto to unlock?", "Key Store Access", JOptionPane.YES_NO_CANCEL_OPTION );
    if ( choice == JOptionPane.CANCEL_OPTION )
    {
      keystorelabel.setText( "" );
      aliaslabel.setText( "" );
      return;
    }

    String pass = null;
    if ( choice == JOptionPane.NO_OPTION )
    {
      pass = JOptionPane.showInputDialog(rootPane,"Enter the password for unlocking the selected key store.");
      if ( pass != null && pass.trim().length() == 0 )
      {
        keystorelabel.setText( "" );
        aliaslabel.setText( "" );
        return;
      }
    }
    
    try
    {
      if ( pass != null )
        personalkeystorepasshandler = new PasswordPasswordHandler( pass.toCharArray() );
      else
        personalkeystorepasshandler = new WindowsPasswordHandler();
      personalkeystorefile = file;
    }
    catch ( Exception e )
    {
      alias = null;
      euser = null;
      personalkeystorefile = null;
      keystorelabel.setText( "" );
      aliaslabel.setText( "" );
      e.printStackTrace();
      JOptionPane.showMessageDialog( rootPane, "A problem occured attempting to open that keyring file." );
    }
    
  }//GEN-LAST:event_openkeyringmenuitemActionPerformed

  private void openmenuitemActionPerformed(java.awt.event.ActionEvent evt)//GEN-FIRST:event_openmenuitemActionPerformed
  {//GEN-HEADEREND:event_openmenuitemActionPerformed

    if ( euser == null || teamtrust == null )
    {
      JOptionPane.showMessageDialog( rootPane, "You need to open a personal keystore and a team keystore before opening a data file." );
      return;
    }

    JFileChooser fc = new JFileChooser();
    fc.setCurrentDirectory( new File(".") );
    int result = fc.showOpenDialog( this );
    if ( result != JFileChooser.APPROVE_OPTION )
      return;
    
    File file = fc.getSelectedFile();
    if ( !file.isFile() )
    {
      JOptionPane.showMessageDialog( rootPane, "You need to select a file, not a folder." );
      return;
    }

    try
    {
      if ( compfile != null )
        compfile.close();
      datastorelabel.setText(file.getAbsolutePath());
      compfile = new EncryptedCompositeFile( file, false, true );
      compfile.setUser( euser );

      ArrayList<String> list = new ArrayList<>();
      for ( String name : compfile.getComponentNames() )
      {
        if ( !name.startsWith(".encryption") )
          list.add(name);
      }
      list.sort( String.CASE_INSENSITIVE_ORDER );

      listmodel.clear();
      for ( String name : list )
        listmodel.addElement(name);
    }
    catch ( Exception e )
    {
      compfile = null;
      e.printStackTrace();
      JOptionPane.showMessageDialog( rootPane, "A problem occured attempting to open that keyring file." );
    }
    
    
  }//GEN-LAST:event_openmenuitemActionPerformed

  private void entrylistValueChanged(javax.swing.event.ListSelectionEvent evt)//GEN-FIRST:event_entrylistValueChanged
  {//GEN-HEADEREND:event_entrylistValueChanged
    if ( evt.getValueIsAdjusting() )
      return;
    
    String value = entrylist.getSelectedValue();
    System.out.println( "Entry changed " + value );
    if ( compfile == null )
      value = null;
    
    contenttextarea.setText("");
    if ( value == null )
      return;
    
    StringBuilder builder = new StringBuilder();
    InputStreamReader reader=null;
    try
    {
      int c;
      reader = new InputStreamReader( compfile.getDecryptingInputStream(value), "UTF-8" );
      while ( (c = reader.read()) >= 0 )
      {
        builder.append((char)c);
      }
    }
    catch (IOException ex)
    {
      Logger.getLogger(EncryptedCompositeFileViewer.class.getName()).log(Level.SEVERE, null, ex);
      JOptionPane.showMessageDialog( rootPane, "Technical problem attempting to read encrypted entry: " + ex.getMessage() );
    }
    finally
    {
      try
      {
        reader.close();
      }
      catch (Exception ex)
      {
        JOptionPane.showMessageDialog( rootPane, "Technical problem attempting to read to end of encrypted entry: " + ex.getMessage() );
        Logger.getLogger(EncryptedCompositeFileViewer.class.getName()).log(Level.SEVERE, null, ex);
      }
    }
    contenttextarea.append( builder.toString() );
    
  }//GEN-LAST:event_entrylistValueChanged

  private void extractentrymenuitemActionPerformed(java.awt.event.ActionEvent evt)//GEN-FIRST:event_extractentrymenuitemActionPerformed
  {//GEN-HEADEREND:event_extractentrymenuitemActionPerformed
    String value = entrylist.getSelectedValue();
    if ( value == null )
    {
      JOptionPane.showMessageDialog(rootPane, "You need to select an entry in an open file first.");
      return;      
    }
    
    JFileChooser fc = new JFileChooser();
    fc.setCurrentDirectory( new File(".") );
    fc.setDialogTitle("Select Destination Directory");
    fc.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
    int result = fc.showOpenDialog( this );
    if ( result != JFileChooser.APPROVE_OPTION )
      return;
    
    File destination = fc.getSelectedFile();
    if ( destination == null )
      return;
    if ( !destination.isDirectory() )
    {
      JOptionPane.showMessageDialog(rootPane, "The selection is not a directory.");
      return;
    }

    File file = new File( value );
    File outfile = new File( destination, file.getName() );
    if ( outfile.exists() )
    {
      if ( JOptionPane.showConfirmDialog(rootPane, "Destination file exists already. Overwrite?", "Overwrite", JOptionPane.OK_CANCEL_OPTION ) != JOptionPane.OK_OPTION )
        return;
    }
    
    try ( 
            InputStream in = compfile.getDecryptingInputStream(value);
            OutputStream out = new FileOutputStream( outfile );
        )
    {
      Streams.pipeAll(in, out);
    }
    catch (IOException ex)
    {
      Logger.getLogger(EncryptedCompositeFileViewer.class.getName()).log(Level.SEVERE, null, ex);
      JOptionPane.showMessageDialog( rootPane, "Technical problem attempting to read encrypted entry into unencrypted file: " + ex.getMessage() );
    }

    
  }//GEN-LAST:event_extractentrymenuitemActionPerformed

  private void openteammenutiemActionPerformed(java.awt.event.ActionEvent evt)//GEN-FIRST:event_openteammenutiemActionPerformed
  {//GEN-HEADEREND:event_openteammenutiemActionPerformed
    
    
    JFileChooser fc = new JFileChooser();
    fc.setCurrentDirectory( new File(".") );
    int result = fc.showOpenDialog( rootPane );
    if ( result != JFileChooser.APPROVE_OPTION )
      return;
    
    File teamkeystorefile = fc.getSelectedFile();
    if ( !teamkeystorefile.isFile() )
    {
      JOptionPane.showMessageDialog( rootPane, "You need to select a file, not a folder." );
      return;
    }
    
    teamlabel.setText( teamkeystorefile.getAbsolutePath() );
    
    try
    {
      EncryptedCompositeFileUser personaleu = new EncryptedCompositeFileUser( personalkeystorepasshandler );
      CompositeFileKeyStore personalkeystore = new CompositeFileKeyStore( personalkeystorefile );
      personalkeystore.setUser( personaleu );
      CompositeFileKeyFinder personalkeyfinder = new CompositeFileKeyFinder( personalkeystore, alias, alias );
      personalkeyfinder.init();

      teamtrust = new TeamTrust( alias, personalkeystore, personalkeyfinder, teamkeystorefile );
      euser = new EncryptedCompositeFileUser( teamtrust, teamtrust );
    }
    catch ( Exception e )
    {
      teamtrust = null;
      euser = null;
      teamlabel.setText( "" );
      e.printStackTrace();
      JOptionPane.showMessageDialog( rootPane, "A problem occured attempting to open that keyring file." );
    }
    
    
    
  }//GEN-LAST:event_openteammenutiemActionPerformed

  private void exitmenuitemActionPerformed(java.awt.event.ActionEvent evt)//GEN-FIRST:event_exitmenuitemActionPerformed
  {//GEN-HEADEREND:event_exitmenuitemActionPerformed
    setVisible( false );
    dispose();
  }//GEN-LAST:event_exitmenuitemActionPerformed

  /**
   * @param args the command line arguments
   */
  public static void main(String args[])
  {
    /* Set the Nimbus look and feel */
    //<editor-fold defaultstate="collapsed" desc=" Look and feel setting code (optional) ">
    /* If Nimbus (introduced in Java SE 6) is not available, stay with the default look and feel.
         * For details see http://download.oracle.com/javase/tutorial/uiswing/lookandfeel/plaf.html 
     */
    try
    {
      for (javax.swing.UIManager.LookAndFeelInfo info : javax.swing.UIManager.getInstalledLookAndFeels())
      {
        if ("Nimbus".equals(info.getName()))
        {
          javax.swing.UIManager.setLookAndFeel(info.getClassName());
          break;
        }
      }
    }
    catch (ClassNotFoundException ex)
    {
      java.util.logging.Logger.getLogger(EncryptedCompositeFileViewer.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
    }
    catch (InstantiationException ex)
    {
      java.util.logging.Logger.getLogger(EncryptedCompositeFileViewer.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
    }
    catch (IllegalAccessException ex)
    {
      java.util.logging.Logger.getLogger(EncryptedCompositeFileViewer.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
    }
    catch (javax.swing.UnsupportedLookAndFeelException ex)
    {
      java.util.logging.Logger.getLogger(EncryptedCompositeFileViewer.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
    }
    //</editor-fold>
    //</editor-fold>

    Security.addProvider(new BouncyCastleProvider());    
    /* Create and display the form */
    java.awt.EventQueue.invokeLater(new Runnable()
    {
      public void run()
      {
        new EncryptedCompositeFileViewer().setVisible(true);
      }
    });
  }

  // Variables declaration - do not modify//GEN-BEGIN:variables
  private javax.swing.JLabel aliaslabel;
  private javax.swing.JTextArea contenttextarea;
  private javax.swing.JLabel datastorelabel;
  private javax.swing.JList<String> entrylist;
  private javax.swing.JMenuItem exitmenuitem;
  private javax.swing.JMenuItem extractentrymenuitem;
  private javax.swing.JLabel jLabel1;
  private javax.swing.JLabel jLabel2;
  private javax.swing.JLabel jLabel3;
  private javax.swing.JLabel jLabel4;
  private javax.swing.JMenu jMenu1;
  private javax.swing.JMenuBar jMenuBar1;
  private javax.swing.JPanel jPanel1;
  private javax.swing.JPanel jPanel2;
  private javax.swing.JPanel jPanel3;
  private javax.swing.JScrollPane jScrollPane1;
  private javax.swing.JScrollPane jScrollPane2;
  private javax.swing.JPopupMenu.Separator jSeparator1;
  private javax.swing.JSplitPane jSplitPane1;
  private javax.swing.JLabel keystorelabel;
  private javax.swing.JMenuItem openkeyringmenuitem;
  private javax.swing.JMenuItem openmenuitem;
  private javax.swing.JMenuItem openteammenutiem;
  private javax.swing.JLabel teamlabel;
  // End of variables declaration//GEN-END:variables
}
