/*
 * Copyright 2019 jon.
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
package org.quipto.compositefile.demo;

import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import static org.quipto.compositefile.demo.DemoUtils.ALICE;
import static org.quipto.compositefile.demo.DemoUtils.BOB;
import static org.quipto.compositefile.demo.DemoUtils.CHARLIE;
import org.quipto.passwords.PasswordPasswordHandler;

/**
 * One user certifies the keys of other users.
 */
public class Demo11AliceCertifyBobCharlie
{
  static final DemoUtils.DemoUser[] subjectdemousers = { BOB, CHARLIE };
  static final boolean[] addtoteam = { true, true };
  static final boolean[] controller = { true, false };
  static final boolean[] isparent = { false, false };
  
  /**
   * Run the demo.
   * @param args No arguments used.
   * @throws Exception 
   */
  public static void main(
          String[] args)
          throws Exception
  {
    Security.addProvider(new BouncyCastleProvider());        
    PasswordPasswordHandler passhandler = new PasswordPasswordHandler(  ALICE.password );
    SignKeys.signKeysAndImport( ALICE, passhandler, true, subjectdemousers, addtoteam, controller, isparent );
  }
}
