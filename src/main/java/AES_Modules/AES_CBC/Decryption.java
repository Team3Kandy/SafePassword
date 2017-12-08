/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package AES_Modules.AES_CBC;

import java.nio.ByteBuffer;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import com.sun.xml.internal.messaging.saaj.util.Base64;
import sun.misc.BASE64Decoder;

/**
 *
 * @author Rahmican
 */
public class Decryption {
  @SuppressWarnings("static-access")
  public String decrypt(String encryptedText,String password) throws Exception {
    Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
    
    // Salt ve Vi 'yi ayır
    ByteBuffer buffer = ByteBuffer.wrap(new BASE64Decoder().decodeBuffer(encryptedText));
    byte[] encryptedTextBytes = new byte[buffer.capacity()];

    buffer.get(encryptedTextBytes);

   // Anahtarı türet
    
    SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
    PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), encryptedTextBytes, 65556, 256);
    SecretKey secretKey = factory.generateSecret(spec);
    SecretKeySpec secret = new SecretKeySpec(secretKey.getEncoded(), "AES");
    cipher.init(Cipher.DECRYPT_MODE, secret);
    byte[] decryptedTextBytes = null;
    
    try {
      decryptedTextBytes = cipher.doFinal(encryptedTextBytes);
    } catch (IllegalBlockSizeException e) {
        e.printStackTrace();
    } catch (BadPaddingException e) {
        e.printStackTrace();
    }
   
    return new String(decryptedTextBytes);
  }
}