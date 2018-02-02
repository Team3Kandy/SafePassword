import AES_Modules.AES_CBC.*;
import sun.security.krb5.EncryptionKey;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.spec.KeySpec;
import java.util.Arrays;
import java.util.Properties;

public class SafePassword {
    private String SecretKey = "secret";
    private String MyKeystoreFileName;
    private KeyStore keyStore;

    {
        try {
            keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        } catch (KeyStoreException e) {
            System.err.println("KeyStore error");
            e.printStackTrace();
        }
    }

    private static final String ENCODING_KEY = "d308ae9f8a204cbfbabc0919abc87abd";
    private static final String KEYSTORE_FILENAME = "wae.keystore";
    private static final String KEYSTORE_TYPE = "jceks";

    public static void main2(String [] argv) throws IOException{

        generateKeyStore("asd","netas");

        KeyManager keyManager = new KeyManager();

        keyManager.importKeyFromHexStr("1785FC64DB5956AD86C6674BE742072E", "AES", "eeee", "netas".toCharArray());
        //TODO : gerçek wae.keystore yap
        keyManager.saveKeyStore("netas".toCharArray());

        String[] keys = keyManager.listKeys().split("\n");
        String[] asd = new String[keys.length - 3];

        System.arraycopy(keys, 3, asd, 0, keys.length - 3);


        for (String str :
                asd) {
            System.out.println(str.split(" ")[0]);
            System.out.println(bytesToHexStr(keyManager.getKey(str.split(" ")[0]).getEncoded()));
        }

    }

    public static void generateKeyStore(String filename,String passphrase){
        KeyStore keyStore = null;
        try {
            keyStore = KeyStore.getInstance(KEYSTORE_TYPE);
            keyStore.load(null,passphrase.toCharArray());
        //keyStore.setKeyEntry("rahmican","1785FC64DB5956AD86C6674BE742072C".getBytes(),null);
            keyStore.store(new FileOutputStream( new File(filename)),passphrase.toCharArray());
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static void main(String [] argv) throws IOException {
        KeyManager keyManager = new KeyManager();
        String[] keys = keyManager.listKeys().split("\n");
        String[] asd = new String[keys.length-3];

        System.arraycopy(keys,3,asd,0,keys.length-3);

        for (String str :
                asd) {
            System.out.println(str.split(" ")[0]);
            System.out.println(bytesToHexStr( keyManager.getKey(str.split(" ")[0]).getEncoded()));
        }
    }
    private final static char[] hexArray = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E',
            'F' };
    public static String bytesToHexStr(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        int v;
        for (int j = 0; j < bytes.length; j++) {
            v = bytes[j] & 0xFF; // & 0xff why? avoid sign extension?
            hexChars[j * 2] = hexArray[v / 16];
            hexChars[j * 2 + 1] = hexArray[v % 16];
        }
        return new String(hexChars);
    }

    public static void main1(String [] argv) {
        try {
            Cipher lCipher = Cipher.getInstance("AES");
            SecretKey iEncodingKey = null;
            Properties iKeyStoreProps = new Properties();

            byte[] bytesOfMessage = ENCODING_KEY.getBytes();
            MessageDigest md = MessageDigest.getInstance("MD5");

            iEncodingKey = new SecretKeySpec(md.digest(bytesOfMessage), "AES");
            lCipher.init(Cipher.DECRYPT_MODE, iEncodingKey);
            CipherInputStream lCos = new CipherInputStream(new FileInputStream("wae_keymgmt.properties"), lCipher);
            iKeyStoreProps.load(lCos);

            String lPassphrase = iKeyStoreProps.getProperty("key_store_passphrase");
          //  iKeyStoreProps.list(System.out);

           // System.out.println(lPassphrase);
            String aesPass = iKeyStoreProps.getProperty("default_file_aes_128");
            FileInputStream lFis = new FileInputStream(KEYSTORE_FILENAME);
            KeyStore iKeyStore = KeyStore.getInstance(KEYSTORE_TYPE);
            iKeyStore.load(lFis, lPassphrase.toCharArray());
            Key key = iKeyStore.getKey("default_file_aes_128",aesPass.toCharArray());
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(2,key);
            String encrpted = "265CC8E9A5B565CACC0FBEE4E97FB7A0";
            System.out.println(cipher.doFinal(hexStrToBytes(encrpted)));
            //System.out.println(new String(key.getEncoded()));
            lCos.close();

        } catch (Exception e) {
            System.out.println(e.getMessage());
        }
    }

    public static byte[] hexStrToBytes(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        len--; // don't trap on odd length String.
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4) + Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }
    public static void maian(String [] argv){

        if(argv[1].contains("-r") || argv[1].contains("--read")){
            //decrypt
        }
        else if (argv[1].contains("-w") || argv[1].contains("--write")){
            //encrpyt
        }
        else if (argv[1].contains("-u") ||argv[1].contains("--user")){
            // user
        }






        String encrypted,decrypted;
        String text = "hi  kl b kl ii";
        SafePassword s = new SafePassword();

        encrypted = AES.encrypt(text,"secret");
        System.out.println("Encrypted : " + encrypted);
        decrypted = AES.decrypt(encrypted,"secret");
        System.out.println("Decrypted : " + decrypted);
    }

    public String Encrypt(String text){
        try {
            return (new Encryption().encrypt(text,SecretKey));
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public String Decrypt(String text){
        try {
            return new Decryption().decrypt(text,SecretKey);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }
}
