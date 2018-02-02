



import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.Enumeration;
import java.util.Properties;

/**
 * 2011 March - G.Larson This class may not function in WAE. It was used in VSP. It contains IBM JRE or WebSphere
 * interactions. 2012 March - H.Semerci This class modified to function in WAE with JDK. It was used in VSP with IBMJDK.
 */
public final class KeyManager {

    /** Logger */
    // private static final String JCE_PROVIDER = "SUN";
    private static final String KEYSTORE_FILENAME = "wae.keystore";
    private static final String KEYSTORE_TYPE = "jceks";

    private KeyStoreProps iKeyStoreProps = null;
    private KeyStore iKeyStore = null;

    public KeyManager() {

        // decode and load key store properties
        iKeyStoreProps = new KeyStoreProps();

        // load key store
        try {
            FileInputStream lFis = new FileInputStream(KEYSTORE_FILENAME);
            iKeyStore = KeyStore.getInstance(KEYSTORE_TYPE);
            iKeyStore.load(lFis, iKeyStoreProps.getKeyStorePassphrase());
            lFis.close();
        }catch (Exception e){
            System.out.println(e.getMessage());
        }

    }

    /**
     * Generate a symmetric key !!NOT TESTED!!
     * 
     * @param pAlgorithm
     * @param pKeySize
     * @param pAlias
     * @param pPassphrase
     */
    public void BUGgenerateKey(String pAlgorithm, int pKeySize, String pAlias, char[] pPassphrase)
            {

        // existing key cannot be overwritten
        if (containsKey(pAlias)) {
            System.out.println("The key " + pAlias + " already exists.");
        }

        try {
            // init secure random number generator
            // BUG: this implementation not available in JBOSS
            // BUG: SecureRandom instances must not be generated frequently.
            SecureRandom lRng = SecureRandom.getInstance("SecureRandom"); // IBMSecureRandom
                                                                          // known
                                                                          // as
                                                                          // FIPSPRNG

            // init key generator
            KeyGenerator lKeyGenerator = KeyGenerator.getInstance(pAlgorithm);
            lKeyGenerator.init(pKeySize, lRng);

            SecretKey lSecretKey = lKeyGenerator.generateKey();
            addAndSaveSecretKey(pAlias, pPassphrase, lSecretKey);

        } catch (Exception e) {
            System.out.println("Failed to generate key" + e.toString());
        }
    }

    /**
     * Import a symmetric key from file !!NOT TESTED!!
     * 
     * @param pKeyFileName
     * @param pAlias
     * @param pPassphrase
     * @return
     */
    public void importKeyFromFile(String pKeyFileName, String pAlgorithm, String pAlias, char[] pPassphrase) {

        // existing key cannot be overwritten
        if (containsKey(pAlias)) {
            System.out.println("The key already exists.");
        }

        try {
            // construct a secretkey
            SecretKey lSecretKey = SecretKeyFactory.getInstance(pAlgorithm).generateSecret(
                    new SecretKeySpec(readRawBytes(pKeyFileName), pAlgorithm));

            // save the key in key store
            addAndSaveSecretKey(pAlias, pPassphrase, lSecretKey);
        } catch (Exception e) {
            System.out.println("Failed to import the key." + e.toString());
        }
    }
    public static byte[] readRawBytes(String pFileName) throws FileNotFoundException, IOException {

        byte[] lByteBuf = new byte[(int) new File(pFileName).length()];
        new RandomAccessFile(pFileName, "r").readFully(lByteBuf);
        return lByteBuf;

    }

    /**
     * Import a symmetric key from a hex string !!NOT TESTED!!
     * 
     * @param pKeyStr
     * @param pAlias
     * @param pPassphrase
     * @return
     */
    public void importKeyFromHexStr(String pKeyStr, String pAlgorithm, String pAlias, char[] pPassphrase) {

        // existing key cannot be overwritten
        if (containsKey(pAlias)) {
            System.out.println("The key already exists.");
        }

        try {
            // construct a secretkey
            SecretKey lSecretKey = SecretKeyFactory.getInstance(pAlgorithm).generateSecret(
                    new SecretKeySpec(hexStrToBytes(pKeyStr), pAlgorithm));

            // save the key in key store
            addAndSaveSecretKey(pAlias, pPassphrase, lSecretKey);
        } catch (Exception e) {
            System.out.println("Failed to import the key." + e.toString());
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

    /**
     * Delete a key
     * 
     * @param pAlias
     */
    public void deleteKey(String pAlias) {
        try {
            iKeyStore.deleteEntry(pAlias);
            saveKeyStore(iKeyStoreProps.getKeyStorePassphrase());

            iKeyStoreProps.deleteKeyPassphrase(pAlias);
        } catch (Exception e) {
            System.out.println(("Failed to delete the key " + pAlias + "." + e.toString()));
        }
    }

    /**
     * List all the keys in the key store
     * 
     * @return
     */
    public String listKeys() {

        StringBuffer lStrBuf = new StringBuffer("");
        try {
            lStrBuf.append(KEYSTORE_FILENAME + "\n");
            lStrBuf.append("Type: " + KEYSTORE_TYPE + "\n");
            lStrBuf.append("Size: " + iKeyStore.size() + "\n");

            Enumeration<String> lEnumAlias = iKeyStore.aliases();
            while (lEnumAlias.hasMoreElements()) {
                String lEntryAlias = lEnumAlias.nextElement();
                String lSecretKeyAlgorithm = getKey(lEntryAlias).getAlgorithm();
                lStrBuf.append(lEntryAlias + " " + lSecretKeyAlgorithm + " " + iKeyStore.getCreationDate(lEntryAlias)
                        + " " + "\n");
            }
        } catch (KeyStoreException e) {
            lStrBuf.append("Error reading keystore");
        }
        return lStrBuf.toString();
    }

    /**
     * Retrieve a key from the key store
     * 
     * @param pAlias
     * @return
     */
    public SecretKey getKey(String pAlias) {
        try {
            return (SecretKey) iKeyStore.getKey(pAlias, iKeyStoreProps.getKeyPassphrase(pAlias));
        } catch (Exception e) {
            System.out.println("SecWarn0007: Failed to load the key " + pAlias + " from symmetric key repository. "
                    + e.getMessage());
            System.out.println(("Failed to retrieve the key " + pAlias + "." +  e.toString()));
            return null;
        }
    }

    /**
     * Return true if the input keystore passphrase is correct
     * 
     * @return
     */
    public boolean authenticate(String pInputKeyStorePassphrase) {
        return new String(iKeyStoreProps.getKeyStorePassphrase()).equals(pInputKeyStorePassphrase);
    }

    /**
     * Check if the key store contains a key with the alias
     * 
     * @param pKeyAlias
     * @return
     */
    public boolean containsKey(String pKeyAlias) {
        try {
            return iKeyStore.containsAlias(pKeyAlias);
        } catch (KeyStoreException e) {
            System.out.println(("Failed to detect the key's existance." + e.toString()));
            return false;
        }
    }

    /**
     * Create an encoded keystore properties file from a clear file
     */
    public static void createEncodedKeyStorePropsFile() {

        String lPropFileName = KeyStoreProps.KEYSTORE_PROP_FILE;

        try {
            // read the clear property file
            FileInputStream lFis = new FileInputStream(lPropFileName);
            Properties lKeyStoreProps = new Properties();
            lKeyStoreProps.load(lFis);
            lFis.close();

            // if (lKeyStoreProps.getProperty(KeyStoreProps.PASS_PHRASE) ==
            // null) {
            // lKeyStoreProps.setProperty(KeyStoreProps.PASS_PHRASE,
            // "329rxn9329xr2rwDqC4sPSAFJ9JFD0D0");
            // lKeyStoreProps.setProperty("default_app_aes_128","spD7dj0nd0as32ASDFwinefrn30jsnpm");
            // lKeyStoreProps.setProperty("default_app_hmacmd5_160","rsNUXMqeun=XEN0=CU@53sd(34DGzlb09#@xcbB;");
            // lKeyStoreProps.setProperty("default_file_aes_128","spD7dj0nd0as32ASDFwinefrn30jsnpm");
            // lKeyStoreProps.setProperty("default_file_hmacmd5_160","rsNUXMqeun=XEN0=CU@53sd(34DGzlb09#@xcbB;");
            // }

            // init encoding key
            // SecretKey lEncodingKey = SecretKeyFactory.getInstance(
            // KeyStoreProps.ENCODING_ALGORITHM).generateSecret(
            // new SecretKeySpec(CryptoUtils
            // .hexStrToBytes(KeyStoreProps.ENCODING_KEY),
            // KeyStoreProps.ENCODING_ALGORITHM));
            SecretKey lEncodingKey = new SecretKeySpec(getMD5(KeyStoreProps.ENCODING_KEY),
                    KeyStoreProps.ENCODING_ALGORITHM);

            // encode the property file
            Cipher lCipher = Cipher.getInstance(KeyStoreProps.ENCODING_ALGORITHM);
            lCipher.init(Cipher.ENCRYPT_MODE, lEncodingKey);
            CipherOutputStream lCos = new CipherOutputStream(new FileOutputStream(lPropFileName), lCipher);
            lKeyStoreProps.store(lCos, lPropFileName);
            lCos.close();
        } catch (FileNotFoundException e) {
            System.out.println("SecSvr0001: Failed to read security configuration file " + lPropFileName + ". "
                    + e.getMessage());
            } catch (Exception e) {
            System.out.println("SecSvr0001: Failed to read security configuration file " + lPropFileName + ". "
                    + e.getMessage());
           }
    }

    public static byte[] getMD5(String input) {
        try {
            byte[] bytesOfMessage = input.getBytes("UTF-8");
            MessageDigest md = MessageDigest.getInstance("MD5");
            return md.digest(bytesOfMessage);
        } catch (Exception e) {
            return null;
        }
    }

    // ====================== protected/private helper methods
    // ======================
    /**
     * Add a key to the key store and save the key store
     */
    private void addAndSaveSecretKey(String pAlias, char[] pPassphrase, Key pKey) {

        try {
            iKeyStore.setKeyEntry(pAlias, pKey, pPassphrase, null); // it is
                                                                    // private
                                                                    // key, so
                                                                    // no
                                                                    // certificate
                                                                    // chain
            saveKeyStore(iKeyStoreProps.getKeyStorePassphrase());

            iKeyStoreProps.setKeyPassphrase(pAlias, pPassphrase);
        } catch (Exception e) {
            System.out.println("Failed to add and save secret key " + pAlias + e.toString());
        }
    }

    /**
     * Save the key store with the given passphrase. Therefore, it is capable of changing keystore passphrase
     * 
     * @throws KeyStoreException
     * @throws NoSuchAlgorithmException
     * @throws CertificateException
     * @throws IOException
     */
    protected void saveKeyStore(char[] pKeyStorePassphrase) {

        try {
            FileOutputStream lFos = new FileOutputStream(KEYSTORE_FILENAME);
            iKeyStore.store(lFos, pKeyStorePassphrase);
            lFos.close();
        } catch (Exception e) {
            System.out.println("Failed to save the key store." + e.toString());
        }

        iKeyStoreProps.setKeyStorePassphrase(pKeyStorePassphrase);
    }

    // ====================== private nested class ======================
    /**
     * This is a class handles secured key store information: key store location, key store passphrase, key passphrase
     */
    protected class KeyStoreProps {
        private static final String KEYSTORE_PROP_FILE = "wae_keymgmt.properties";
        private static final String ENCODING_KEY = "d308ae9f8a204cbfbabc0919abc87abd"; // generated
                                                                                       // using
                                                                                       // IBM
                                                                                       // FIPS
        private static final String ENCODING_ALGORITHM = "AES";
        public static final String PASS_PHRASE = "key_store_passphrase";

        private Properties iKeyStoreProps = null;
        private SecretKey iEncodingKey = null;

        public KeyStoreProps() {
            // init the encoding key
            try {
                // SecretKeyFactory factory =
                // SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
                // KeySpec key = new
                // SecretKeySpec(CryptoUtils.hexStrToBytes(ENCODING_KEY),ENCODING_ALGORITHM);
                // iEncodingKey = factory.generateSecret(key);
                iEncodingKey = new SecretKeySpec(getMD5(ENCODING_KEY), ENCODING_ALGORITHM);
            } catch (Exception e) {
                System.out.println("Failed to init the embedded key." + e.toString());
            }

            // load the properties
            // KeyManager.createEncodedKeyStorePropsFile();
            this.loadProps();
        }

        /**
         * Get the key store passphrase
         * 
         * @return
         */
        public char[] getKeyStorePassphrase() {
            String str = iKeyStoreProps.getProperty(PASS_PHRASE);
            return str.toCharArray();
        }

        /**
         * Get passphrase of a key
         * 
         * @param pKeyAlias
         * @return
         */
        public char[] getKeyPassphrase(String pKeyAlias) {
            char[] lRet = "".toCharArray();

            String lPassphrase = iKeyStoreProps.getProperty(pKeyAlias);
            if (lPassphrase != null) {
                lRet = lPassphrase.toCharArray();
            }

            return lRet;
        }

        /**
         * Delete key passphrase
         * 
         * @param pKeyAlias
         */
        public void deleteKeyPassphrase(String pKeyAlias) {
            iKeyStoreProps.remove(pKeyAlias);
            saveProps();
        }

        /**
         * Set keystore passphrase
         * 
         * @param pPassphrase
         */
        public void setKeyStorePassphrase(char[] pPassphrase) {
            iKeyStoreProps.setProperty(PASS_PHRASE, new String(pPassphrase));
            saveProps();
        }

        /**
         * Set passphrase of a key
         * 
         * @param pKeyAlias
         * @param pPassphrase
         */
        public void setKeyPassphrase(String pKeyAlias, char[] pPassphrase) {
            iKeyStoreProps.setProperty(pKeyAlias, new String(pPassphrase));
            saveProps();
        }

        // ========================= Private Helper Methods
        // =========================
        /**
         * Decode the file and load the properties
         */
        private void loadProps() {

            iKeyStoreProps = new Properties();
            String lPropFileName = (KeyStoreProps.KEYSTORE_PROP_FILE);
            try {
                Cipher lCipher = Cipher.getInstance(ENCODING_ALGORITHM);
                lCipher.init(Cipher.DECRYPT_MODE, iEncodingKey);
                CipherInputStream lCos = new CipherInputStream(new FileInputStream(lPropFileName), lCipher);
                iKeyStoreProps.load(lCos);
                lCos.close();

            } catch (Exception e) {
                System.out.println("SecSvr0001: Failed to read security configuration file " + lPropFileName + ". "
                        + e.getMessage());
            }
        }

        /**
         * write the properties in a file and encode it
         */
        private void saveProps() {
            try {
                String lPropFileName = (KeyStoreProps.KEYSTORE_PROP_FILE);

                Cipher lCipher = Cipher.getInstance(ENCODING_ALGORITHM);
                lCipher.init(Cipher.ENCRYPT_MODE, iEncodingKey);
                CipherOutputStream lCos = new CipherOutputStream(new FileOutputStream(lPropFileName), lCipher);
                iKeyStoreProps.store(lCos, lPropFileName);
                lCos.close();
            } catch (Exception e) {
                System.out.println("Failed to save keystore properties." + e.toString());
            }
        }
    }
}
