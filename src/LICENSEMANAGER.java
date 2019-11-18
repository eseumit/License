import javax.crypto.Cipher;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

class LICENSEMANAGER {

    /**
     * Constructor function for license manager.
     * It use display message.
     */


    /**
     * This function performs the operations of the license manager.
     * @return signed value.
     */
    public String start(byte[] data) throws Exception {
        PublicKey publicKey = getPublic();
        PrivateKey privateKey = getPrivate();

        System.out.println("Server -- Server is being requested...");
        System.out.println("Server -- Incoming Encrypted Text:  " + new String(data,StandardCharsets.UTF_8));

        String decrypted = RSAdec(data, privateKey);
        String MD5 = getMd5(decrypted);

        System.out.println("Server -- Decrypted Text:  " + decrypted);
        System.out.println("Server -- MD5fied Plain License Text:  " + MD5);

        String MD5_sign = sign(MD5, privateKey);
        System.out.println("Server -- Digital Signature:  " + MD5_sign);

        return MD5_sign;
    }

    /**
     * It signs with "SHA256withRSA" algorithm.
     */
    private static String sign(String plainText, PrivateKey privateKey) throws Exception {
        Signature privateSignature = Signature.getInstance("SHA256withRSA");
        privateSignature.initSign(privateKey);
        privateSignature.update(plainText.getBytes(StandardCharsets.UTF_8));

        byte[] signature = privateSignature.sign();

        return Base64.getEncoder().encodeToString(signature);
    }

    /**
     * This function decrypt the plain text with the private key.
     * @return decrypted value.
     */
    private static String RSAdec(byte[] plainText, Key privateKey) throws Exception {
        Cipher encryptCipher = Cipher.getInstance("RSA");
        encryptCipher.init(Cipher.DECRYPT_MODE, privateKey);

        byte[] cipherText = encryptCipher.doFinal(plainText);
        return new String(cipherText,0,cipherText.length, StandardCharsets.UTF_8);
    }
    /**
     * It returns MD5 value of input.
     * @return hashtext.
     */
    private static String getMd5(String input) {
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] messageDigest = md.digest(input.getBytes());
            BigInteger no = new BigInteger(1, messageDigest);
            String hashtext = no.toString(16);
            while (hashtext.length() < 32) {
                hashtext = "0" + hashtext;
            }
            return hashtext;
        }
        catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * @return privateKey.
     */
    private static PrivateKey getPrivate() throws Exception {

        byte[] keyBytes = Files.readAllBytes(Paths.get("keys/private.key"));

        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePrivate(spec);
    }

    /**
     * @return publicKey.
     */
    private static PublicKey getPublic() throws Exception {

        byte[] keyBytes = Files.readAllBytes(Paths.get("keys/public.key"));

        X509EncodedKeySpec spec =
                new X509EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePublic(spec);
    }
}
