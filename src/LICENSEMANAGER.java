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

    LICENSEMANAGER() {
        System.out.println("License Manager service started...");

    }

    public String start(byte[] data) throws Exception {
        PublicKey publicKey = getPublic();
        PrivateKey privateKey = getPrivate();
        System.out.println("Server -- Server is being requested...");
        //String  str_data = new String(data,0,data.length, StandardCharsets.UTF_8);
        //System.out.println("Server -- Incoming Encrypted Text: " + str_data);
        System.out.println("Server -- Incoming Encrypted Text: " + new String(data));
        String decrypted = RSAdec(data, privateKey);
        String MD5 = getMd5(decrypted);
        System.out.println("Server -- Decrypted Text: " + decrypted);
        System.out.println("Server -- MD5fied Plain License Text: " + MD5);

        //System.out.println(decrypted);
        //System.out.println(MD5);

        String MD5_sign = sign(MD5, privateKey);
        System.out.println("Server -- Digital Signature: " + MD5_sign);

        //System.out.println(MD5_sign);
        return MD5_sign;
    }

    private static String sign(String plainText, PrivateKey privateKey) throws Exception {
        Signature privateSignature = Signature.getInstance("SHA256withRSA");
        privateSignature.initSign(privateKey);
        privateSignature.update(plainText.getBytes("UTF-8"));

        byte[] signature = privateSignature.sign();

        return Base64.getEncoder().encodeToString(signature);
    }

    private static String RSAdec(byte[] plainText, Key privateKey) throws Exception {
        Cipher encryptCipher = Cipher.getInstance("RSA");
        encryptCipher.init(Cipher.DECRYPT_MODE, privateKey);

        byte[] cipherText = encryptCipher.doFinal(plainText);
        return new String(cipherText,0,cipherText.length, StandardCharsets.UTF_8);
    }

    private static String getMd5(String input) {
        try {

            // Static getInstance method is called with hashing MD5
            MessageDigest md = MessageDigest.getInstance("MD5");

            // digest() method is called to calculate message digest
            //  of an input digest() return array of byte
            byte[] messageDigest = md.digest(input.getBytes());

            // Convert byte array into signum representation
            BigInteger no = new BigInteger(1, messageDigest);

            // Convert message digest into hex value
            String hashtext = no.toString(16);
            while (hashtext.length() < 32) {
                hashtext = "0" + hashtext;
            }
            return hashtext;
        }

        // For specifying wrong message digest algorithms
        catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    private static PrivateKey getPrivate()throws Exception {

        byte[] keyBytes = Files.readAllBytes(Paths.get("keys/private.key"));

        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePrivate(spec);
    }

    private static PublicKey getPublic() throws Exception {

        byte[] keyBytes = Files.readAllBytes(Paths.get("keys/public.key"));

        X509EncodedKeySpec spec =
                new X509EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePublic(spec);
    }


}
