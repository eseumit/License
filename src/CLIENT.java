import javax.crypto.Cipher;
import java.io.*;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class CLIENT {
    public static void main(String[] args) throws Exception {
        System.out.println("Client started...");
        if (CheckFile()) {
            String plainText = plainText_create();
            String MD5_text = readStringFromFile();
            String MD5_Client = getMd5(plainText);
            PublicKey publicKey = getPublic();
            boolean result = verify(MD5_Client, MD5_text, publicKey);
            if (result) {
                System.out.println("Client -- Succeed. The license is correct.");
            } else{
                System.out.println("Client -- The license file has been broken!!");
                System.out.println("Client -- License re-execute...");
                licenseProcess();
            }
        } else {
            licenseProcess();
        }
    }

    private static void licenseProcess() throws Exception {
        String plainText = plainText_create();
        PublicKey publicKey = getPublic();
        LICENSEMANAGER lm = new LICENSEMANAGER();
        byte[] RSA = RSAenc(plainText, publicKey);
        String MD5_Client = getMd5(plainText);
        System.out.println("Client -- Raw License Text:  " + plainText);
        System.out.println("Client -- Encrypted License Text:  " + new String(RSA,"UTF-8"));
        System.out.println("Client -- MD5fied Plain License Text:  " + MD5_Client);
        String MD5_sign_Server = lm.start(RSA);

        boolean result = verify(MD5_Client, MD5_sign_Server, publicKey);
        if(result){
            System.out.println("Client -- Succeed. The license file content is secured and signed by the server.");
            writeFile(MD5_sign_Server.getBytes());
        }
        else
            System.out.println("Client -- Failed. The license file content is not secured and not signed by the server.");
    }

    private static String plainText_create() throws Exception {
        String username = "Umit";
        String serial_number = "0H6U-23BJ-YR84";
        String macAddress = getSystemMac();
        String diskID = "-633475686";  // DiskkID windows için ayarlanacak.
        String motherboardID = "Standard";
        System.out.println("My MAC: " + macAddress);
        System.out.println("My DiskID: " + diskID);
        System.out.println("My Motherboard ID: " + motherboardID);
        return username +"$" + serial_number + "$" + macAddress + "$" + diskID + "$" + motherboardID;
    }

    private static void writeFile(byte[] data) {
        try {
            FileOutputStream out = new FileOutputStream("keys/license.txt");
            out.write(data);
            out.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static boolean verify(String plainText, String signature, PublicKey publicKey) throws Exception {
        Signature publicSignature = Signature.getInstance("SHA256withRSA");
        publicSignature.initVerify(publicKey);
        publicSignature.update(plainText.getBytes("UTF-8"));

        byte[] signatureBytes = Base64.getDecoder().decode(signature);

        return publicSignature.verify(signatureBytes);
    }

    private static byte[] RSAenc(String plainText, Key test) throws Exception {
        Cipher encryptCipher = Cipher.getInstance("RSA");
        encryptCipher.init(Cipher.ENCRYPT_MODE, test);

        //String str = new String(cipherText,0,cipherText.length, StandardCharsets.UTF_8);
        return encryptCipher.doFinal(plainText.getBytes("UTF-8"));
    }

    private static PublicKey getPublic() throws Exception {

        byte[] keyBytes = Files.readAllBytes(Paths.get("keys/public.key"));

        X509EncodedKeySpec spec =
                new X509EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePublic(spec);
    }

    private static String getSystemMac(){
        try{
            String OSName=  System.getProperty("os.name");
            if(OSName.contains("Windows")){
                return (getMAC4Windows());
            }
            else{
                System.err.println("Operating System is not Windows.");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    private static String getMAC4Windows(){
        try{
            InetAddress      addr     =InetAddress.getLocalHost();
            NetworkInterface network  =NetworkInterface.getByInetAddress(addr);

            byte[] mac = network.getHardwareAddress();

            StringBuilder sb = new StringBuilder();
            for(int i=0;i<mac.length;i++){
                sb.append(String.format("%02X%s", mac[i], (i < mac.length - 1) ? "-" : ""));
            }

            return sb.toString();
        }
        catch(Exception E){
            System.err.println("System Windows MAC Exp : "+E.getMessage());
            return null;
        }
    }



    private static boolean CheckFile() {
        return new File("license.txt").exists();
    }

    private static String readStringFromFile() throws FileNotFoundException {
        BufferedReader reader;
        try {
            reader = new BufferedReader(new FileReader("license.txt"));
            return reader.readLine();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
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
}
