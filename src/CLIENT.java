import javax.crypto.Cipher;
import java.io.*;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/**
 * @author Umit ESE - 21484502
 * @author Derya ERSOY - 21327972
 *
 */
public class CLIENT {
    public static void main(String[] args) throws Exception {
        System.out.println("Client started...");
        if (new File("license.txt").exists()) {
            String plainText = plainText_create();
            String MD5_text = readStringFromFile();
            String MD5_Client = getMd5(plainText);
            PublicKey publicKey = getPublic();
            boolean result = verify(MD5_Client, MD5_text, publicKey);
            if (result) {
                System.out.println("Client -- Succeed. The license is correct.");
            } else{
                System.err.println("Client -- The license file has been broken!!");
                System.err.println("Client -- License re-execute...");
                licenseProcess();
            }
        } else {
            licenseProcess();
        }
    }

    /**
     * This function works in two cases. First, if license.txt is not exists.
     * Second, if license.txt is exists but it's broken.
     */
    private static void licenseProcess() throws Exception {
        String plainText = plainText_create();
        PublicKey publicKey = getPublic();
        LICENSEMANAGER lm = new LICENSEMANAGER();
        byte[] RSA = RSAenc(plainText, publicKey);
        String MD5_Client = getMd5(plainText);
        System.out.println("Client -- Raw License Text:  " + plainText);
        System.out.println("Client -- Encrypted License Text:  " + new String(RSA, StandardCharsets.UTF_8));
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

    /**
     * Username and serial_number are constant
     * MAC address of computer is taken from the "getSystemMac" function.
     * DiskID is taken from "getDiskID" function.
     * @return plainText with username, serial_number, mac address, disk id, motherboard id.
     */
    private static String plainText_create() throws Exception {
        String username = "Umit";
        String serial_number = "0H6U-23BJ-YR84";
        String macAddress = getSystemMac();
        String diskID = "-" + getDiskID();
        //String diskID = "-633475686";  // DiskkID windows için ayarlanacak.
        String motherboardID = "Standard";
        System.out.println("My MAC: " + macAddress);
        System.out.println("My DiskID: " + diskID);
        System.out.println("My Motherboard ID: " + motherboardID);
        return username +"$" + serial_number + "$" + macAddress + "$" + diskID + "$" + motherboardID;
    }

    /**
     * Writes the data values to the license.txt file.
     */
    private static void writeFile(byte[] data) {
        try {
            FileOutputStream out = new FileOutputStream("license.txt");
            out.write(data);
            out.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    /**
     * Verifies the signed value and the value on the client side.
     * @return If signature is match functions returns true, is not match functions returns false.
     */
    private static boolean verify(String plainText, String signature, PublicKey publicKey) throws Exception {
        Signature publicSignature = Signature.getInstance("SHA256withRSA");
        publicSignature.initVerify(publicKey);
        publicSignature.update(plainText.getBytes("UTF-8"));
        try {
            byte[] signatureBytes = Base64.getDecoder().decode(signature);
            return publicSignature.verify(signatureBytes);
        }
        catch (IllegalArgumentException e){
            System.err.println("Input byte array has wrong 4-byte ending unit");
            return false;
        }




    }

    /**
     * This function encrypt the plain text with the public key.
     * @return encrypted value.
     */
    private static byte[] RSAenc(String plainText, Key publicKey) throws Exception {
        Cipher encryptCipher = Cipher.getInstance("RSA");
        encryptCipher.init(Cipher.ENCRYPT_MODE, publicKey);

        //String str = new String(cipherText,0,cipherText.length, StandardCharsets.UTF_8);
        return encryptCipher.doFinal(plainText.getBytes("UTF-8"));
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

    /**
     * If your system is different from Windows, then functions gives error message.
     * First we gave MAC Address for Ubuntu Operating System, but then we changed code blocks.
     * @return System MAC Address
     */
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

    /**
     * It works if the operating system is windows.
     */
    private static String getMAC4Windows(){
        try{
            InetAddress addr = InetAddress.getLocalHost();
            NetworkInterface network = NetworkInterface.getByInetAddress(addr);

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

    /**
     * Returns the id according to the disk name given as string.
     * Assuming that each computer will have a disk named "C", the disk id "C" is used.
     */
    private static String getDiskID() {
        StringBuilder result = new StringBuilder();
        try {
            File file = File.createTempFile("realhowto",".vbs");
            file.deleteOnExit();
            FileWriter fw = new java.io.FileWriter(file);

            String vbs = "Set objFSO = CreateObject(\"Scripting.FileSystemObject\")\n"
                    +"Set colDrives = objFSO.Drives\n"
                    +"Set objDrive = colDrives.item(\"" + "C" + "\")\n"
                    +"Wscript.Echo objDrive.SerialNumber";  // see note
            fw.write(vbs);
            fw.close();
            Process p = Runtime.getRuntime().exec("cscript //NoLogo " + file.getPath());
            BufferedReader input =
                    new BufferedReader
                            (new InputStreamReader(p.getInputStream()));
            String line;
            while ((line = input.readLine()) != null) {
                result.append(line);
            }
            input.close();
        }
        catch(Exception e){
            e.printStackTrace();
        }
        return result.toString().trim();
    }

    /**
     * It reads string from license.txt.
     */
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
}
