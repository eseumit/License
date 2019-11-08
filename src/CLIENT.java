import javax.crypto.Cipher;
import java.io.*;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileStore;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.Key;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.X509EncodedKeySpec;

public class CLIENT {
    public static void main(String[] args) throws Exception {
        System.out.println("Client started...");
        if (CheckFile()) {
            System.out.println("File exists");
        } else {
            //System.out.println("File not exists");
            String input = readStringFromFile("input.txt");
            //System.out.println(input);

            assert input != null;
            String username = input.split(" ")[0].trim();
            String serial_number = input.split(" ")[1].trim();

            String macAddress = getSystemMac();
            String diskID = "-633475686";
            String motherboardID = "Standard";
            System.out.println("My MAC: " + macAddress);
            System.out.println("My DiskID: " + diskID);
            System.out.println("My Motherboard ID: " + motherboardID);
            Key publicKey = readFile("keys/public.key");
            String plainText = "";
            plainText += username +"$" + serial_number + "$" + macAddress + "$" + diskID + "$" + motherboardID;
            LICENSEMANAGER lm = new LICENSEMANAGER();
            String RSA = RSAenc(plainText, publicKey);
            String MD5 = getMd5(RSA);
            System.out.println("Client -- Raw License Text:  " + plainText);
            System.out.println("Client -- Encrypted License Text:  " + RSA);
            System.out.println("Client -- MD5fied Plain License Text:  " + MD5);
            lm.start(MD5);





            /*/for (FileStore store: FileSystems.getDefault().getFileStores()) {
                System.out.println("store " + store.getTotalSpace());
                System.out.format("%-20s vsn:%s\n", store, store.getAttribute("volume:vsn"));
                System.out.println(store.getAttribute("volume:vsn"));
            }
            String motherBoard_SerialNumber = getSystemMotherBoard_SerialNumber();
            System.out.println("MotherBoard Serial Number : "+motherBoard_SerialNumber);/*/

            /*/for (FileStore store: FileSystems.getDefault().getFileStores()) {
                System.out.format("%-20s vsn:%s\n", store, store.getAttribute("volume:vsn"));
                System.out.println(store.getAttribute("volume:vsn"));
            }/*/
        }

    }

    private static String RSAenc(String plainText, Key test) throws Exception {
        Cipher encryptCipher = Cipher.getInstance("RSA");
        encryptCipher.init(Cipher.ENCRYPT_MODE, test);

        byte[] cipherText = encryptCipher.doFinal(plainText.getBytes("UTF-8"));
        String str = new String(cipherText,0,cipherText.length, StandardCharsets.UTF_8);
        return str;
    }

    private static Key readFile(String filename) throws Exception {

        byte[] keyBytes = Files.readAllBytes(Paths.get(filename));

        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePublic(spec);
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

    public static String getSystemMotherBoard_SerialNumber(){
        try{
            String OSName=  System.getProperty("os.name");
            if(OSName.contains("Windows")){
                return (getWindowsMotherboard_SerialNumber());
            }
            else{
                return (GetLinuxMotherBoard_serialNumber());
            }
        }
        catch(Exception E){
            System.err.println("System MotherBoard Exp : "+E.getMessage());
            return null;
        }
    }

    private static String getSystemMac(){
        try{
            String OSName=  System.getProperty("os.name");
            if(OSName.contains("Windows")){
                return (getMAC4Windows());
            }
            else{
                String mac=getMAC4Linux("eth0");
                if(mac==null){
                    mac=getMAC4Linux("eth1");
                    if(mac==null){
                        mac=getMAC4Linux("eth2");
                        if(mac==null){
                            mac=getMAC4Linux("wlp3s0");
                        }
                    }
                }
                return mac;
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

    private static String getWindowsMotherboard_SerialNumber() {
        String result = "";
        try {
            File file = File.createTempFile("realhowto",".vbs");
            file.deleteOnExit();
            FileWriter fw = new java.io.FileWriter(file);

            String vbs =
                    "Set objWMIService = GetObject(\"winmgmts:\\\\.\\root\\cimv2\")\n"
                            + "Set colItems = objWMIService.ExecQuery _ \n"
                            + "   (\"Select * from Win32_BaseBoard\") \n"
                            + "For Each objItem in colItems \n"
                            + "    Wscript.Echo objItem.SerialNumber \n"
                            + "    exit for  ' do the first cpu only! \n"
                            + "Next \n";

            fw.write(vbs);
            fw.close();

            Process p = Runtime.getRuntime().exec("cscript //NoLogo " + file.getPath());
            BufferedReader input = new BufferedReader(new InputStreamReader(p.getInputStream()));
            String line;
            while ((line = input.readLine()) != null) {
                result += line;
            }
            input.close();
        }
        catch(Exception E){
            System.err.println("Windows MotherBoard Exp : "+E.getMessage());
        }
        return result.trim();
    }

    private static String GetLinuxMotherBoard_serialNumber() {
        String command = "dmidecode -s baseboard-serial-number";
        String sNum = null;
        try {
            Process SerNumProcess = Runtime.getRuntime().exec(command);
            BufferedReader sNumReader = new BufferedReader(new InputStreamReader(SerNumProcess.getInputStream()));
            sNum = sNumReader.readLine().trim();
            SerNumProcess.waitFor();
            sNumReader.close();
        }
        catch (Exception ex) {
            System.err.println("Linux Motherboard Exp : "+ex.getMessage());
            sNum =null;
        }
        return sNum;
    }

    private static String getMAC4Linux(String name){
        try {
            NetworkInterface network = NetworkInterface.getByName(name);
            byte[] mac = network.getHardwareAddress();
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < mac.length; i++){
                sb.append(String.format("%02X%s", mac[i], (i < mac.length - 1) ? "-" : ""));
            }
            return (sb.toString());
        }
        catch (Exception E) {
            return null;
        }
    }

    private static boolean CheckFile() {
       return new File("license.txt").exists();
    }

    private static String readStringFromFile(String fileName) throws    FileNotFoundException {
        BufferedReader reader;
        try {
            reader = new BufferedReader(new FileReader(fileName));
            return reader.readLine();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }
}
