import java.io.*;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.nio.file.FileStore;
import java.nio.file.FileSystems;

public class CLIENT {
    public static void main(String[] args) throws IOException, InterruptedException {
        System.out.println("Client started...");
        if (CheckFile("licence.txt")) {
            System.out.println("File exists");
        } else {
            System.out.println("File not exists");
            String input = readStringFromFile("input.txt");
            //System.out.println(input);
            assert input != null;
            String username = input.split(" ")[0].trim();
            String serial_number = input.split(" ")[1].trim();
            System.out.println(username);
            System.out.println(serial_number);
            String macAddress = getSystemMac();
            System.out.println("System Mac Address : "+macAddress);
            /*/String motherBoard_SerialNumber = getSystemMotherBoard_SerialNumber();
            System.out.println("MotherBoard Serial Number : "+motherBoard_SerialNumber);/*/

            /*/for (FileStore store: FileSystems.getDefault().getFileStores()) {
                System.out.format("%-20s vsn:%s\n", store, store.getAttribute("volume:vsn"));
                System.out.println(store.getAttribute("volume:vsn"));
            }/*/
        }

    }

    public static String getSystemMac(){
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
        }
        catch(Exception E){
            System.err.println("System Mac Exp : "+E.getMessage());
            return null;
        }
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
            System.err.println("System Linux MAC Exp : "+E.getMessage());
            return null;
        }
    }
    public static String getSystemMotherBoard_SerialNumber() throws IOException, InterruptedException {
		/*String result = "";
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
	}*/
        ProcessBuilder pb = new ProcessBuilder("wmic", "baseboard",
                "get", "serialnumber");
        Process process = pb.start();
        process.waitFor();
        String serialNumber = "";
        try (BufferedReader br = new BufferedReader(new InputStreamReader(
                process.getInputStream()))) {
            for (String line = br.readLine(); line != null; line = br.readLine()) {
                System.out.println(line);
                if (line.length() < 1 || line.startsWith("SerialNumber")) {

                    continue;
                }
                serialNumber = line;
                break;
            }
        }
        return serialNumber;
    }


    public static boolean CheckFile(String path)
    {
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
