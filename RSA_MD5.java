

	import java.io.BufferedReader;
	import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.Key;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.Scanner;

import javax.crypto.Cipher;

import java.math.BigInteger; 
import java.security.MessageDigest; 
import java.security.NoSuchAlgorithmException; 

	
	public class RSA_MD5 {

	    
	    public static void main(String[] args) throws Exception {
	    	String in = "Selman$0H6U-23BJ-YR84$0C-54-15-5B-0A-FE$-633475686$Standard";
	    	Key test = get("public.key");
	    	String result = RSAenc(in, test);
	    	System.out.println(result);
	    	String hash = getMd5(result);
	    	System.out.println(hash);
	    }
	    
	    public static String RSAenc(String plainText, Key test) throws Exception {
		    Cipher encryptCipher = Cipher.getInstance("RSA");
		    encryptCipher.init(Cipher.ENCRYPT_MODE, test);

		    byte[] cipherText = encryptCipher.doFinal(plainText.getBytes("UTF-8"));
		    String str = new String(cipherText,0,cipherText.length,StandardCharsets.UTF_8);
		    return str;
		}
	    
	      
	    public static Key get(String filename)
	    	    throws Exception {

	    	    byte[] keyBytes = Files.readAllBytes(Paths.get(filename));

	    	    X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
	    	    KeyFactory kf = KeyFactory.getInstance("RSA");
	    	    return kf.generatePublic(spec);
	    	  }
	    
	    
	    
	    
	    
	    

	      
	    // Java program to calculate MD5 hash value 
	     
	        public static String getMd5(String input) 
	        { 
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
	    
	    
	    
	/*public static String encrypt(String plainText, PublicKey publicKey) throws Exception {
	    Cipher encryptCipher = Cipher.getInstance("RSA");
	    encryptCipher.init(Cipher.ENCRYPT_MODE, publicKey);

	    byte[] cipherText = encryptCipher.doFinal(plainText.getBytes(UTF_8));

	    return Base64.getEncoder().encodeToString(cipherText);
	}*/
	    
	    
	   
	
