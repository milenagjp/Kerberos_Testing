package org.example;/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;


/**
 *
 * @author Milena
 */
public class Kerberos {

    public static void main(String[] args) throws BadPaddingException, UnsupportedEncodingException, IllegalBlockSizeException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, NoSuchProviderException {
        // TODO code application logic here

        KDC kdc = new KDC();

        String encryptedA = kdc.encryptYA(kdc.getUser1(), kdc.getUser2());
        System.out.println("Encryption with keyA:" + "\n" + encryptedA);

        String encryptedB=kdc.encryptYB(kdc.getUser1(), kdc.getUser2());
        System.out.println("Encryption with keyB:" + "\n" + encryptedB);

        String decrypted = kdc.decryptYA(encryptedA, kdc.getUser1());
        System.out.println("Decryption with keyA:" + "\n" +decrypted);
        // System.out.println(Alice.toString());
        //System.out.println(Bob.toString());
        String checkNonce = Integer.toString(kdc.getUser1().getNonce());
        String id = kdc.getUser2().getId();

        if ((decrypted.contains(checkNonce)) && (decrypted.contains(id))) {
            String encryptedAB=kdc.encryptYAB(kdc.getUser1());
            System.out.println("Encryption with session key:" + "\n" +encryptedAB);
            String decryptedAB=kdc.decryptYAB(encryptedAB);
            System.out.println("Decryption with session key:" + "\n" +decryptedAB);
            String decryptB=kdc.decryptYB(encryptedB, kdc.getUser2());
            System.out.println("Decryption with keyB:" + "\n"+decryptB);
            if(decryptedAB.contains(kdc.getUser1().getId())){
                String messageX = "Zdravo Alice kako si?";
                String encryptX =  kdc.encryptX(messageX);
                System.out.println("Encrypted message:" + "\n" +encryptX);
                String decryptY=kdc.decryptY(encryptX);
                System.out.println("Decrypted message:" + "\n" +decryptY);
            }
        } else {
            System.out.println("Authentication failed!!!");
        }

    }

}
