package org.example;/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

import com.sun.mail.util.BASE64DecoderStream;
import com.sun.mail.util.BASE64EncoderStream;

import javax.crypto.*;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.sql.Timestamp;
import java.util.Timer;


/**
 * @author Milena
 */
public class KDC {

    private KeyGenerator kg;
    private Key Kses;
    private Timer timer;
    private Timestamp timestamp;
    private Cipher enc, dec;
    private User user1, user2;
    public static KerberosInterface kerberosInterface;

    public KDC(KerberosInterface kerberosInterface) {
        this.kerberosInterface = kerberosInterface;
    }

    public KDC() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, NoSuchProviderException {

        kg = KeyGenerator.getInstance("DES");
        timestamp = new Timestamp(System.currentTimeMillis());

        user1 = new User();
        user2 = new User();

        user1.setId("User1");
        user1.setRequest(true);

        user2.setId("User2");

        if (user1.isRequest() || user2.isRequest()) {
            this.Kses = kg.generateKey();
            this.timer = new Timer();
            if ((timer.equals(5 * 60 * 1000))) {
                this.Kses = null;
                System.out.println("Session time has passed!!");
            }

        }
    }

    public KDC(User user1, User user2) throws NoSuchAlgorithmException {
        kg = KeyGenerator.getInstance("DES");
        if (!kerberosInterface.userValidator(user1, user2)) {
            this.Kses = kg.generateKey();
        } else {
            this.Kses = null;
        }
    }


    public User getUser1() {
        return user1;
    }

    public User getUser2() {
        return user2;
    }

    public Timer getTimer() {return timer;}

    public Key getKses() {return Kses;}

    public String encryptYA(User user1, User user2) throws InvalidKeyException, UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException {
        StringBuilder sb = new StringBuilder();

        sb.append(Kses);
        sb.append(" ");
        sb.append(user1.getNonce());
        sb.append(" ");
        sb.append(timestamp);
        sb.append(" ");
        sb.append(user2.getId());
        sb.append(" ");
        String forEncryption = sb.toString();

        enc = Cipher.getInstance("DES");
        enc.init(Cipher.ENCRYPT_MODE, user1.getKey());
        byte[] utf8 = forEncryption.getBytes("utf8");
        byte[] encrypted = enc.doFinal(utf8);
        encrypted = BASE64EncoderStream.encode(encrypted);

        return new String(encrypted);
    }

    public String decryptYA(String encrypted, User user) throws NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
        dec = Cipher.getInstance("DES");
        dec.init(Cipher.DECRYPT_MODE, user.getKey());
        byte[] decrypted = BASE64DecoderStream.decode(encrypted.getBytes());
        byte[] utf8 = dec.doFinal(decrypted);
        return new String(utf8);
    }

    public String encryptYB(User user1, User user2) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException {
        StringBuilder sb = new StringBuilder();

        sb.append(Kses);
        sb.append(" ");
        sb.append(user1.getId());
        sb.append(" ");
        sb.append(timestamp);
        String forEncryption = sb.toString();

        enc = Cipher.getInstance("DES");
        enc.init(Cipher.ENCRYPT_MODE, user2.getKey());
        byte[] utf8 = forEncryption.getBytes("utf8");
        byte[] encrypted = enc.doFinal(utf8);
        encrypted = BASE64EncoderStream.encode(encrypted);

        return new String(encrypted);

    }

    public String decryptYB(String encrypted, User user) throws NoSuchAlgorithmException, NoSuchPaddingException, UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
        dec = Cipher.getInstance("DES");
        dec.init(Cipher.DECRYPT_MODE, user.getKey());
        byte[] decrypted = BASE64DecoderStream.decode(encrypted.getBytes());
        byte[] utf8 = dec.doFinal(decrypted);
        return new String(utf8);
    }

    public String encryptYAB(User user) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException {
        StringBuilder sb = new StringBuilder();

        sb.append(user.getId());
        sb.append(" ");
        sb.append(timestamp);
        String forEncryption = sb.toString();

        enc = Cipher.getInstance("DES");
        enc.init(Cipher.ENCRYPT_MODE, Kses);
        byte[] utf8 = forEncryption.getBytes("utf8");
        byte[] encrypted = enc.doFinal(utf8);
        encrypted = BASE64EncoderStream.encode(encrypted);

        return new String(encrypted);
    }

    public String decryptYAB(String encrypted) throws NoSuchAlgorithmException, NoSuchPaddingException, UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
        dec = Cipher.getInstance("DES");
        dec.init(Cipher.DECRYPT_MODE, Kses);
        byte[] decrypted = BASE64DecoderStream.decode(encrypted.getBytes());
        byte[] utf8 = dec.doFinal(decrypted);
        return new String(utf8);
    }

    public String encryptX(String messageX) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, UnsupportedEncodingException, IllegalBlockSizeException, IllegalBlockSizeException, BadPaddingException, BadPaddingException, BadPaddingException {
        enc = Cipher.getInstance("DES");
        enc.init(Cipher.ENCRYPT_MODE, Kses);
        byte[] utf8 = messageX.getBytes("utf8");
        byte[] encrypted = enc.doFinal(utf8);
        encrypted = BASE64EncoderStream.encode(encrypted);

        return new String(encrypted);
    }

    public String decryptY(String encryptX) throws NoSuchAlgorithmException, NoSuchPaddingException, NoSuchPaddingException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
        dec = Cipher.getInstance("DES");
        dec.init(Cipher.DECRYPT_MODE, Kses);
        byte[] decrypted = BASE64DecoderStream.decode(encryptX.getBytes());
        byte[] utf8 = dec.doFinal(decrypted);
        return new String(utf8);
    }
}
