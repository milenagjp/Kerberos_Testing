package org.example;/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import java.security.*;
import java.util.Random;


/**
 *
 * @author Milena
 */
public class User {

    private KeyGenerator kg;
    private Key key;
    private Random random;
    private int nonce;
    private String id;
    private boolean request;

    public User() throws NoSuchAlgorithmException {
        random = new Random();
        kg = KeyGenerator.getInstance("DES");
        key = kg.generateKey();
        nonce = random.nextInt();
        request = false;
    }

    public KeyGenerator getKg() {
        return kg;
    }


    public Key getKey() {
        return key;
    }

    public int getNonce() {
        return nonce;
    }


    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public boolean isRequest() {
        return request;
    }

    public void setRequest(boolean request) {
        this.request = request;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append(key);
        sb.append(" ");
        sb.append(nonce);
        sb.append(" ");
        sb.append(id);
        return sb.toString();
    }

}
