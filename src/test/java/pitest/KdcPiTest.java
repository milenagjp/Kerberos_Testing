package pitest;

import org.example.KDC;
import org.example.Kerberos;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

import static org.junit.Assert.*;

public class KdcPiTest {

    private KDC kdc;


    @Before
    public void setup() throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException {

        kdc = new KDC();
    }

    @Test
    public void test1() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, NoSuchProviderException, UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException {

        //methods from User class
        assertNotNull(kdc.getUser1().getId());
        assertEquals("User2", kdc.getUser2().getId());
        assertTrue(kdc.getUser1().isRequest());
        assertFalse(kdc.getUser2().isRequest());
        assertNotEquals("", kdc.getUser1().toString());
        assertNotEquals("", kdc.getUser2().toString());
        assertTrue(kdc.getUser1().getNonce() != 0);
        assertTrue(kdc.getUser2().getNonce() != 0);
        assertNotNull(kdc.getUser1().getKey());
        assertNotNull(kdc.getUser2().getKg());

        //kdc enkripcii
        assertNotNull(kdc.encryptYA(kdc.getUser1(), kdc.getUser2()));
        assertNotNull(kdc.encryptYB(kdc.getUser1(), kdc.getUser2()));
        assertNotNull(kdc.encryptYAB(kdc.getUser1()));
        assertNotNull(kdc.encryptX("Zdravo, kako si?"));

        assertNotEquals("", kdc.encryptYA(kdc.getUser1(), kdc.getUser2()));
        assertNotEquals("", kdc.encryptYB(kdc.getUser1(), kdc.getUser2()));
        assertNotEquals("", kdc.encryptYAB(kdc.getUser1()));
        assertNotEquals("", kdc.encryptX("Zdravo, kako si?"));

        //kdc dekripcii
        assertNotNull(kdc.decryptYA(kdc.encryptYA(kdc.getUser1(), kdc.getUser2()), kdc.getUser1()));
        assertNotNull(kdc.decryptYB(kdc.encryptYB(kdc.getUser1(), kdc.getUser2()), kdc.getUser2()));
        assertNotNull(kdc.decryptYAB(kdc.encryptYAB(kdc.getUser1())));
        assertNotNull(kdc.decryptY(kdc.encryptX("Zdravo, kako si?")));

        assertNotEquals("", kdc.decryptYA(kdc.encryptYA(kdc.getUser1(), kdc.getUser2()), kdc.getUser1()));
        assertNotEquals("", kdc.decryptYB(kdc.encryptYB(kdc.getUser1(), kdc.getUser2()), kdc.getUser2()));
        assertNotEquals("", kdc.decryptYAB(kdc.encryptYAB(kdc.getUser1())));
        assertNotEquals("", kdc.decryptY(kdc.encryptX("Zdravo, kako si?")));



    }

    @Test
    public void test2() throws NoSuchPaddingException, BadPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, UnsupportedEncodingException, NoSuchProviderException, InvalidKeyException {


        ByteArrayOutputStream outContent = new ByteArrayOutputStream();
        System.setOut(new PrintStream(outContent));

        Kerberos.main(null);
        assertTrue(outContent.toString().contains(kdc.getUser1().getId()));
        //assertEquals("Authentication failed!!!", outContent.toString());
        assertTrue(outContent.toString().contains("Encryption with keyA:"));
        assertTrue(outContent.toString().contains("Encryption with keyB:"));
        assertTrue(outContent.toString().contains("Decryption with keyA:"));
        assertTrue(outContent.toString().contains("Decryption with keyB:"));
        assertTrue(outContent.toString().contains("Encryption with session key:"));
        assertTrue(outContent.toString().contains("Decryption with session key:"));
        assertTrue(outContent.toString().contains("Encrypted message:"));
        assertTrue(outContent.toString().contains("Decrypted message:"));


    }
}
