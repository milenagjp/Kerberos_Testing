package logic;

import org.example.KDC;
import org.example.Kerberos;
import org.example.User;
import org.junit.Before;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

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


public class LogicCoverageMainTest {

    public static KDC kdc;
    public static ByteArrayOutputStream outContent;

    @Test
    void testMain1() throws NoSuchPaddingException, BadPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, UnsupportedEncodingException, NoSuchProviderException, InvalidKeyException {
    //TTT
        kdc=new KDC();

        outContent = new ByteArrayOutputStream();
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

    @Test
    void testMain2() throws NoSuchPaddingException, BadPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, UnsupportedEncodingException, NoSuchProviderException, InvalidKeyException {
        //TTF
        kdc=new KDC();

        outContent = new ByteArrayOutputStream();
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
        assertFalse(outContent.toString().contains("Encrypted message:"));
        assertFalse(outContent.toString().contains("Decrypted message:"));

    }

    @Test
    void testMain3() {
        //TFT
        kdc = null;
        //dokolku vo main() metodot na Kerberos dojde do slucaj kdc==null ili parametrite od kdc da imaat vrednost null
        //togas treba da se pojavi Auth failed
        assertEquals("Authentication failed!!!", outContent.toString());
    }

    @Test
    void testMain5() {
        //FTT
        kdc = null;
        //dokolku vo main() metodot na Kerberos dojde do slucaj kdc==null ili parametrite od kdc da imaat vrednost null
        //togas treba da se pojavi Auth failed
        assertNull(outContent.toString());
    }
}
