package logic;

import org.example.KDC;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;

import javax.crypto.NoSuchPaddingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

import static org.junit.jupiter.api.Assertions.*;

public class LogicCoverageKDCTest {

    public static KDC kdc;

    @BeforeAll
    static void beforeAll() throws NoSuchProviderException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException {
        kdc=new KDC();
    }


    @Test
    void test3() {
        //TFT
        assertTrue(kdc.getUser1().isRequest());
        assertFalse(kdc.getUser2().isRequest());
        assertEquals(kdc.getTimer().purge(), 0);
        assertNull(kdc.getKses());
    }

    @Test
    void test4() {
        //TFF
        assertTrue(kdc.getUser1().isRequest());
        assertFalse(kdc.getUser2().isRequest());
        assertNotEquals(kdc.getTimer(), 5 * 60 * 1000);
        assertNotNull(kdc.getKses());

    }



}
