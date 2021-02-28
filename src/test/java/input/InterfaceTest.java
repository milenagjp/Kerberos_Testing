package input;

import org.example.KDC;
import org.example.Kerberos;
import org.example.User;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

import static org.junit.Assert.*;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class InterfaceTest {

    public static KDC kdc;

    @BeforeAll
    static void setup() throws NoSuchProviderException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException {
        kdc = new KDC();
    }

    @Test
    void testEncryptYA_1() throws NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException, InvalidKeyException, UnsupportedEncodingException {
        //FF
        assertNotNull(kdc.encryptYA(kdc.getUser1(), kdc.getUser2()));
        assertFalse(kdc.encryptYA(kdc.getUser1(), kdc.getUser2()).equals(""));

    }

    @Test
    void testEncryptYA_2() { //TF
        assertThrows(NullPointerException.class, () -> {
            kdc.encryptYA(kdc.getUser1(), null);
        });
    }

    @Test
    void testEncryptYA_3() {
        //FT
        assertThrows(NullPointerException.class, () -> {
            kdc.encryptYA(null, kdc.getUser2());
        });

    }

    @Test
    void testEncryptYA_4(){
        //TT
        assertThrows(NullPointerException.class, () -> {
            kdc.encryptYA(null, null);
        });

    }

    @Test
    void testDecryptYA_1()  {
        //TFT
        String encrypted = null;
        assertThrows(NullPointerException.class, () -> {
            kdc.decryptYA(encrypted, null);
        });

    }

    @Test
    void testDecryptYA_2()  {
        //TFF
        String encrypted = null;
        assertThrows(NullPointerException.class, () -> {
            kdc.decryptYA(encrypted, kdc.getUser1());
        });

    }

    @Test
    void testDecryptYA_3() {
        //FTT
        String encrypted = "";
        assertThrows(NullPointerException.class, () -> {
            kdc.decryptYA(encrypted, null);
        });

    }

    @Test
    void testDecryptYA_4() throws NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException, InvalidKeyException {
        //FTF
        String encrypted = "";
        assertTrue(kdc.decryptYA(encrypted, kdc.getUser1()).equals(""));

    }

    @Test
    void testDecryptYA_5() throws BadPaddingException, UnsupportedEncodingException, IllegalBlockSizeException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException {
        //FFT
        String encrypted = kdc.encryptYA(kdc.getUser1(), kdc.getUser2());
        assertThrows(NullPointerException.class, () -> {
            kdc.decryptYA(encrypted, null);
        });
    }

    @Test
    void testDecryptYA_6() throws BadPaddingException, UnsupportedEncodingException, IllegalBlockSizeException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException {
        //FFF
        String encrypted = kdc.encryptYA(kdc.getUser1(), kdc.getUser2());
        assertFalse(kdc.decryptYA(encrypted, kdc.getUser1()).equals(""));
    }


    @Test
    void testEncryptYB_1() throws NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException, InvalidKeyException, UnsupportedEncodingException{
        //FF
        assertNotNull(kdc.encryptYB(kdc.getUser1(), kdc.getUser2()));
        assertFalse(kdc.encryptYB(kdc.getUser1(), kdc.getUser2()).equals(""));

    }

    @Test
    void testEncryptYB_2() {
        //TF
        assertThrows(NullPointerException.class, () -> {
            kdc.encryptYB(kdc.getUser1(), null);
        });
    }

    @Test
    void testEncryptYB_3() {
        //FT
        assertThrows(NullPointerException.class, () -> {
            kdc.encryptYB(null, kdc.getUser2());
        });

    }

    @Test
    void testEncryptYB_4() {
        //TT
        assertThrows(NullPointerException.class, () -> {
            kdc.encryptYB(null, null);
        });

    }

    @Test
    void testDecryptYB_1() {
        //TFT
        String encrypted = null;
        assertThrows(NullPointerException.class, () -> {
            kdc.decryptYB(encrypted, null);
        });

    }

    @Test
    void testDecryptYB_2()  {
        //TFF
        String encrypted = null;
        assertThrows(NullPointerException.class, () -> {
            kdc.decryptYB(encrypted, kdc.getUser1());
        });

    }

    @Test
    void testDecryptYB_3() {
        //FTT
        String encrypted = "";
        assertThrows(NullPointerException.class, () -> {
            kdc.decryptYB(encrypted, null);
        });

    }

    @Test
    void testDecryptYB_4() throws NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException, InvalidKeyException, UnsupportedEncodingException{
        //FTF
        String encrypted = "";
        assertTrue(kdc.decryptYB(encrypted, kdc.getUser1()).equals(""));

    }

    @Test
    void testDecryptYB_5() throws BadPaddingException, UnsupportedEncodingException, IllegalBlockSizeException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException {
        //FFT
        String encrypted = kdc.encryptYB(kdc.getUser1(), kdc.getUser2());
        assertThrows(NullPointerException.class, () -> {
            kdc.decryptYB(encrypted, null);
        });
    }

    @Test
    void testDecryptYB_6() throws BadPaddingException, UnsupportedEncodingException, IllegalBlockSizeException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException {
        //FFF
        String encrypted = kdc.encryptYB(kdc.getUser1(), kdc.getUser2());
        assertFalse(kdc.decryptYB(encrypted, kdc.getUser2()).equals(""));
    }

    @Test
    void testEncryptYAB_1(){
        //T
        assertThrows(NullPointerException.class, () -> {
            kdc.encryptYAB(null);
        });

    }

    @Test
    void testEncryptYAB_2() throws BadPaddingException, UnsupportedEncodingException, IllegalBlockSizeException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException {
        //F
        String encrypted=kdc.encryptYAB(kdc.getUser1());
        assertNotNull(encrypted);
        assertNotEquals("", encrypted);
    }

    @Test
    void testDecryptYAB_1() {
        //TF
        String encrypted = null;
        assertThrows(NullPointerException.class, () -> {
            kdc.decryptYAB(encrypted);
        });

    }

    @Test
    void testDecryptYAB_2() throws BadPaddingException, UnsupportedEncodingException, IllegalBlockSizeException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException {
        //FT
        String encrypted = "";
        assertNotNull(kdc.decryptYAB(encrypted));

    }

    @Test
    void testDecryptYAB_3() throws BadPaddingException, UnsupportedEncodingException, IllegalBlockSizeException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException {
        //FF
        String encrypted=kdc.encryptYAB(kdc.getUser1());
        assertNotNull(kdc.decryptYAB(encrypted));
        assertNotEquals("",kdc.decryptYAB(encrypted));

    }

    @Test
    void testEncryptX_1()  {
        //TF
        String encrypted = null;
        assertThrows(NullPointerException.class, () -> {
            kdc.encryptX(encrypted);
        });

    }

    @Test
    void testEncryptX_2() throws BadPaddingException, UnsupportedEncodingException, IllegalBlockSizeException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException {
        //FT
        String encrypted = "";
        assertNotNull(kdc.encryptX(encrypted));

    }

    @Test
    void testEncryptX_3() throws BadPaddingException, UnsupportedEncodingException, IllegalBlockSizeException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException {
        //FF
        String encrypted=kdc.encryptX("Jas sum Milena 161536.");
        assertNotNull(encrypted);
        assertNotEquals("",encrypted);

    }

    @Test
    void testDecryptY_1() {
        //TF
        String encrypted = null;
        assertThrows(NullPointerException.class, () -> {
            kdc.decryptY(encrypted);
        });

    }

    @Test
    void testDecryptY_2() throws BadPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException {
        //FT
        String encrypted = "";
        assertNotNull(kdc.decryptY(encrypted));
        assertEquals("", kdc.decryptY(encrypted));
    }

    @Test
    void testDecryptY_3() throws BadPaddingException, UnsupportedEncodingException, IllegalBlockSizeException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException {
        //FF
        String encrypted=kdc.encryptX("Jas sum Milena 161536.");
        assertNotNull(kdc.decryptY(encrypted));
        assertNotEquals("",kdc.decryptY(encrypted));
        assertEquals("Jas sum Milena 161536.", kdc.decryptY(encrypted));

    }


    @Test
    public void serializeAndDeserializeUTF8StringValueExpectingEqual()  {
        String stringValue = "\u0048\u0065\u006C\u006C\u006F";
        String deserializedStringValue = new String(stringValue);

        assertThrows(ArrayIndexOutOfBoundsException.class, () -> {
            kdc.decryptYA(deserializedStringValue,kdc.getUser1());
        });
    }

}
