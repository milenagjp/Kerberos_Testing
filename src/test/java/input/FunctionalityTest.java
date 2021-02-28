package input;

import com.sun.mail.util.BASE64EncoderStream;
import org.example.KDC;
import org.example.User;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import javax.crypto.*;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.sql.Timestamp;

import static org.junit.jupiter.api.Assertions.assertThrows;

public class FunctionalityTest {
    public static KDC kdc;

    @BeforeAll
    static void setup() throws NoSuchProviderException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException {
        kdc = new KDC();
    }

    @Test
    public void arrayIndexOutOfBoundsEx() {
        String stringValue = "\u0048\u0065\u006C\u006C\u006F";
        String deserializedStringValue = new String(stringValue);

        assertThrows(ArrayIndexOutOfBoundsException.class, () -> {
            kdc.decryptYA(deserializedStringValue, kdc.getUser1());
        });

        assertThrows(ArrayIndexOutOfBoundsException.class, () -> {
            kdc.decryptYA(deserializedStringValue, kdc.getUser2());
        });
    }

    @Test
    public void badPaddingEx() throws BadPaddingException, UnsupportedEncodingException, IllegalBlockSizeException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException {
        String encrypted = kdc.encryptYA(kdc.getUser1(), kdc.getUser2());
        assertThrows(BadPaddingException.class, () -> {
            kdc.decryptYA(encrypted, kdc.getUser2());
        });
    }

    @Test
    void invalidKeyEx() throws NoSuchPaddingException, BadPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, UnsupportedEncodingException, InvalidKeyException {
        //ecrypted with DES, decrypting with AES
        assertThrows(InvalidKeyException.class, () -> {
            encrypt(kdc.getUser1(), kdc.getUser2());
        });

    }

    public String encrypt(User user1, User user2) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, UnsupportedEncodingException, BadPaddingException, IllegalBlockSizeException {

        KeyGenerator kg = KeyGenerator.getInstance("DES");
        Key Kses = kg.generateKey();
        Timestamp timestamp = new Timestamp(System.currentTimeMillis());
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

        Cipher enc = Cipher.getInstance("AES");
        enc.init(Cipher.ENCRYPT_MODE, user1.getKey());
        byte[] utf8 = forEncryption.getBytes("utf8");
        byte[] encrypted = enc.doFinal(utf8);
        encrypted = BASE64EncoderStream.encode(encrypted);

        return new String(encrypted);
    }

    @Test
    void noSuchAlgorithmEx() {
        //not valid algorithm

        assertThrows(NoSuchAlgorithmException.class, () -> {
            encrypt1(kdc.getUser1(), kdc.getUser2());
        });
    }

    public String encrypt1(User user1, User user2) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, UnsupportedEncodingException, BadPaddingException, IllegalBlockSizeException {

        KeyGenerator kg = KeyGenerator.getInstance("DER");
        Key Kses = kg.generateKey();
        Timestamp timestamp = new Timestamp(System.currentTimeMillis());
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

        Cipher enc = Cipher.getInstance("DER");
        enc.init(Cipher.ENCRYPT_MODE, user1.getKey());
        byte[] utf8 = forEncryption.getBytes("utf8");
        byte[] encrypted = enc.doFinal(utf8);
        encrypted = BASE64EncoderStream.encode(encrypted);

        return new String(encrypted);
    }

    @Test
    void unsupportedEncodingEx() {
        //byte[] utf8 = forEncryption.getBytes("utf");

        assertThrows(UnsupportedEncodingException.class, () -> {
            encrypt2(kdc.getUser1(), kdc.getUser2());
        });
    }

    public String encrypt2(User user1, User user2) throws NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, UnsupportedEncodingException, NoSuchPaddingException {
        KeyGenerator kg = KeyGenerator.getInstance("DES");
        Key Kses = kg.generateKey();
        Timestamp timestamp = new Timestamp(System.currentTimeMillis());
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

        Cipher enc = Cipher.getInstance("DES");
        enc.init(Cipher.ENCRYPT_MODE, user1.getKey());
        byte[] utf8 = forEncryption.getBytes("utf");
        byte[] encrypted = enc.doFinal(utf8);
        encrypted = BASE64EncoderStream.encode(encrypted);

        return new String(encrypted);
    }

    @Test
    void illegalBlockSizeEx() {
        // Cipher enc = Cipher.getInstance("DES/CBC/NoPadding");

        assertThrows(IllegalBlockSizeException.class, () -> {
            encrypt3(kdc.getUser1(), kdc.getUser2());
        });
    }

    public String encrypt3(User user1, User user2) throws UnsupportedEncodingException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException {
        KeyGenerator kg = KeyGenerator.getInstance("DES");
        Key Kses = kg.generateKey();
        Timestamp timestamp = new Timestamp(System.currentTimeMillis());
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

        Cipher enc = Cipher.getInstance("DES/CBC/NoPadding");
        enc.init(Cipher.ENCRYPT_MODE, user1.getKey());
        byte[] utf8 = forEncryption.getBytes("utf8");
        byte[] encrypted = enc.doFinal(utf8);
        encrypted = BASE64EncoderStream.encode(encrypted);

        return new String(encrypted);
    }

}
