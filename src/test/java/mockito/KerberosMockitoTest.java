package mockito;

import org.example.KDC;
import org.example.KerberosInterface;
import org.example.User;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.runners.MockitoJUnitRunner;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import static org.junit.Assert.assertNotNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.class)
public class KerberosMockitoTest {
    static KerberosInterface kerberosInterface;
    private static KDC kdc;
    private static User user1, user2;


    @BeforeClass
    public static void init() throws NoSuchAlgorithmException {

        user1 = new User();
        user1.setId("User1");

        user2 = new User();
        user2.setId("User2");

        kerberosInterface = mock(KerberosInterface.class);
        kdc = new KDC(kerberosInterface);

        when(kerberosInterface.userValidator(user1, user2)).thenReturn(false);
    }

    @Test
    public void test1() throws NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException, InvalidKeyException, UnsupportedEncodingException {
        kdc = new KDC(new User(), new User());

        assertNotNull(kdc.encryptYA(user1,user2));
        assertNotNull(kdc.decryptYA(kdc.encryptYA(user1,user2),user1));

        assertNotNull(kdc.encryptYB(user1,user2));
        assertNotNull(kdc.decryptYB(kdc.encryptYB(user1,user2),user2));

        assertNotNull(kdc.encryptYAB(user1));
        assertNotNull(kdc.decryptYAB(kdc.encryptYAB(user1)));

        assertNotNull(kdc.encryptX("Zdravo, kako si?"));
        assertNotNull(kdc.decryptY(kdc.encryptX("Zdravo, kako si?")));


    }
}
