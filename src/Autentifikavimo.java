import java.security.Key;
import java.security.MessageDigest;
import java.security.Provider;
import java.security.Security;
import java.util.Iterator;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.util.encoders.Hex;

public class Autentifikavimo {
    private static final String digits = "0123456789ABCDEF";

    public static void main(String[] args) throws Exception {
        //doHmacSHA1Check();
        doHmacRipeMD128Check();
        //doHmacTigerCheck();
    }

    public static void doHmacSHA1Check() throws Exception {
        boolean ok = false;
        byte[] inputBytes = Hex.decode("BABCE00000010203 0405060708090A00");
        byte[]  macKeyBytes = Hex.decode("5172333435363738");
        //byte[] macKeyBytes = Hex.decode("51723334353637386666"); //Pailginamas raktas 5.1
        byte[] hmacBytes = Hex.decode("098C3E536A4E3579 EB4254F10F5A4D84 6950D8AA");

        Mac hMac = Mac.getInstance("HmacSHA1");
        Key hMacKey = new SecretKeySpec(macKeyBytes, "HmacSHA1");

        System.out.println("Tekstograma : " + toHex(inputBytes));
        System.out.println("Slaptas raktas : " + toHex(macKeyBytes));
        System.out.println("Pateiktas hmac : " + toHex(hmacBytes));

        hMac.init(hMacKey);
        hMac.update(inputBytes, 0, inputBytes.length);

        byte[] inputMac = new byte[hMac.getMacLength()];
        inputMac = hMac.doFinal();

        System.out
            .println("Apskaiciuotas hmac : " + toHex(inputMac) + " ilgis " + hMac.getMacLength());

        ok = MessageDigest.isEqual(inputMac, hmacBytes);
        System.out.println("Pranesimas nesuklastotas : " + ok);
    }

    public static void doHmacRipeMD128Check() throws Exception {
        boolean ok = false;
        byte[] inputBytes = Hex.decode("FADE000000010203 040506");
        byte[] macKeyBytes = Hex.decode("717233343536");
        //byte[] macKeyBytes = Hex.decode("717233343536332211"); //Pailginamas raktas 5.2
        byte[] hmacBytes = Hex.decode("0C7F638EB778C2F3 72AB520385F8FAAE");

        Mac hMac = Mac.getInstance("Hmac-RipeMD128");
        Key hMacKey = new SecretKeySpec(macKeyBytes, "Hmac-RipeMD128");

        System.out.println("Tekstograma : " + toHex(inputBytes));
        System.out.println("Slaptas raktas : " + toHex(macKeyBytes));
        System.out.println("Pateiktas hmac : " + toHex(hmacBytes));

        hMac.init(hMacKey);
        hMac.update(inputBytes, 0, inputBytes.length);

        byte[] inputMac = new byte[hMac.getMacLength()];
        inputMac = hMac.doFinal();

        System.out.println("Apskaiciuotas hmac : " + toHex(inputMac) + " ilgis " + hMac.getMacLength());

        ok = MessageDigest.isEqual(inputMac, hmacBytes);
        System.out.println("Pranesimas nesuklastotas : " + ok);
    }

    public static void doHmacTigerCheck() throws Exception {
        boolean ok = false;
        byte[] inputBytes = Hex.decode("BAD0000000010203 040506070809");
        byte[] macKeyBytes = Hex.decode("3132333435363738 393A3B3C");
        //byte[] macKeyBytes = Hex.decode("3132333435363738 39"); //Sutrumpinamas raktas 5.3
        byte[] hmacBytes = Hex.decode("AF7D0DC4DA5E8E47 436768F68FB095CF 2530FCCF4683F147");

        Mac hMac = Mac.getInstance("Hmac-Tiger");
        Key hMacKey = new SecretKeySpec(macKeyBytes, "Hmac-Tiger");

        System.out.println("Tekstograma : " + toHex(inputBytes));
        System.out.println("Slaptas raktas : " + toHex(macKeyBytes));
        System.out.println("Pateiktas hmac : " + toHex(hmacBytes));

        hMac.init(hMacKey);
        hMac.update(inputBytes, 0, inputBytes.length);

        byte[] inputMac = new byte[hMac.getMacLength()];
        inputMac = hMac.doFinal();

        System.out.println("Apskaiciuotas hmac : " + toHex(inputMac) + " ilgis " + hMac.getMacLength());

        ok = MessageDigest.isEqual(inputMac, hmacBytes);
        System.out.println("Pranesimas nesuklastotas : " + ok);
    }

    public static String toHex(byte[] data, int length) {
        StringBuffer buf = new StringBuffer();
        for (int i = 0; i != length; i++) {
            int v = data[i] & 0xff;

            buf.append(digits.charAt(v >> 4));
            buf.append(digits.charAt(v & 0xf));

            if (((i + 1) % 8 == 0) && (i > 0)) {
                buf.append(" ");
            }

        }
        return buf.toString();
    }

    public static String toHex(byte[] data) {
        return toHex(data, data.length);
    }
}