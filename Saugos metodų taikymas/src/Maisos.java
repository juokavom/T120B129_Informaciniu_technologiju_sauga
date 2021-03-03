import org.bouncycastle.util.encoders.Hex;

import java.security.MessageDigest;
import java.security.Provider;
import java.security.Security;
import java.util.Iterator;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class Maisos {
    private static final String digits = "0123456789ABCDEF";

    public static void main(String[] args) throws Exception {
        // Savo uzduotis realizuokite kaip klases Main metodus
        // ir juos iskvieskite is sio metodo, kaip pavyzdziui:
        doMD4HashCheck();
        //doRipeMD160HashCheck();
        //doGOST3411HashCheck();

    }

    public static void doMD4HashCheck() throws Exception {
        boolean ok = false;
        byte[]  inputBytes = Hex.decode("BABE000004050607 08090A0B0C0D");
        //byte[] inputBytes = Hex.decode("BAA9000004050607 08090A0B0C0D"); //Keista tekstograma 4.3
        byte[] hashBytes = Hex.decode("1657674F1D008C56 428C8B6D9DB199DC");

        System.out.println("Tekstograma : " + toHex(inputBytes));
        System.out.println("MD4 santrauka : " + toHex(hashBytes));

        MessageDigest hash = MessageDigest.getInstance("MD4");

        hash.update(inputBytes, 0, inputBytes.length);
        byte[] inputHash = new byte[hash.getDigestLength()];
        inputHash = hash.digest();

        System.out.println("Apskaičiuota santrauka : " + toHex(inputHash));

        ok = MessageDigest.isEqual(inputHash, hashBytes);
        System.out.println("Tekstograma nepakeista? : " + ok);
    }

    public static void doRipeMD160HashCheck() throws Exception {
        boolean ok = false;
        byte[] inputBytes = Hex.decode("ABBA000004050607 08090A0B0C0D");
        byte[] hashBytes = Hex.decode("138C4F74479575B7 AE8B23F175A35D04 E4E77AE3");

        System.out.println("Tekstograma : " + toHex(inputBytes));
        System.out.println("RipeMD160 santrauka : " + toHex(hashBytes));

        MessageDigest hash = MessageDigest.getInstance("RipeMD160");

        hash.update(inputBytes, 0, inputBytes.length);
        byte[] inputHash = new byte[hash.getDigestLength()];
        inputHash = hash.digest();

        System.out.println("Apskaičiuota santrauka : " + toHex(inputHash));

        ok = MessageDigest.isEqual(inputHash, hashBytes);
        System.out.println("Tekstograma nepakeista? : " + ok);
    }

    public static void doGOST3411HashCheck() throws Exception {
        boolean ok = false;
        byte[] inputBytes = Hex.decode("DAF0020304050607 08090A90");
        byte[] hashBytes = Hex.decode("2EB90EFCDCC91F26 42303229AFB70867 9F70095AB1A1D2F7 ED5B5E0A8B99BA48");

        System.out.println("Tekstograma : " + toHex(inputBytes));
        System.out.println("GOST3411 santrauka : " + toHex(hashBytes));

        MessageDigest hash = MessageDigest.getInstance("GOST3411");

        hash.update(inputBytes, 0, inputBytes.length);
        byte[] inputHash = new byte[hash.getDigestLength()];
        inputHash = hash.digest();

        System.out.println("Apskaičiuota santrauka : " + toHex(inputHash));

        ok = MessageDigest.isEqual(inputHash, hashBytes);
        System.out.println("Tekstograma nepakeista? : " + ok);
    }

    public static String toHex(byte[] data, int length) {
        StringBuffer buf = new StringBuffer();
        for (int i = 0; i != length; i++) {
            int v = data[i] & 0xff;

            buf.append(digits.charAt(v >> 4));
            buf.append(digits.charAt(v & 0xf));

            if (((i + 1) % 8 == 0) && (i > 0)) buf.append(" ");

        }
        return buf.toString();
    }

    public static String toHex(byte[] data) {
        return toHex(data, data.length);
    }
}
