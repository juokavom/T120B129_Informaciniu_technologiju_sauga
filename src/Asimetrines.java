import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Iterator;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.jce.interfaces.ElGamalPrivateKey;
import org.bouncycastle.jce.interfaces.ElGamalPublicKey;
import org.bouncycastle.jce.spec.ElGamalParameterSpec;
import org.bouncycastle.jce.spec.ElGamalPrivateKeySpec;
import org.bouncycastle.jce.spec.ElGamalPublicKeySpec;

public class Asimetrines {
    private static final String digits = "0123456789ABCDEF";

    public static void main(String[] args) throws Exception {
        doRSADecrypt();
    }

    public static void doRSADecrypt() throws Exception {
        int ilgis = 0;
        BigInteger mod = new BigInteger(
            "00B3446AF443CD8413C155114359C501DF6616282F89F3B178CFB62B689E899E03",
            16);
        BigInteger vies = new BigInteger(
            "010001",
            16);
        BigInteger ct = new BigInteger("0554AE129B4788E803F5E5F6D01D6002439C432D47A6D97A298536D615309039",16);
        //BigInteger ct = new BigInteger("0554AEA99B4788E803F5E5F6D01D6002439C432D47A6D97A298536D615309039",16); //Modifikuota sifrograma 6.2

        byte[] inputBytes = ct.toByteArray();
        SecureRandom random = new SecureRandom();
        Cipher cipher = Cipher.getInstance("RSA/None/PKCS1Padding");
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");

        RSAPublicKeySpec pubKeySpec = new RSAPublicKeySpec(mod, vies);
        RSAPrivateKeySpec privKeySpec = new RSAPrivateKeySpec(mod,
            new BigInteger("3D4224F641712A300201CABB6422B1278E7008C9D6D3AFA63A67D919CED15719",16));

        RSAPublicKey pubKey = (RSAPublicKey) keyFactory.generatePublic(pubKeySpec);
        RSAPrivateKey privKey = (RSAPrivateKey) keyFactory.generatePrivate(privKeySpec);

        System.out.println("Šifrograma: " + toHex(inputBytes, inputBytes.length));
        cipher.init(Cipher.DECRYPT_MODE, privKey, random);
        byte[] plainText = new byte[cipher.getOutputSize(inputBytes.length)];

        ilgis += cipher.doFinal(inputBytes, 0, inputBytes.length, plainText, 0);
        System.out.println("Iššifruota tekstograma: " + toHex(plainText, ilgis) + "baitai: " + ilgis);
        System.out.println("Viešasis raktas: " + toHex(pubKey.getPublicExponent().toByteArray()));
        System.out.println("RSA modulis: " + toHex(pubKey.getModulus().toByteArray()));
        System.out.println("Privatusis raktas: " + toHex(privKey.getPrivateExponent().toByteArray()));

        //patikrinimas
        cipher.init(Cipher.ENCRYPT_MODE, pubKey);
        byte[] cipherText = cipher.doFinal(plainText);
        System.out.println("Vel užšifruota: " + toHex(cipherText));
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