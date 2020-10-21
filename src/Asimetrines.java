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

public class Asimetrines
{
    private static final String	digits = "0123456789ABCDEF";
    public static void main(String[] args) throws Exception
    {
        // Savo uzduotis realizuokite kaip klases Main metodus
        // ir juos iskvieskite is sio metodo, kaip pavyzdziui:
        //doListBCCapabilities();
        //doRSADecrypt();
        doElGamalDecrypt();

    }
    public static void doElGamalDecrypt() throws Exception
    {
        BigInteger g256 = new BigInteger(
            "65EFF5CCAAC2B7E132335DECB7A7BC21B9AFC7FF422595355BA83141C7910A9A", 16);
        BigInteger p256 = new BigInteger(
            "00EBFCB7E2CB29A9C9EF551690E0A276B643A78B9B54F1C0DF26A7F778F219A1DF", 16);
        ElGamalParameterSpec  egSpec = new ElGamalParameterSpec(p256, g256);

        BigInteger       ct = new BigInteger ("4C22AD8CBDA8173296B746A2EF4ED7141B206004A3627F68B9CA50397F45D8421E5E3E3172DEA839AFA4B90ED40385DC0F3E847322C0B94100207BCA64AAA6BF", 16);
        byte[]           inputBytes = ct.toByteArray();
        Cipher	         cipher = Cipher.getInstance("ElGamal/None/NoPadding");
        SecureRandom     random = new SecureRandom();

        KeyFactory      keyFactory = KeyFactory.getInstance("ElGamal");
        ElGamalPublicKeySpec pubKeySpec = new ElGamalPublicKeySpec(
            new BigInteger("00E54C26F99C62135DA0DC788C20C54DA2836C93D80E26DF0E350B353D286D9A7C", 16),
            egSpec);
        ElGamalPrivateKeySpec privKeySpec = new ElGamalPrivateKeySpec(
            new BigInteger("0BDBE219B628E8C37C2723ECBD7B9E27402DA552386A05C54C44EEAE438E370A", 16),
            egSpec);
        ElGamalPublicKey pubEG = (ElGamalPublicKey)keyFactory.generatePublic(pubKeySpec);
        ElGamalPrivateKey privEG = (ElGamalPrivateKey)keyFactory.generatePrivate(privKeySpec);

        System.out.println("Duotoji sifrograma : " + toHex(inputBytes));
        cipher.init(Cipher.DECRYPT_MODE, privEG);
        byte[] plainText = cipher.doFinal(inputBytes, 0, inputBytes.length);

        System.out.println("Iššifruota tekstograma : " + toHex(plainText));

        //patikrinimas
        cipher.init(Cipher.ENCRYPT_MODE, pubEG, random);
        byte[] cipherText = cipher.doFinal(plainText);

        System.out.println("Vel uzsifruotas : " + toHex(cipherText));

        System.out.println("EG viesas Y : " + toHex(pubEG.getY().toByteArray()));
        System.out.println("EG privatus X : " + toHex(privEG.getX().toByteArray()));
        System.out.println("EG generatorius G : " + toHex(privEG.getParameters().getG().toByteArray()));
        System.out.println("EG modulis P : " + toHex(pubEG.getParameters().getP().toByteArray()));
        //Ar turi sutapti? Kodel?
    }

    /*
512
OAEPWithSHA1AndMGF1Padding
BABCE30405060708
VR:  010001
MOD: 00F4044E3AF2E724 A27E778BB695F8C1 0647B95821B878DF 5268EE87C4BC8553 3B392A3BF42AB6F7 1F3CEA4F5A61A661 E82093350E285411 13F7FF722A3672A9 3F
CT:  16769A30619EFF60 562DA5F10C511654 868D901BC60AE6C8 7252D4969D38E85D C271C50B98507314 8A5CD7B2A113346D CF4AB2DCD583F944 BBA7C05C0D6577A4
PRR: 00DE20953E2023BD 3B9638289C7B04C8 617925054F1CE81B 129FA6933CCA07EB EC745972940C7940 38EA3E9BC4C0D79B EF3EBE318F072361 332889D0F7681DB1 21
     BABCE30405060708
     *
     */


    public static void doRSADecrypt() throws Exception
    {
        int              ilgis = 0;
        BigInteger       ct = new BigInteger("16769A30619EFF60562DA5F10C511654868D901BC60AE6C87252D4969D38E85DC271C50B985073148A5CD7B2A113346DCF4AB2DCD583F944BBA7C05C0D6577A4", 16);
        byte[]           inputBytes = ct.toByteArray();
        SecureRandom     random = new SecureRandom();
        Cipher	         cipher = Cipher.getInstance("RSA/None/OAEPWithSHA1AndMGF1Padding");
        KeyFactory       keyFactory = KeyFactory.getInstance("RSA");

        RSAPublicKeySpec pubKeySpec = new RSAPublicKeySpec(
            new BigInteger("00F4044E3AF2E724A27E778BB695F8C10647B95821B878DF5268EE87C4BC85533B392A3BF42AB6F71F3CEA4F5A61A661E82093350E28541113F7FF722A3672A93F", 16),
            new BigInteger("010001", 16));
        RSAPrivateKeySpec privKeySpec = new RSAPrivateKeySpec(
            new BigInteger("00F4044E3AF2E724A27E778BB695F8C10647B95821B878DF5268EE87C4BC85533B392A3BF42AB6F71F3CEA4F5A61A661E82093350E28541113F7FF722A3672A93F", 16),
            new BigInteger("00DE20953E2023BD3B9638289C7B04C8617925054F1CE81B129FA6933CCA07EBEC745972940C794038EA3E9BC4C0D79BEF3EBE318F072361332889D0F7681DB121", 16));

        RSAPublicKey pubKey = (RSAPublicKey)keyFactory.generatePublic(pubKeySpec);
        RSAPrivateKey privKey = (RSAPrivateKey)keyFactory.generatePrivate(privKeySpec);

        System.out.println("Sifrograma : " + toHex(inputBytes, inputBytes.length));
        cipher.init(Cipher.DECRYPT_MODE, privKey, random);
        byte[] plainText = new byte[cipher.getOutputSize(inputBytes.length)];

        ilgis += cipher.doFinal(inputBytes, 0, inputBytes.length, plainText, 0);
        System.out.println("Issifruota tekstograma : " + toHex(plainText, ilgis) + " ilgis: " + ilgis);
        System.out.println("Viesasis raktas :" + toHex(pubKey.getPublicExponent().toByteArray()));
        System.out.println("RSA modulis : " + toHex(pubKey.getModulus().toByteArray()));
        System.out.println("Privatusis raktas : " + toHex(privKey.getPrivateExponent().toByteArray()));


        //patikrinimas
        cipher.init(Cipher.ENCRYPT_MODE, pubKey);
        byte[] cipherText = cipher.doFinal(plainText);
        System.out.println("Vel uzsifruota : " + toHex(cipherText));
        //Ar sutampa abi sifrogramos?
    }

    /**
     * List the available capabilities for ciphers, key agreement, macs, message
     * digests, signatures and other objects in the BC provider.
     */
    public static void doListBCCapabilities() throws Exception
    {
        Provider	provider = Security.getProvider("BC");
        Iterator        it = provider.keySet().iterator();

        while (it.hasNext())
        {
            String	entry = (String)it.next();
            // this indicates the entry refers to another entry
            if (entry.startsWith("Alg.Alias."))
            {
                entry = entry.substring("Alg.Alias.".length());
            }
            String  factoryClass = entry.substring(0, entry.indexOf('.'));
            String  name = entry.substring(factoryClass.length() + 1);

            System.out.println(factoryClass + ": " + name);
        }
    }

    /**
     * Du pagalbiniai metodai skirti "graziai" atvaizduoti baitu masyvus
     */
    public static String toHex(byte[] data, int length)
    {
        StringBuffer	buf = new StringBuffer();
        for (int i = 0; i != length; i++)
        {
            int	v = data[i] & 0xff;

            buf.append(digits.charAt(v >> 4));
            buf.append(digits.charAt(v & 0xf));

            if (((i+1) % 8 == 0) && (i>0)) buf.append(" ");

        }
        return buf.toString();
    }

    public static String toHex(byte[] data)
    {
        return toHex(data, data.length);
    }

}