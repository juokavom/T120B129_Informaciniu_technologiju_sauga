import org.bouncycastle.util.encoders.Hex;

import java.security.Provider;
import java.security.Security;
import java.util.Iterator;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class Simetriniai
{
    private static final String	digits = "0123456789ABCDEF";
    public static void main(String[] args) throws Exception
    {
        // Savo uzduotis realizuokite kaip klases Main metodus
        // ir juos iskvieskite is sio metodo, kaip pavyzdziui:
        //doListBCCapabilities();
        doEncryptAES();
        //doDecryptSerpent();

    }

    public static void doEncryptAES() throws Exception
    {
        byte[]  plainText = Hex.decode("035816224D55DEC6 173EFE204B47B054 E063DCF424590D9F 2B5B087F1968AB24");
        //byte[]  plainText = Hex.decode("035816224D55DEC6 173EFE0B4B47B054 E063DCF424590D9F 2B5B087F1968AB24"); //Modifikuota tekstograma 2.2
        //byte[]  plainText = Hex.decode("035816224D55DEC6 173EFE204B47B054 E063DCF424590D9F 2B5B087F1968AB"); //Sutrumpinta tekstograma 2.3
        byte[]  keyBytes = Hex.decode("0001020304050607 08090A0B0C0D0E0F 1011121314151617 2021222324252627");

        SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");
        Cipher        cipher = Cipher.getInstance("AES/ECB/NoPadding");
        int           len = plainText.length;

        System.out.println("Tekstograma : " + toHex(plainText, len));
        System.out.println("AES raktas : " + toHex(keyBytes));

        byte[] cipherText = new byte[len];
        cipher.init(Cipher.ENCRYPT_MODE, key);
        int ctLength = cipher.update(plainText, 0, len, cipherText, 0);
        ctLength += cipher.doFinal(cipherText, ctLength);
        System.out.println("Šifrograma : " + toHex(cipherText) + " baitai: " + ctLength);

        /*
        cipherText[10] = (byte) 0x8C;
        System.out.println("Modifikuota šifrograma : " + toHex(cipherText) + " baitai: " + ctLength); //modifikuota šifrograma 2.4
        */

        // Patikrinimas
        byte[] decrText = new byte[len];
        cipher.init(Cipher.DECRYPT_MODE, key);
        int ptLength = cipher.update(cipherText, 0, len, decrText, 0);
        ptLength += cipher.doFinal(decrText, ptLength);
        System.out.println("Iššifruotas tekstas : " + toHex(decrText) + " baitai: " + ptLength);
    }
    public static void doDecryptSerpent() throws Exception
    {
        //small changes
        byte[]  input = new byte[] {
                (byte) 0xDF, (byte) 0xD1, (byte) 0xAD, (byte) 0x8F, (byte) 0xED, 0x3D, 0x09, 0x1F,
                (byte) 0x79, (byte) 0xD8, 0x5F, 0x1A, 0x0E, (byte) 0x8F, 0x1F, 0x61,
                (byte) 0xD9, (byte) 0x8C, 0x1A, 0x50, 0x03, (byte) 0xFD, (byte) 0xEE, 0x0B,
                0x61, 0x5F, (byte) 0xC3, (byte) 0x94, (byte) 0xD8, (byte) 0xFE, 0x1C, 0x54};
        /*byte[]  keyBytes = new byte[] {
                0x66, 0x65, 0x56, 0x66, 0x66, 0x65, 0x56, 0x66,
                0x33, 0x31, 0x13, 0x33, 0x33, 0x31, 0x13, 0x33};*/
        byte[]  keyBytes = Hex.decode("6665566666655666 3331133333311333");
        byte[]	ivBytes = new byte[] {
                0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00,
                0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};

        System.out.println("Input : " + toHex(input));
        SecretKeySpec   key = new SecretKeySpec(keyBytes, 0, 16, "serpent");
        // IV turi buti lygiai tiek baitu, koks yra bloko ilgis
        IvParameterSpec ivSpec = new IvParameterSpec(ivBytes, 0, 16);
        Cipher          cipher = Cipher.getInstance("serpent/CBC/TBCPadding");

        cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
        byte[] plainText = new byte[cipher.getOutputSize(input.length)];

        int ptLength = cipher.update(input, 0, input.length, plainText, 0);
        ptLength += cipher.doFinal(plainText, ptLength);
        System.out.println("Serpent decrypted message: " + toHex(plainText, ptLength) + " bytes: " + ptLength);
        byte[] raktas = key.getEncoded();
        System.out.println("Used key : " + toHex(raktas));
        System.out.println("Used IV : " + toHex(ivSpec.getIV()));

        //Patikrinimas
        cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
        byte[] cipherText = new byte[cipher.getOutputSize(ptLength)];

        int ctLength = cipher.update(plainText, 0, ptLength, cipherText, 0);
        ctLength += cipher.doFinal(cipherText, ctLength);

        System.out.println("Cipher text : " + toHex(cipherText, ctLength) + " bytes: " + ctLength);


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