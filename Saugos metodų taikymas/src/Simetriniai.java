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
        //doEncryptAES();
        doDecryptTEA();
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

    public static void doDecryptTEA() throws Exception
    {
        byte[]  cipherText = Hex.decode("0BFB0E46DA1A19D5 B8E283386FB492F3 574A4C3D4DA0FB82");
        //byte[]  cipherText = Hex.decode("A9FB0E46DA1A19D5 B8E283386FB492F3 574A4C3D4DA0FB82"); //Modifikuota šifrograma 3.3
        byte[]  ivBytes = Hex.decode("0706050403020100");
        //byte[]  ivBytes = Hex.decode("070605A903020100"); //Modifikuotas IV 3.4
        byte[]  keyBytes = Hex.decode("6665566666655666 3331133333311333");

        System.out.println("Šifrograma : " + toHex(cipherText));
        System.out.println("TEA raktas : " + toHex(keyBytes));
        System.out.println("IV : " + toHex(ivBytes));

        SecretKeySpec key = new SecretKeySpec(keyBytes, 0, 16,"TEA");
        Cipher        cipher = Cipher.getInstance("TEA/CBC/TBCPadding");
        IvParameterSpec ivSpec = new IvParameterSpec(ivBytes, 0, 8);
        int           len = cipherText.length;

        cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
        byte[] plainText = new byte[cipher.getOutputSize(cipherText.length)];

        int ptLength = cipher.update(cipherText, 0, cipherText.length, plainText, 0);
        ptLength += cipher.doFinal(plainText, ptLength);
        System.out.println("Iššifruotas tekstas : " + toHex(plainText, ptLength) + " baitai: " + ptLength);

        /*
        plainText[19] = (byte) 0xA9;
        System.out.println("Iššifruotas modifikuotas tekstas : " + toHex(plainText, ptLength) + " baitai: " + ptLength); //Modifikuota tekstograma 3.2
         */

        //Patikrinimas
        cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
        byte[] cipherText2 = new byte[cipher.getOutputSize(ptLength)];

        int ctLength2 = cipher.update(plainText, 0, ptLength, cipherText2, 0);
        ctLength2 += cipher.doFinal(cipherText2, ctLength2);

        System.out.println("Užšifruotas tekstas : " + toHex(cipherText2, ctLength2) + " baitai: " + ctLength2);
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