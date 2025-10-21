import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class DecryptUtil {
    public static String decrypt(String encryptedText, String key) throws Exception {
        byte[] encryptedBytes = Base64.getDecoder().decode(encryptedText);
        byte[] keyBytes = Base64.getDecoder().decode(key + "=");
        byte[] ivBytes = new byte[16];
        System.arraycopy(keyBytes, 0, ivBytes, 0, 16);

        SecretKeySpec secretKeySpec = new SecretKeySpec(keyBytes, "AES");
        IvParameterSpec ivParameterSpec = new IvParameterSpec(ivBytes);

        Cipher cipher = Cipher.getInstance("AES/CBC/NOPADDING");
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec);

        byte[] decryptedBytes = cipher.doFinal(encryptedBytes);
        int paddingLength = decryptedBytes[decryptedBytes.length - 1];
        byte[] unpaddedData = new byte[decryptedBytes.length - paddingLength];
        System.arraycopy(decryptedBytes, 0, unpaddedData, 0, unpaddedData.length);
        return new String(unpaddedData, StandardCharsets.UTF_8);
    }
}
