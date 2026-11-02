import java.security.*;
import javax.crypto.Cipher;
public class Auth {
  KeyPair kp() throws Exception { KeyPairGenerator g = KeyPairGenerator.getInstance("RSA"); g.initialize(1024); return g.generateKeyPair(); }
  Cipher c() throws Exception { return Cipher.getInstance("AES/ECB/PKCS5Padding"); }
  Signature s() throws Exception { return Signature.getInstance("SHA256withECDSA"); }
  KeyPairGenerator d() throws Exception { return KeyPairGenerator.getInstance("DSA"); }
  MessageDigest m() throws Exception { return MessageDigest.getInstance("SHA-1"); }
}
