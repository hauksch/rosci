package de.deshittifier.osci.bridge;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Date;

import javax.crypto.Cipher;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import de.deshittifier.osci.bridge.CryptoMaterial.P12Decrypter;
import de.deshittifier.osci.bridge.CryptoMaterial.P12Signer;
import de.osci.osci12.common.DialogHandler;

/**
 * Crypto wiring tests with freshly generated keys — no committed fixtures,
 * no secrets in git, nothing that outlives the test run. The bureaucrat's
 * nightmare: paperwork that shreds itself.
 */
class CryptoMaterialTest
{
  private static final char[] PIN = "testpin".toCharArray();

  @BeforeAll
  static void setUpProvider()
  {
    Security.addProvider(new BouncyCastleProvider());
    DialogHandler.setSecurityProvider(Security.getProvider(BouncyCastleProvider.PROVIDER_NAME));
  }

  @Test
  void parsesCertificateFromPemAndBareBase64() throws Exception
  {
    X509Certificate cert = certificateFor(rsaKeyPair(), "CN=osci-deshittifier-test");
    byte[] der = cert.getEncoded();
    String bare = Base64.getEncoder().encodeToString(der);
    String pem = "-----BEGIN CERTIFICATE-----\n" + bare + "\n-----END CERTIFICATE-----\n";

    assertEquals(cert, CryptoMaterial.parseCertificate(pem));
    assertEquals(cert, CryptoMaterial.parseCertificate(bare));
    assertEquals(cert, CryptoMaterial.parseCertificate("  " + bare + "\n")); // tolerant of whitespace
  }

  @Test
  void rejectsGarbageCertificates()
  {
    assertThrows(BridgeException.class, () -> CryptoMaterial.parseCertificate(null));
    assertThrows(BridgeException.class, () -> CryptoMaterial.parseCertificate(""));
    assertThrows(BridgeException.class, () -> CryptoMaterial.parseCertificate("nicht wirklich ein zertifikat"));
    // valid base64, but not a certificate
    assertThrows(BridgeException.class,
                 () -> CryptoMaterial.parseCertificate(Base64.getEncoder().encodeToString(new byte[]{1, 2, 3})));
  }

  @Test
  void signerSignsAndVerifierVerifies() throws Exception
  {
    KeyPair kp = rsaKeyPair();
    X509Certificate cert = certificateFor(kp, "CN=signer-test");
    byte[] p12 = pkcs12(kp, cert, "signer");

    P12Signer signer = new P12Signer(p12, PIN);
    assertEquals(cert, signer.getCertificate());

    byte[] data = "die nutzdaten".getBytes(StandardCharsets.UTF_8);
    byte[] signature = signer.sign(data, signer.getAlgorithm());

    Signature verifier = Signature.getInstance("SHA256withRSA/PSS", BouncyCastleProvider.PROVIDER_NAME);
    verifier.initVerify(kp.getPublic());
    verifier.update(data);
    assertTrue(verifier.verify(signature), "PSS signature must verify with the public key");
  }

  @Test
  void signerFailsOnWrongPin() throws Exception
  {
    KeyPair kp = rsaKeyPair();
    byte[] p12 = pkcs12(kp, certificateFor(kp, "CN=wrong-pin"), "alias");
    BridgeException e = assertThrows(BridgeException.class,
                                     () -> new P12Signer(p12, "falsche-pin".toCharArray()));
    assertEquals(BridgeException.CRYPTO, e.kind);
  }

  @Test
  void decrypterRoundTripsPkcs1v15() throws Exception
  {
    KeyPair kp = rsaKeyPair();
    byte[] p12 = pkcs12(kp, certificateFor(kp, "CN=cipher-test"), "cipher");

    P12Decrypter decrypter = new P12Decrypter(p12, PIN);

    byte[] secret = new byte[32];
    new SecureRandom().nextBytes(secret);
    Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
    cipher.init(Cipher.ENCRYPT_MODE, kp.getPublic());
    byte[] sealed = cipher.doFinal(secret);

    assertArrayEquals(secret, decrypter.decrypt(sealed));
  }

  @Test
  void decrypterFailsOnGarbageInput() throws Exception
  {
    KeyPair kp = rsaKeyPair();
    byte[] p12 = pkcs12(kp, certificateFor(kp, "CN=cipher-garbage"), "cipher");
    P12Decrypter decrypter = new P12Decrypter(p12, PIN);
    BridgeException e = assertThrows(BridgeException.class,
                                     () -> decrypter.decrypt(new byte[]{9, 9, 9}));
    assertEquals(BridgeException.CRYPTO, e.kind);
  }

  // ------------------------------------------------------------ fixtures

  private static KeyPair rsaKeyPair() throws Exception
  {
    KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
    gen.initialize(2048);
    return gen.generateKeyPair();
  }

  private static X509Certificate certificateFor(KeyPair kp, String dn) throws Exception
  {
    X509CertificateHolder holder = new JcaX509v3CertificateBuilder(
        new org.bouncycastle.asn1.x500.X500Name(dn),
        BigInteger.valueOf(new SecureRandom().nextLong() & Long.MAX_VALUE),
        new Date(System.currentTimeMillis() - 60_000),
        new Date(System.currentTimeMillis() + 365L * 24 * 3600 * 1000),
        new org.bouncycastle.asn1.x500.X500Name(dn),
        kp.getPublic())
      .build(new JcaContentSignerBuilder("SHA256withRSA").build(kp.getPrivate()));
    return new JcaX509CertificateConverter().getCertificate(holder);
  }

  private static byte[] pkcs12(KeyPair kp, X509Certificate cert, String alias) throws Exception
  {
    KeyStore ks = KeyStore.getInstance("PKCS12", BouncyCastleProvider.PROVIDER_NAME);
    ks.load(null, null);
    ks.setKeyEntry(alias, kp.getPrivate(), PIN, new X509Certificate[]{cert});
    java.io.ByteArrayOutputStream buf = new java.io.ByteArrayOutputStream();
    ks.store(buf, PIN);
    return buf.toByteArray();
  }
}
