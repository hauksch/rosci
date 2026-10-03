package de.deshittifier.osci.bridge;

import java.io.ByteArrayInputStream;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Enumeration;

import de.osci.osci12.common.Constants;
import de.osci.osci12.common.DialogHandler;
import de.osci.osci12.encryption.Crypto;
import de.osci.osci12.encryption.OSCICipherException;
import de.osci.osci12.extinterfaces.crypto.Decrypter;
import de.osci.osci12.extinterfaces.crypto.Signer;

/**
 * Turns base64 blobs from the line protocol into the library's Signer /
 * Decrypter SPI objects, plus a tolerant certificate parser that accepts both
 * PEM and bare base64 DER — because after decades of German PKI, certificates
 * arrive in whatever envelope the sending Behörde had lying around.
 */
public final class CryptoMaterial
{
  private CryptoMaterial()
  {}

  /** Parses a certificate given as PEM or bare base64 DER. */
  public static X509Certificate parseCertificate(String pemOrBase64Der)
  {
    require(pemOrBase64Der != null && !pemOrBase64Der.isBlank(), "missing certificate");
    String b64 = pemOrBase64Der.replace("-----BEGIN CERTIFICATE-----", "")
                               .replace("-----END CERTIFICATE-----", "")
                               .replaceAll("\\s", "");
    byte[] der;
    try
    {
      der = Base64.getDecoder().decode(b64);
    }
    catch (IllegalArgumentException e)
    {
      throw new BridgeException(BridgeException.PROTOCOL, "certificate is neither PEM nor base64 DER");
    }
    try
    {
      CertificateFactory cf = CertificateFactory.getInstance("X.509");
      return (X509Certificate)cf.generateCertificate(new ByteArrayInputStream(der));
    }
    catch (GeneralSecurityException e)
    {
      throw new BridgeException(BridgeException.CRYPTO, "cannot parse certificate: " + e.getMessage());
    }
  }

  private static void require(boolean cond, String message)
  {
    if (!cond)
      throw new BridgeException(BridgeException.PROTOCOL, message);
  }

  /**
   * Signer SPI backed by a PKCS#12 bundle. Follows the library's sample
   * implementation: first key entry wins, RSA defaults to PSS padding
   * (v1.5 is only kept around for museum use).
   */
  public static final class P12Signer extends Signer
  {
    private final X509Certificate cert;
    private final PrivateKey key;

    public P12Signer(byte[] p12, char[] pin)
    {
      KeyStore ks = loadP12(p12, pin);
      String alias = firstKeyAlias(ks);
      this.cert = certificate(ks, alias);
      this.key = privateKey(ks, alias, pin);
      require(this.cert != null && this.key != null, "PKCS#12 contains no usable key entry");
    }

    @Override
    public String getVendor()
    {
      return "osci-deshittifier";
    }

    @Override
    public String getVersion()
    {
      return "1.0";
    }

    @Override
    public X509Certificate getCertificate()
    {
      return cert;
    }

    @Override
    public String getAlgorithm()
    {
      String algo = DialogHandler.getSignatureAlgorithm();
      String keyType = key.getAlgorithm();
      if (algo.endsWith("sha256") && "EC".equals(keyType))
        algo = Constants.SIGNATURE_ALGORITHM_ECDSA_SHA256;
      else if (algo.endsWith("sha384") && "EC".equals(keyType))
        algo = Constants.SIGNATURE_ALGORITHM_ECDSA_SHA384;
      else if (algo.endsWith("sha512") && "EC".equals(keyType))
        algo = Constants.SIGNATURE_ALGORITHM_ECDSA_SHA512;
      else if ("RSA".equals(keyType))
      {
        // PSS only: the bridge always constructs this signer with PSS on,
        // and the library has deprecated the PKCS#1 v1.5 constants — the
        // museum branch would be both dead and officially discouraged.
        if (algo.contains("sha256"))
          algo = Constants.SIGNATURE_ALGORITHM_RSA_SHA256_PSS;
        else if (algo.contains("sha512"))
          algo = Constants.SIGNATURE_ALGORITHM_RSA_SHA512_PSS;
      }
      return algo;
    }

    @Override
    public byte[] sign(byte[] hash, String algorithm)
    {
      try
      {
        Provider p = DialogHandler.getSecurityProvider();
        String jca = Constants.JCA_JCE_MAP.get(algorithm);
        Signature engine = (p == null) ? Signature.getInstance(jca)
                                      : Signature.getInstance(jca, p);
        engine.initSign(key);
        engine.update(hash);
        return engine.sign();
      }
      catch (GeneralSecurityException e)
      {
        throw new BridgeException(BridgeException.CRYPTO, "signing failed: " + e.getMessage());
      }
    }
  }

  /**
   * Decrypter SPI backed by a PKCS#12 bundle. Both RSAES-PKCS1-v1_5 and
   * RSAES-OAEP delegate to the library's own Crypto helpers so we stay
   * byte-compatible with whatever the intermediary dreamed up.
   */
  public static final class P12Decrypter extends Decrypter
  {
    private final X509Certificate cert;
    private final PrivateKey key;

    public P12Decrypter(byte[] p12, char[] pin)
    {
      KeyStore ks = loadP12(p12, pin);
      String alias = firstKeyAlias(ks);
      this.cert = certificate(ks, alias);
      this.key = privateKey(ks, alias, pin);
      require(this.cert != null && this.key != null, "PKCS#12 contains no usable key entry");
    }

    @Override
    public String getVendor()
    {
      return "osci-deshittifier";
    }

    @Override
    public String getVersion()
    {
      return "1.0";
    }

    @Override
    public X509Certificate getCertificate()
    {
      return cert;
    }

    @Override
    public byte[] decrypt(byte[] data)
    {
      try
      {
        return Crypto.doRSADecryption(key, data);
      }
      catch (OSCICipherException | GeneralSecurityException e)
      {
        throw new BridgeException(BridgeException.CRYPTO, "decryption failed: " + e.getMessage());
      }
    }

    @Override
    public byte[] decrypt(byte[] data, String mgfAlgorithm, String digestAlgorithm)
    {
      try
      {
        return Crypto.doRSADecryption(key, data, Constants.ASYMMETRIC_CIPHER_ALGORITHM_RSA_OAEP,
                                      mgfAlgorithm, digestAlgorithm, null);
      }
      catch (OSCICipherException | GeneralSecurityException e)
      {
        throw new BridgeException(BridgeException.CRYPTO, "decryption failed: " + e.getMessage());
      }
    }
  }

  static KeyStore loadP12(byte[] p12, char[] pin)
  {
    require(p12 != null && p12.length > 0, "missing PKCS#12 material");
    try
    {
      Provider p = DialogHandler.getSecurityProvider();
      KeyStore ks = (p == null) ? KeyStore.getInstance("PKCS12")
                               : KeyStore.getInstance("PKCS12", p);
      ks.load(new ByteArrayInputStream(p12), pin);
      return ks;
    }
    catch (Exception e)
    {
      throw new BridgeException(BridgeException.CRYPTO,
                                "cannot load PKCS#12 (wrong PIN?): " + e.getMessage());
    }
  }

  private static String firstKeyAlias(KeyStore ks)
  {
    try
    {
      Enumeration<String> aliases = ks.aliases();
      while (aliases.hasMoreElements())
      {
        String alias = aliases.nextElement();
        if (ks.isKeyEntry(alias))
          return alias;
      }
    }
    catch (GeneralSecurityException e)
    {
      throw new BridgeException(BridgeException.CRYPTO, "cannot enumerate PKCS#12 aliases: " + e.getMessage());
    }
    throw new BridgeException(BridgeException.CRYPTO, "PKCS#12 contains no key entry");
  }

  private static X509Certificate certificate(KeyStore ks, String alias)
  {
    try
    {
      return (X509Certificate)ks.getCertificate(alias);
    }
    catch (GeneralSecurityException e)
    {
      throw new BridgeException(BridgeException.CRYPTO, "cannot read certificate from PKCS#12: " + e.getMessage());
    }
  }

  private static PrivateKey privateKey(KeyStore ks, String alias, char[] pin)
  {
    try
    {
      return (PrivateKey)ks.getKey(alias, pin);
    }
    catch (GeneralSecurityException e)
    {
      throw new BridgeException(BridgeException.CRYPTO,
                                "cannot extract private key from PKCS#12: " + e.getMessage());
    }
  }
}
