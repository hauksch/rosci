package de.rosci.osci.mock;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import javax.crypto.spec.SecretKeySpec;

/**
 * Transport-layer crypto for the mock intermediary — the difference between
 * pretending to be an intermediary and actually being able to read what the
 * client sends.
 *
 * Wire format (mirrored byte-for-byte from what the OSCI library itself
 * writes, so the client's parser accepts our answers):
 *
 * <pre>
 * MIME-Version: 1.0
 * Content-Type: Multipart/Related; boundary=B; type=text/xml
 *
 * --B
 * Content-Type: text/xml; charset=UTF-8
 * Content-Transfer-Encoding: 8bit
 * Content-ID: &lt;osci@message&gt;
 * Content-Length: N
 *
 * &lt;soap:Envelope xsi:schemaLocation="… soapMessageEncrypted.xsd …"&gt;
 *   &lt;soap:Body&gt;&lt;xenc:EncryptedData MimeType="Multipart/Related"&gt;
 *     EncryptionMethod = aes256-gcm (+ osci128:IvLength Value="12")
 *     EncryptedKey: rsa-oaep (MGF1-SHA-256, digest SHA-256),
 *                  KeyInfo carries the RECIPIENT's cipher certificate,
 *                  CipherValue = base64(RSA-OAEP-wrapped AES-256 key)
 *     CipherReference URI="cid:osci_enc" (base64 transform, ceremonial)
 *   --B
 *   Content-Type: application/octet-stream
 *   Content-Transfer-Encoding: binary
 *   Content-ID: &lt;osci_enc&gt;
 *
 *   IV(12) || AES-256-GCM(ciphertext || 128-bit tag)
 * --B--
 * </pre>
 *
 * All crypto is plain JCE; no OSCI library, no BouncyCastle, no mercy.
 */
public final class TransportCrypto
{
  // Algorithm URIs exactly as the client writes and parses them.
  static final String RSA_OAEP = "http://www.w3.org/2009/xmlenc11#rsa-oaep";
  static final String MGF1_SHA256 = "http://www.w3.org/2009/xmlenc11#mgf1sha256";
  static final String DIGEST_SHA256 = "http://www.w3.org/2001/04/xmlenc#sha256";
  static final String AES256_GCM = "http://www.w3.org/2009/xmlenc11#aes256-gcm";
  static final String CIPHER_PART_ID = "osci_enc";
  static final String ENVELOPE_PART_ID = "osci@message";

  private static final int IV_LENGTH = 12;
  private static final int GCM_TAG_BITS = 128;
  private static final int AES_KEY_BITS = 256;

  private static final String XENC = "http://www.w3.org/2001/04/xmlenc#";
  private static final String DS = "http://www.w3.org/2000/09/xmldsig#";
  private static final String SOAP = "http://schemas.xmlsoap.org/soap/envelope/";
  private static final String XSI = "http://www.w3.org/2001/XMLSchema-instance";
  private static final String XENC11 = "http://www.w3.org/2009/xmlenc11#";
  private static final String OSCI128 = "http://xoev.de/transport/osci12/8";

  // Namespace URIs shared with MockIntermediary's canned content builder.
  static final String XENC_NS = XENC;
  static final String DS_NS = DS;
  static final String XENC11_NS = XENC11;
  static final String OSCI128_NS = OSCI128;
  private static final String XSD_ENC_SIG =
    "http://www.w3.org/2000/09/xmldsig# oscisig.xsd http://www.w3.org/2001/04/xmlenc# oscienc.xsd";
  private static final String XSD_ENCRYPTED =
    "http://schemas.xmlsoap.org/soap/envelope/ soapMessageEncrypted.xsd " + XSD_ENC_SIG;

  private final PrivateKey intermediaryKey;
  private final SecureRandom random = new SecureRandom();

  public TransportCrypto(PrivateKey intermediaryKey)
  {
    this.intermediaryKey = intermediaryKey;
  }

  /** Loads a PKCS#8 PEM private key (the openssl output of tests/gen-pki.sh). */
  public static TransportCrypto fromPkcs8Pem(Path pem) throws IOException
  {
    String text = Files.readString(pem, StandardCharsets.US_ASCII);
    String b64 = text.replace("-----BEGIN PRIVATE KEY-----", "")
                     .replace("-----END PRIVATE KEY-----", "")
                     .replaceAll("\\s", "");
    byte[] der;
    try
    {
      der = Base64.getDecoder().decode(b64);
    }
    catch (IllegalArgumentException e)
    {
      throw new IOException("not a PKCS#8 PEM: " + pem, e);
    }
    try
    {
      PrivateKey key = KeyFactory.getInstance("RSA")
                                 .generatePrivate(new PKCS8EncodedKeySpec(der));
      return new TransportCrypto(key);
    }
    catch (Exception e)
    {
      throw new IOException("cannot parse private key from " + pem + ": " + e.getMessage(), e);
    }
  }

  /** True if the raw request body is a transport-encrypted envelope. */
  public static boolean isEncryptedTransport(String rawBody)
  {
    return rawBody.contains("soapMessageEncrypted.xsd");
  }

  /**
   * Decrypts a transport-encrypted request and returns the inner OSCI
   * envelope. If this succeeds, the packet was provably encrypted to this
   * intermediary's certificate — the AEAD tag does not negotiate.
   */
  public byte[] decryptRequest(byte[] body) throws IOException
  {
    // ISO-8859-1 keeps byte offsets identical to char offsets, so binary
    // parts survive the round trip through String unharmed.
    String raw = new String(body, StandardCharsets.ISO_8859_1);
    List<MimePart> parts = splitMime(raw);
    MimePart envelope = partById(parts, ENVELOPE_PART_ID);
    if (envelope == null)
      throw new IOException("no osci@message part in request");

    String xml = envelope.content;
    require(xml.contains("rsa-oaep"), "unsupported key transport (want rsa-oaep)");
    require(xml.contains("aes256-gcm"), "unsupported data cipher (want aes256-gcm)");

    String wrappedKeyB64 = firstGroup(xml,
                                      "(?s)<xenc:EncryptedKey>.*?<xenc:CipherValue>(.*?)</xenc:CipherValue>");
    require(wrappedKeyB64 != null, "no EncryptedKey CipherValue");
    byte[] wrappedKey = Base64.getDecoder().decode(wrappedKeyB64.replaceAll("\\s", ""));

    String refId = firstGroup(xml, "URI=\"cid:([^\"]+)\"");
    require(refId != null, "no CipherReference");
    MimePart cipherPart = partById(parts, refId);
    require(cipherPart != null, "no cipher part with Content-ID " + refId);
    byte[] cipherBlob = cipherPart.content.getBytes(StandardCharsets.ISO_8859_1);
    require(cipherBlob.length > IV_LENGTH, "cipher part too short");

    byte[] aesKey;
    byte[] plain;
    try
    {
      Cipher rsa = Cipher.getInstance("RSA/ECB/OAEPPadding");
      rsa.init(Cipher.DECRYPT_MODE, intermediaryKey,
               new OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256,
                                     PSource.PSpecified.DEFAULT));
      aesKey = rsa.doFinal(wrappedKey);

      Cipher aes = Cipher.getInstance("AES/GCM/NoPadding");
      aes.init(Cipher.DECRYPT_MODE,
               new SecretKeySpec(aesKey, "AES"),
               new GCMParameterSpec(GCM_TAG_BITS, cipherBlob, 0, IV_LENGTH));
      plain = aes.doFinal(cipherBlob, IV_LENGTH, cipherBlob.length - IV_LENGTH);
    }
    catch (Exception e)
    {
      throw new IOException("transport decryption failed: " + e, e);
    }
    return plain;
  }

  /** A sealed payload: the wrapped session key and the encrypted bytes. */
  record Sealed(byte[] wrappedKey, byte[] blob)
  {}

  /**
   * Seals {@code plain} for the holder of {@code cert}: fresh AES-256-GCM
   * session key, RSA-OAEP key transport (SHA-256/MGF1-SHA-256), blob
   * formatted as IV(12) || ciphertext || tag — the exact dialect the OSCI
   * library writes and reads.
   */
  public Sealed seal(byte[] plain, X509Certificate cert) throws IOException
  {
    try
    {
      byte[] aesKey = new byte[AES_KEY_BITS / 8];
      random.nextBytes(aesKey);
      byte[] iv = new byte[IV_LENGTH];
      random.nextBytes(iv);

      Cipher aes = Cipher.getInstance("AES/GCM/NoPadding");
      aes.init(Cipher.ENCRYPT_MODE,
               new SecretKeySpec(aesKey, "AES"),
               new GCMParameterSpec(GCM_TAG_BITS, iv));
      byte[] ct = aes.doFinal(plain);
      byte[] blob = new byte[IV_LENGTH + ct.length];
      System.arraycopy(iv, 0, blob, 0, IV_LENGTH);
      System.arraycopy(ct, 0, blob, IV_LENGTH, ct.length);

      Cipher rsa = Cipher.getInstance("RSA/ECB/OAEPPadding");
      rsa.init(Cipher.ENCRYPT_MODE, cert.getPublicKey(),
               new OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256,
                                     PSource.PSpecified.DEFAULT));
      return new Sealed(rsa.doFinal(aesKey), blob);
    }
    catch (Exception e)
    {
      throw new IOException("sealing failed: " + e, e);
    }
  }

  /**
   * Wraps an inner response envelope for the client: fresh AES-256-GCM key,
   * RSA-OAEP key transport to the client's cipher certificate, full MIME
   * framing. The client's parser checks the embedded certificate byte-for-byte
   * against its own, so we embed exactly what the request advertised.
   */
  public byte[] encryptResponse(byte[] innerXml, X509Certificate clientCipherCert) throws IOException
  {
    Sealed sealed = seal(innerXml, clientCipherCert);
    String certB64;
    try
    {
      certB64 = Base64.getEncoder().encodeToString(clientCipherCert.getEncoded());
    }
    catch (Exception e)
    {
      throw new IOException("cannot encode client cert: " + e, e);
    }
    String keyB64 = Base64.getEncoder().encodeToString(sealed.wrappedKey());
    String xml = """
        <?xml version="1.0" encoding="UTF-8"?>
        <soap:Envelope xmlns:ds="%s" xmlns:soap="%s" xmlns:xenc="%s" xmlns:xsi="%s" xsi:schemaLocation="%s"><soap:Body><xenc:EncryptedData MimeType="Multipart/Related"><xenc:EncryptionMethod Algorithm="%s"><osci128:IvLength xmlns:osci128="%s" Value="%d"></osci128:IvLength></xenc:EncryptionMethod><ds:KeyInfo><xenc:EncryptedKey><xenc:EncryptionMethod Algorithm="%s"><xenc11:MGF xmlns:xenc11="%s" Algorithm="%s"></xenc11:MGF><ds:DigestMethod Algorithm="%s"></ds:DigestMethod></xenc:EncryptionMethod><ds:KeyInfo><ds:X509Data><ds:X509Certificate>%s</ds:X509Certificate></ds:X509Data></ds:KeyInfo><xenc:CipherData><xenc:CipherValue>%s</xenc:CipherValue></xenc:CipherData></xenc:EncryptedKey></ds:KeyInfo><xenc:CipherData><xenc:CipherReference URI="cid:%s"><xenc:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#base64"></ds:Transform></xenc:Transforms></xenc:CipherReference></xenc:CipherData></xenc:EncryptedData></soap:Body></soap:Envelope>"""
        .formatted(DS, SOAP, XENC, XSI, XSD_ENCRYPTED,
                   AES256_GCM, OSCI128, IV_LENGTH,
                   RSA_OAEP, XENC11, MGF1_SHA256, DIGEST_SHA256,
                   certB64, keyB64, CIPHER_PART_ID);

    String boundary = "MIME_boundary_mock_" + Long.toHexString(random.nextLong());
    String head = "MIME-Version: 1.0\r\n"
                  + "Content-Type: Multipart/Related; boundary=" + boundary + "; type=text/xml\r\n"
                  + "\r\n"
                  + "--" + boundary + "\r\n"
                  + "Content-Type: text/xml; charset=UTF-8\r\n"
                  + "Content-Transfer-Encoding: 8bit\r\n"
                  + "Content-ID: <" + ENVELOPE_PART_ID + ">\r\n"
                  + "Content-Length: " + xml.getBytes(StandardCharsets.UTF_8).length + "\r\n"
                  + "\r\n"
                  + xml + "\r\n"
                  + "--" + boundary + "\r\n"
                  + "Content-Type: application/octet-stream\r\n"
                  + "Content-Transfer-Encoding: binary\r\n"
                  + "Content-ID: <" + CIPHER_PART_ID + ">\r\n"
                  + "\r\n";
    String tail = "\r\n--" + boundary + "--\r\n";

    // Binary part assembled as raw bytes — never through a lossy charset.
    // seal() already laid the blob out as IV(12) || ciphertext || tag.
    byte[] prefix = head.getBytes(StandardCharsets.US_ASCII);
    byte[] blob = sealed.blob();
    byte[] tailBytes = tail.getBytes(StandardCharsets.US_ASCII);
    byte[] out = new byte[prefix.length + blob.length + tailBytes.length];
    System.arraycopy(prefix, 0, out, 0, prefix.length);
    System.arraycopy(blob, 0, out, prefix.length, blob.length);
    System.arraycopy(tailBytes, 0, out, prefix.length + blob.length, tailBytes.length);
    return out;
  }

  /** Extracts the client's cipher certificate from an inner request envelope. */
  public static String clientCipherCertB64(String innerXml) throws IOException
  {
    // <osci:CipherCertificateOriginator Id="…"><ds:X509Data><ds:X509Certificate>B64…
    String b64 = firstGroup(innerXml,
                            "(?s)<\\w+:CipherCertificateOriginator[^>]*>.*?<ds:X509Certificate>(.*?)</ds:X509Certificate>");
    if (b64 == null)
      return null;
    return b64.replaceAll("\\s", "");
  }

  public static X509Certificate certFromB64(String b64) throws IOException
  {
    try
    {
      CertificateFactory cf = CertificateFactory.getInstance("X.509");
      return (X509Certificate)cf.generateCertificate(
        new java.io.ByteArrayInputStream(Base64.getDecoder().decode(b64)));
    }
    catch (Exception e)
    {
      throw new IOException("cannot parse certificate: " + e.getMessage(), e);
    }
  }

  // ------------------------------------------------------------------ MIME

  record MimePart(String contentId, String content)
  {}

  /**
   * Splits a multipart body into its parts. Deliberately naive: boundary
   * scanning at line starts, exactly like every other MIME parser that
   * pretends MIME is simple. (It is, if you own both ends.)
   */
  static List<MimePart> splitMime(String raw) throws IOException
  {
    Matcher m = Pattern.compile("boundary=([^;\\r\\n]+)").matcher(raw);
    if (!m.find())
      throw new IOException("no MIME boundary");
    String delimiter = "--" + m.group(1).trim();

    List<MimePart> parts = new ArrayList<>();
    int pos = raw.indexOf(delimiter);
    while (pos >= 0)
    {
      int afterDelim = pos + delimiter.length();
      boolean isFinal = raw.startsWith("--", afterDelim);
      int lineEnd = endOfLine(raw, afterDelim);
      if (isFinal)
        break;
      int contentStart = lineEnd;
      int nextDelim = raw.indexOf("\r\n" + delimiter, contentStart);
      int sepLen = 2;
      if (nextDelim < 0)
      {
        nextDelim = raw.indexOf("\n" + delimiter, contentStart);
        sepLen = 1;
      }
      int contentEnd = nextDelim < 0 ? raw.length() : nextDelim;
      String part = raw.substring(contentStart, Math.min(contentEnd, raw.length()));
      // Separate the part's headers from its body: the cipher bytes start
      // after the first empty line, not after "Content-Type: application/…".
      int hdrEnd = part.indexOf("\r\n\r\n");
      int bodyStart;
      if (hdrEnd >= 0)
        bodyStart = hdrEnd + 4;
      else
      {
        int alt = part.indexOf("\n\n");
        bodyStart = alt >= 0 ? alt + 2 : 0;
      }
      parts.add(new MimePart(contentIdOf(part.substring(0, bodyStart)), part.substring(bodyStart)));
      pos = nextDelim < 0 ? -1 : nextDelim + sepLen;
    }
    if (parts.isEmpty())
      throw new IOException("no MIME parts found");
    return parts;
  }

  private static int endOfLine(String s, int from)
  {
    int nl = s.indexOf('\n', from);
    return nl < 0 ? s.length() : nl + 1;
  }

  private static String contentIdOf(String part)
  {
    int headerEnd = part.indexOf("\r\n\r\n");
    int alt = part.indexOf("\n\n");
    String header = (headerEnd >= 0 && (alt < 0 || headerEnd <= alt)) ? part.substring(0, headerEnd)
                                                                     : part.substring(0, alt < 0                                             ? part.length() : alt);
    Matcher m = Pattern.compile("Content-ID:\\s*<([^>]*)>", Pattern.CASE_INSENSITIVE).matcher(header);
    return m.find() ? m.group(1) : "";
  }

  private static MimePart partById(List<MimePart> parts, String id)
  {
    for (MimePart p : parts)
    {
      if (id.equals(p.contentId))
        return p;
    }
    return null;
  }

  // ---------------------------------------------------------------- helpers

  private static String firstGroup(String xml, String regex)
  {
    Matcher m = Pattern.compile(regex).matcher(xml);
    return m.find() ? m.group(1) : null;
  }

  private static void require(boolean cond, String message) throws IOException
  {
    if (!cond)
      throw new IOException(message);
  }
}
