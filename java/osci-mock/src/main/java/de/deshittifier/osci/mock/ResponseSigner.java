package de.deshittifier.osci.mock;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.PSSParameterSpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.parsers.DocumentBuilderFactory;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

/**
 * Signs mock responses the way a proper intermediary would: an
 * osci:SupplierSignature header over every Id-carrying message part, plus
 * the IntermediaryCertificates header carrying the signing certificate.
 *
 * The client library verifies this automatically (checkSignatures defaults
 * on): part digests must match its canonicalizer's computation, and the
 * RSA-PSS signature must verify over the SignedInfo bytes as captured from
 * the wire. We therefore
 *   1. digest each part with the JDK's inclusive-C14N implementation
 *      (the same W3C spec the library implements),
 *   2. emit the SignedInfo in the library's own template shape — a form
 *      canonicalization leaves unchanged — and sign exactly those bytes
 *      with JCA RSA-PSS (SHA-256, MGF1-SHA-256, salt 32; matching the
 *      library's BouncyCastle defaults).
 */
final class ResponseSigner
{
  private static final String SIGNATURE_METHOD =
    "http://www.w3.org/2007/05/xmldsig-more#sha256-rsa-MGF1";
  private static final String DIGEST_METHOD = "http://www.w3.org/2001/04/xmlenc#sha256";
  private static final String C14N = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315";
  private static final String SIGN_CERT_ROLE_ID = "intermediary_signature_cert";

  private final PrivateKey signKey;
  private final X509Certificate signCert;

  private ResponseSigner(PrivateKey signKey, X509Certificate signCert)
  {
    this.signKey = signKey;
    this.signCert = signCert;
  }

  /** Loads a PKCS#8 private key PEM plus the matching certificate PEM. */
  static ResponseSigner fromPem(Path keyPem, Path certPem) throws IOException
  {
    PrivateKey key = loadPkcs8(keyPem);
    X509Certificate cert;
    try
    {
      cert = (X509Certificate)CertificateFactory.getInstance("X.509")
                                                .generateCertificate(
                                                  new ByteArrayInputStream(readPemBody(certPem)));
    }
    catch (Exception e)
    {
      throw new IOException("cannot parse signing certificate: " + e, e);
    }
    return new ResponseSigner(key, cert);
  }

  private static byte[] readPemBody(Path pem) throws IOException
  {
    String text = Files.readString(pem, StandardCharsets.US_ASCII);
    String body = text.replaceAll("-----BEGIN [A-Z0-9 ]+-----", "")
                      .replaceAll("-----END [A-Z0-9 ]+-----", "")
                      .replaceAll("\\s", "");
    return Base64.getDecoder().decode(body);
  }

  private static PrivateKey loadPkcs8(Path pem) throws IOException
  {
    try
    {
      return KeyFactory.getInstance("RSA")
                       .generatePrivate(new PKCS8EncodedKeySpec(readPemBody(pem)));
    }
    catch (Exception e)
    {
      throw new IOException("cannot parse PKCS#8 signing key: " + e, e);
    }
  }

  /**
   * Signs the given response XML and returns it with the two extra header
   * blocks (IntermediaryCertificates + SupplierSignature) spliced in right
   * after the ControlBlock. Attachments ride as cid: references with
   * digests over their raw bytes — the library demands attachment coverage
   * on signed messages (readAttachment looks the digest up or dies).
   */
  String sign(String responseXml, List<String[]> attachments) throws IOException
  {
    try
    {
      String certB64;
      try
      {
        certB64 = Base64.getEncoder().encodeToString(signCert.getEncoded());
      }
      catch (Exception e)
      {
        throw new IOException("cannot encode signing cert: " + e, e);
      }

      String certHeader = "<osci:IntermediaryCertificates Id=\"intermediarycertificates\""
                          + " soap:actor=\"http://www.w3.org/2001/12/soap-envelope/actor/none\""
                          + " soap:mustUnderstand=\"1\">"
                          + "<osci:SignatureCertificateIntermediary Id=\"" + SIGN_CERT_ROLE_ID + "\">"
                          + "<ds:X509Data><ds:X509Certificate>" + certB64
                          + "</ds:X509Certificate></ds:X509Data>"
                          + "</osci:SignatureCertificateIntermediary>"
                          + "</osci:IntermediaryCertificates>";

      // The certificate header must be in place before digesting: it is a
      // direct header child and therefore a hashable, signable part —
      // unlike the role element nested inside it (the client's canonicalizer
      // hashes exactly: ControlBlock, direct header children that are not
      // signature headers, and the Body).
      int anchor = responseXml.indexOf("</osci:ControlBlock>");
      if (anchor < 0)
        throw new IOException("no ControlBlock to anchor the signature blocks");
      anchor += "</osci:ControlBlock>".length();
      String withCertHeader = responseXml.substring(0, anchor)
                              + "\n        " + certHeader
                              + responseXml.substring(anchor);

      Document doc = parse(withCertHeader);

      // Hashable parts, mirroring the canonicalizer's selection: every
      // element with an Id whose parent is the soap:Header or that is the
      // soap:Body. (ControlBlock qualifies as a header child; nested role
      // Ids and the signature's own Id do not.)
      List<String> ids = new ArrayList<>();
      NodeList all = doc.getElementsByTagName("*");
      for (int i = 0; i < all.getLength(); i++)
      {
        Element el = (Element)all.item(i);
        String id = el.getAttribute("Id");
        if (id.isEmpty())
          continue;
        String parent = el.getParentNode().getNodeName();
        boolean directHeaderChild = parent.endsWith(":Header");
        boolean isBody = el.getNodeName().endsWith(":Body");
        if (directHeaderChild || isBody)
          ids.add(id);
      }
      byte[][] digests = computePartDigests(doc, ids);

      // 2. SignedInfo in the library's own template shape. Attachments
      //    follow the part references as transform-less cid: references
      //    over their raw bytes — exactly how the client signs its own
      //    attachments.
      StringBuilder refs = new StringBuilder();
      for (int i = 0; i < ids.size(); i++)
      {
        refs.append("<ds:Reference URI=\"#").append(ids.get(i)).append("\">\n")
            .append("<ds:Transforms>\n")
            .append("<ds:Transform Algorithm=\"").append(C14N).append("\"></ds:Transform>\n")
            .append("</ds:Transforms>\n")
            .append("<ds:DigestMethod Algorithm=\"").append(DIGEST_METHOD)
            .append("\"></ds:DigestMethod>\n")
            .append("<ds:DigestValue>")
            .append(Base64.getEncoder().encodeToString(digests[i]))
            .append("</ds:DigestValue>\n")
            .append("</ds:Reference>\n");
      }
      for (String[] attachment : attachments)
      {
        byte[] attDigest = MessageDigest.getInstance("SHA-256")
                                        .digest(attachment[1].getBytes(StandardCharsets.UTF_8));
        refs.append("<ds:Reference URI=\"cid:").append(attachment[0]).append("\">\n")
            .append("<ds:DigestMethod Algorithm=\"").append(DIGEST_METHOD)
            .append("\"></ds:DigestMethod>\n")
            .append("<ds:DigestValue>")
            .append(Base64.getEncoder().encodeToString(attDigest))
            .append("</ds:DigestValue>\n")
            .append("</ds:Reference>\n");
      }
      String signedInfo = "<ds:SignedInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\""
                          + " xmlns:osci=\"http://www.osci.de/2002/04/osci\""
                          + " xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\""
                          + " xmlns:xenc=\"http://www.w3.org/2001/04/xmlenc#\""
                          + " xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\">\n"
                          + "<ds:CanonicalizationMethod Algorithm=\"" + C14N
                          + "\"></ds:CanonicalizationMethod>\n"
                          + "<ds:SignatureMethod Algorithm=\"" + SIGNATURE_METHOD
                          + "\"></ds:SignatureMethod>\n"
                          + refs
                          + "</ds:SignedInfo>";

      // 3. Sign exactly those bytes with RSA-PSS.
      Signature s = Signature.getInstance("RSASSA-PSS");
      s.setParameter(new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1));
      s.initSign(signKey);
      s.update(signedInfo.getBytes(StandardCharsets.UTF_8));
      String signatureValue = Base64.getEncoder().encodeToString(s.sign());

      String supplierSignature = "<osci:SupplierSignature Id=\"suppliersignature\""
                                 + " soap:actor=\"http://www.w3.org/2001/12/soap-envelope/actor/next\""
                                 + " soap:mustUnderstand=\"1\">"
                                 + "<ds:Signature>"
                                 + signedInfo
                                 + "<ds:SignatureValue>" + signatureValue + "</ds:SignatureValue>"
                                 + "<ds:KeyInfo><ds:RetrievalMethod URI=\"#" + SIGN_CERT_ROLE_ID
                                 + "\"></ds:RetrievalMethod></ds:KeyInfo>"
                                 + "</ds:Signature>"
                                 + "</osci:SupplierSignature>";

      // 4. Splice the signature after the certificate header.
      int insert = withCertHeader.indexOf("</osci:IntermediaryCertificates>");
      if (insert < 0)
        throw new IOException("certificate header vanished between steps");
      insert += "</osci:IntermediaryCertificates>".length();
      return withCertHeader.substring(0, insert)
             + "\n        " + supplierSignature
             + withCertHeader.substring(insert);
    }
    catch (IOException e)
    {
      throw e;
    }
    catch (Exception e)
    {
      throw new IOException("response signing failed: " + e, e);
    }
  }

  /**
   * Computes inclusive-C14N SHA-256 digests of the elements with the given
   * Ids via the JDK's XML-DSig engine: one throwaway signature whose
   * references carry the c14n transform; the digests are harvested and the
   * signature node discarded again.
   */
  private byte[][] computePartDigests(Document doc, List<String> ids) throws Exception
  {
    XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM");
    List<Reference> references = new ArrayList<>();
    for (String id : ids)
    {
      List<Transform> transforms = new ArrayList<>();
      transforms.add(fac.newTransform(CanonicalizationMethod.INCLUSIVE,
                                      (TransformParameterSpec)null));
      references.add(fac.newReference("#" + id,
                                      fac.newDigestMethod(DigestMethod.SHA256, null),
                                      transforms, null, null));
    }
    // The throwaway signature method is irrelevant — only the reference
    // digests are harvested — so use the one algorithm every JDK dsig
    // factory accepts. (This JDK rejects rsa-sha256 here; rsa-sha1 always
    // registers. The real signature below uses RSA-PSS.)
    SignedInfo si = fac.newSignedInfo(
      fac.newCanonicalizationMethod(CanonicalizationMethod.INCLUSIVE,
                                    (C14NMethodParameterSpec)null),
      fac.newSignatureMethod("http://www.w3.org/2000/09/xmldsig#rsa-sha1", null),
      references);

    // A throwaway key signs nothing that matters; only the digests survive.
    KeyPair ephemeral = KeyPairGenerator.getInstance("RSA").genKeyPair();
    DOMSignContext ctx = new DOMSignContext(ephemeral.getPrivate(), doc.getDocumentElement());
    // The JDK's resolver only finds #id references for attributes declared
    // as IDs — untyped Id="" attributes need manual registration.
    NodeList all = doc.getElementsByTagName("*");
    for (int i = 0; i < all.getLength(); i++)
    {
      Element el = (Element)all.item(i);
      if (!el.getAttribute("Id").isEmpty())
        ctx.setIdAttributeNS(el, null, "Id");
    }
    fac.newXMLSignature(si, null).sign(ctx);

    NodeList sigs = doc.getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#", "Signature");
    for (int i = sigs.getLength() - 1; i >= 0; i--)
      sigs.item(i).getParentNode().removeChild(sigs.item(i));

    byte[][] out = new byte[ids.size()][];
    for (int i = 0; i < ids.size(); i++)
      out[i] = references.get(i).getDigestValue();
    return out;
  }

  private static Document parse(String xml) throws Exception
  {
    DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
    dbf.setNamespaceAware(true);
    return dbf.newDocumentBuilder()
              .parse(new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8)));
  }
}
