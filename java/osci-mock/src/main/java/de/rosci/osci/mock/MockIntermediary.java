package de.rosci.osci.mock;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

/**
 * A mock OSCI-1.2 intermediary, localhost only, for the e2e suite.
 *
 * It implements the minimum dialogue the client library expects:
 * challenge echo, sequence numbers, feedback code 0 and fresh message ids.
 *
 * Two dialects, auto-detected per request:
 * <ul>
 *   <li><b>Plain</b> (client ran {@code --insecure-transport}): requests are
 *       answered with plain SOAP envelopes.</li>
 *   <li><b>Secure</b> (default): requests arrive as OSCI transport-encrypted
 *       MIME packages. The mock decrypts them with the intermediary's
 *       private key (see {@link TransportCrypto}), processes the inner
 *       envelope, and encrypts the response to the client's cipher
 *       certificate — a real cryptographic round trip, not a costume.</li>
 * </ul>
 *
 * Usage: java -jar osci-mock.jar &lt;port&gt; [dumpDir] [--key intermed-cipher.key]
 * Prints "READY" on stdout once listening. Terminates on kill.
 *
 * Dumps, per request N (when dumpDir given):
 * {@code request-N.xml} (raw bytes as received), {@code request-N.inner.xml}
 * (decrypted inner envelope, secure mode only), {@code request-N.meta}
 * ({@code transport_encrypted: true|false}).
 */
public final class MockIntermediary
{
  private static final String SOAP_NS = "http://schemas.xmlsoap.org/soap/envelope/";
  private static final String OSCI_NS = "http://www.osci.de/2002/04/osci";
  private static final String XSD_ENC_SIG =
    "http://www.w3.org/2000/09/xmldsig# oscisig.xsd http://www.w3.org/2001/04/xmlenc# oscienc.xsd";

  /** Canned postbox content, served on every fetchDelivery. */
  private static final String FETCH_ATTACHMENT_ID = "mock-antwort.xta";
  private static final String FETCH_ATTACHMENT_BODY =
    "<?xml version=\"1.0\"?><XTA><antwort>die behoerde dankt fuer die nachricht"
    + " und wird sich melden. vermutlich per fax.</antwort></XTA>";

  /** The encrypted twin: served inline inside a sealed xenc:EncryptedData block. */
  private static final String FETCH_ENCRYPTED_ATTACHMENT_BODY =
    "<?xml version=\"1.0\"?><XTA><antwort>streng vertrauliche antwort, nur mit"
    + " dem privaten schluessel zu lesen.</antwort></XTA>";

  /** Id of the reader role the encrypted content's key reference points at. */
  private static final String READER_ROLE_ID = "mock_reader_cipher_1";

  private static final SecureRandom RANDOM = new SecureRandom();
  private static final AtomicInteger MESSAGE_IDS = new AtomicInteger(1);
  private static final AtomicInteger REQUEST_COUNTER = new AtomicInteger(1);

  private static Path dumpDir = null;
  private static TransportCrypto crypto = null;
  private static ResponseSigner signer = null;
  /** Test mode: corrupt the response signature to exercise the client's verification failure path. */
  private static boolean tamperSignature = false;
  private static final java.util.concurrent.atomic.AtomicReference<java.security.cert.X509Certificate>
    LAST_CLIENT_CERT = new java.util.concurrent.atomic.AtomicReference<>();

  public static void main(String[] args) throws IOException
  {
    if (args.length < 1)
    {
      System.err.println(
        "usage: MockIntermediary <port> [dumpDir] [--key <pkcs8.pem>] [--sign-key <pkcs8.pem> --sign-cert <cert.pem>]");
      System.exit(2);
    }
    int port = Integer.parseInt(args[0]);
    for (String arg : args)
    {
      if ("--tamper-signature".equals(arg))
      {
        tamperSignature = true;
        System.err.println("mock: signature tampering armed (responses will fail verification)");
      }
    }
    for (int i = 1 ; i < args.length - 1 ; i++)
    {
      if ("--key".equals(args[i]))
      {
        crypto = TransportCrypto.fromPkcs8Pem(Path.of(args[i + 1]));
        System.err.println("mock: secure mode armed (intermediary key loaded)");
      }
      else if ("--sign-key".equals(args[i]))
      {
        Path key = Path.of(args[i + 1]);
        // The matching certificate is expected right after --sign-cert.
        for (int j = 1 ; j < args.length - 1 ; j++)
        {
          if ("--sign-cert".equals(args[j]))
          {
            signer = ResponseSigner.fromPem(key, Path.of(args[j + 1]));
            System.err.println("mock: response signing armed (supplier key loaded)");
          }
        }
      }
    }
    if (args.length > 1 && !args[1].startsWith("--"))
    {
      dumpDir = Path.of(args[1]);
      Files.createDirectories(dumpDir);
    }

    HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", port), 0);
    server.createContext("/", MockIntermediary::handle);
    server.setExecutor(null);
    server.start();
    System.out.println("READY");
    System.out.flush();
  }

  private static void handle(HttpExchange exchange) throws IOException
  {
    try
    {
      byte[] body = exchange.getRequestBody().readAllBytes();
      // Lossy on purpose: only the ASCII XML part is inspected; the binary
      // cipher part keeps its real bytes in `body`.
      String request = new String(body, StandardCharsets.UTF_8);
      int n = REQUEST_COUNTER.getAndIncrement();
      dump("request-" + n + ".xml", new String(body, StandardCharsets.ISO_8859_1));

      byte[] out;
      if (TransportCrypto.isEncryptedTransport(request))
      {
        if (crypto == null)
          throw new IOException("request is transport-encrypted but the mock was started without --key");
        byte[] inner = crypto.decryptRequest(body);
        // Byte-exact: the decrypted envelope is UTF-8, and dump() re-encodes
        // through Latin-1 — correct for the raw transport dumps (byte
        // bijection) but lossy/mojibake for this inner document, whose XML
        // declaration still says utf-8. Write the raw bytes.
        dumpBytes("request-" + n + ".inner.xml", inner);
        writeMeta(n, true);
        String innerXml = new String(inner, StandardCharsets.UTF_8);
        rememberClientCert(innerXml);

        java.security.cert.X509Certificate clientCipher = LAST_CLIENT_CERT.get();
        if (clientCipher == null)
          throw new IOException("no client cipher certificate seen yet "
                                + "(first message of this client carried none)");

        String plainResponse = respondTo(innerXml);
        out = crypto.encryptResponse(plainResponse.getBytes(StandardCharsets.UTF_8), clientCipher);
      }
      else
      {
        writeMeta(n, false);
        // Plain dialect: remember the client too, so the canned fetch can
        // carry content encrypted to the fetcher even without transport crypto.
        rememberClientCert(request);
        out = respondTo(request).getBytes(StandardCharsets.UTF_8);
      }

      // The MIME headers (with the boundary) travel inside the body — the
      // client's MIMEParser reads them from the stream, not from HTTP.
      dump("response-" + n + ".xml", new String(out, StandardCharsets.ISO_8859_1));
      exchange.getResponseHeaders().set("Content-Type", "Multipart/Related; type=text/xml");
      exchange.sendResponseHeaders(200, out.length);
      try (OutputStream os = exchange.getResponseBody())
      {
        os.write(out);
      }
    }
    catch (Exception e)
    {
      System.err.println("mock intermediary choked: " + e);
      e.printStackTrace();
      byte[] fault = ("mock error: " + e).getBytes(StandardCharsets.UTF_8);
      exchange.sendResponseHeaders(500, fault.length);
      try (OutputStream os = exchange.getResponseBody())
      {
        os.write(fault);
      }
    }
  }

  private static void writeMeta(int n, boolean encrypted)
  {
    if (dumpDir == null)
      return;
    try
    {
      Files.writeString(dumpDir.resolve("request-" + n + ".meta"),
                        "transport_encrypted: " + encrypted + "\n");
    }
    catch (IOException e)
    {
      System.err.println("cannot write meta: " + e);
    }
  }

  /**
   * Not every message type advertises the originator's cipher certificate
   * (initDialog, for one, keeps its pockets empty), so the mock remembers
   * the last one it saw — the registration-table memory of a proper
   * intermediary, minus the paperwork.
   */
  private static void rememberClientCert(String xml)
  {
    try
    {
      String certB64 = TransportCrypto.clientCipherCertB64(xml);
      if (certB64 != null)
        LAST_CLIENT_CERT.set(TransportCrypto.certFromB64(certB64));
    }
    catch (IOException e)
    {
      System.err.println("mock: cannot remember client cert: " + e);
    }
  }

  private static void dumpBytes(String name, byte[] content) throws IOException
  {
    if (dumpDir == null)
      return;
    Files.write(dumpDir.resolve(name), content);
  }

  private static void dump(String name, String content)
  {
    if (dumpDir == null)
      return;
    try
    {
      // ISO-8859-1 chars map 1:1 to the bytes we derived them from; writing
      // them as raw bytes keeps binary parts byte-exact for inspection.
      Files.write(dumpDir.resolve(name), content.getBytes(StandardCharsets.ISO_8859_1));
    }
    catch (IOException e)
    {
      System.err.println("cannot dump " + name + ": " + e);
    }
  }

  private static String respondTo(String request) throws IOException
  {
    String type = detectType(request);

    // Control-block contract, per DialogHandler.checkControlBlock:
    //  - the response's <Response> must echo the request's <Challenge>,
    //  - the response's ConversationId must equal the request's,
    //  - the response's SequenceNumber must equal the request's (the
    //    supplier-side counter is a different counter — classic OSCI).
    // SequenceNumber mirrors the request attribute exactly — including its
    // absence (InitDialog sends none; inventing one fails check[3]==0).
    String seqAttr = attr(request, "SequenceNumber", null);
    String echoedChallenge = element(request, "Challenge");
    // InitDialog requests carry no ConversationId, so the response assigns
    // one — digits only, because the schema's ControlBlock pattern is \d+
    // and every later request (orders AND ExitDialog) echoes it back.
    String conversationId = attr(request, "ConversationId",
                                 String.valueOf(System.currentTimeMillis()));

    // Response layouts are NOT uniform: some response elements live in the
    // SOAP body, others in the SOAP header. We follow each builder's
    // expectations to the letter, because the parser certainly does.
    String xsd;
    String headerExtras = "";
    String bodyContent = "";
    List<String[]> extraParts = new ArrayList<>();
    switch (type)
    {
      case "getMessageId":
        xsd = "soapResponseToGetMessageId.xsd";
        bodyContent = bodyElement("responseToGetMessageId", "",
                                  "<osci:MessageId>" + b64("mock-msgid-" + MESSAGE_IDS.getAndIncrement())
                                  + "</osci:MessageId>");
        break;
      case "storeDelivery":
      {
        // Header layout, and the receipt's message id hides inside a
        // ProcessCardBundle — ResponseToStoreDelivery.getMessageId() reads
        // it from there or throws. Naturally.
        xsd = "soapResponseToStoreDelivery.xsd";
        String msgId = element(request, "MessageId");
        if (msgId == null)
          msgId = b64("mock-msgid-" + MESSAGE_IDS.get());
        headerExtras = bodyElement("responseToStoreDelivery", " Id=\"rsp-1\"",
                                   FEEDBACK
                                   + "<osci:ProcessCardBundle><osci:ProcessCard><osci:MessageId>"
                                   + msgId + "</osci:MessageId></osci:ProcessCard>"
                                   + "</osci:ProcessCardBundle>");
        break;
      }
      case "initDialog":
        xsd = "soapResponseToInitDialog.xsd";
        bodyContent = bodyElement("responseToInitDialog", "", FEEDBACK);
        break;
      case "exitDialog":
        xsd = "soapResponseToExitDialog.xsd";
        bodyContent = bodyElement("responseToExitDialog", "", FEEDBACK);
        break;
      case "fetchDelivery":
      {
        // Header layout, and a canned message in the postbox with BOTH
        // dialects of content: a plain attachment-referencing container and
        // an xenc:EncryptedData block sealed to the fetching client — so
        // the bridge's decrypt path gets exercised like a real postbox.
        xsd = "soapResponseToFetchDelivery.xsd";
        String encryptedBlock = encryptedContentBlock();
        if (encryptedBlock != null)
        {
          headerExtras = readerRoleHeader() + bodyElement("responseToFetchDelivery",
                                                          " Id=\"rsp-1\"", FEEDBACK);
          bodyContent = "  <osci:ContentPackage><osci:ContentContainer Id=\"mock-cc-1\">"
                        + "<osci:Content Id=\"mock-c-1\" href=\"cid:" + FETCH_ATTACHMENT_ID
                        + "\"></osci:Content></osci:ContentContainer>"
                        + encryptedBlock + "</osci:ContentPackage>";
          extraParts.add(new String[]{FETCH_ATTACHMENT_ID, FETCH_ATTACHMENT_BODY});
        }
        else
        {
          // No client cert remembered yet: plain content only.
          headerExtras = bodyElement("responseToFetchDelivery", " Id=\"rsp-1\"", FEEDBACK);
          bodyContent = "  <osci:ContentPackage><osci:ContentContainer Id=\"mock-cc-1\">"
                        + "<osci:Content Id=\"mock-c-1\" href=\"cid:" + FETCH_ATTACHMENT_ID
                        + "\"></osci:Content></osci:ContentContainer></osci:ContentPackage>";
          extraParts.add(new String[]{FETCH_ATTACHMENT_ID, FETCH_ATTACHMENT_BODY});
        }
        break;
      }
      case "fetchProcessCard":
      {
        // A canned but honest Laufzettel: one card for the requested
        // message id, with a plain creation timestamp and a subject.
        xsd = "soapResponseToFetchProcessCard.xsd";
        String msgId = element(request, "MessageId");
        if (msgId == null)
          msgId = b64("mock-msgid-unknown");
        bodyContent = bodyElement(
            "responseToFetchProcessCard", "", FEEDBACK
            + "<osci:ProcessCardBundle><osci:ProcessCard><osci:MessageId>"
            + msgId + "</osci:MessageId><osci:Creation><osci:Plain>"
            + "2026-09-30T08:15:00Z" + "</osci:Plain></osci:Creation>"
            + "<osci:Subject>mock laufzettel: alles seinen gang gegangen</osci:Subject>"
            + "</osci:ProcessCard></osci:ProcessCardBundle>");
        break;
      }
      default:
        throw new IllegalArgumentException("mock does not know this request type: " + type);
    }

    return envelope(bodyContent, headerExtras, xsd, seqAttr, conversationId, echoedChallenge,
                    extraParts);
  }

  /**
   * Builds the xenc:EncryptedData block for the canned fetch message: a
   * sealed inner ContentContainer (inline CipherValues, key referenced via
   * RetrievalMethod to the reader role header), or null when no client
   * cipher certificate has been remembered yet.
   */
  private static String encryptedContentBlock() throws IOException
  {
    java.security.cert.X509Certificate client = LAST_CLIENT_CERT.get();
    if (client == null || crypto == null)
      return null;

    // Inline Base64Content, not an attachment reference: the decrypted
    // inner container is parsed as a fresh message that cannot resolve
    // outer-message attachment hrefs — real encrypted contents ride inline
    // for exactly this reason.
    String innerContainer = "<osci:ContentContainer xmlns:ds=\"" + TransportCrypto.DS_NS + "\""
                            + " xmlns:osci=\"http://www.osci.de/2002/04/osci\""
                            + " xmlns:xenc=\"" + TransportCrypto.XENC_NS + "\""
                            + " Id=\"mock-cc-enc\">"
                            + "<osci:Base64Content Id=\"mock-c-enc\">"
                            + Base64.getEncoder()
                                    .encodeToString(FETCH_ENCRYPTED_ATTACHMENT_BODY.getBytes(StandardCharsets.UTF_8))
                            + "</osci:Base64Content></osci:ContentContainer>";
    TransportCrypto.Sealed sealed = crypto.seal(innerContainer.getBytes(StandardCharsets.UTF_8), client);
    String keyB64 = Base64.getEncoder().encodeToString(sealed.wrappedKey());
    String blobB64 = Base64.getEncoder().encodeToString(sealed.blob());
    String readerId = READER_ROLE_ID;

    return "<xenc:EncryptedData Id=\"mock-encdata\" MimeType=\"text/xml\">"
           + "<xenc:EncryptionMethod Algorithm=\"" + TransportCrypto.AES256_GCM + "\">"
           + "<osci128:IvLength xmlns:osci128=\"" + TransportCrypto.OSCI128_NS + "\" Value=\"12\">"
           + "</osci128:IvLength></xenc:EncryptionMethod>"
           + "<ds:KeyInfo><xenc:EncryptedKey>"
           + "<xenc:EncryptionMethod Algorithm=\"" + TransportCrypto.RSA_OAEP + "\">"
           + "<xenc11:MGF xmlns:xenc11=\"" + TransportCrypto.XENC11_NS + "\" Algorithm=\""
           + TransportCrypto.MGF1_SHA256 + "\"></xenc11:MGF>"
           + "<ds:DigestMethod Algorithm=\"" + TransportCrypto.DIGEST_SHA256 + "\">"
           + "</ds:DigestMethod></xenc:EncryptionMethod>"
           + "<ds:KeyInfo><ds:RetrievalMethod Type=\"http://www.w3.org/2000/09/xmldsig#X509Data\""
           + " URI=\"#" + readerId + "\"></ds:RetrievalMethod></ds:KeyInfo>"
           + "<xenc:CipherData><xenc:CipherValue>" + keyB64 + "</xenc:CipherValue></xenc:CipherData>"
           + "</xenc:EncryptedKey></ds:KeyInfo>"
           + "<xenc:CipherData><xenc:CipherValue>" + blobB64 + "</xenc:CipherValue></xenc:CipherData>"
           + "</xenc:EncryptedData>";
  }

  /** The reader role header the encrypted content's RetrievalMethod points at. */
  private static String readerRoleHeader() throws IOException
  {
    java.security.cert.X509Certificate client = LAST_CLIENT_CERT.get();
    if (client == null)
      return "";
    String certB64;
    try
    {
      certB64 = Base64.getEncoder().encodeToString(client.getEncoded());
    }
    catch (Exception e)
    {
      throw new IOException("cannot encode client cert: " + e, e);
    }
    return "<osci:NonIntermediaryCertificates Id=\"nonintermediarycertificates\""
           + " soap:actor=\"http://www.w3.org/2001/12/soap-envelope/actor/none\" soap:mustUnderstand=\"1\">"
           + "<osci:CipherCertificateOtherReader Id=\"" + READER_ROLE_ID + "\">"
           + "<ds:X509Data><ds:X509Certificate>" + certB64 + "</ds:X509Certificate></ds:X509Data>"
           + "</osci:CipherCertificateOtherReader></osci:NonIntermediaryCertificates>";
  }

  private static String detectType(String request)
  {
    for (String candidate : new String[]{"getMessageId", "storeDelivery", "initDialog",
                                         "fetchDelivery", "fetchProcessCard", "exitDialog",
                                         "acceptDelivery", "processDelivery", "forwardDelivery"})
    {
      Pattern p = Pattern.compile("<\\w*:" + candidate + "[\\s>]");
      if (p.matcher(request).find())
        return candidate;
    }
    throw new IllegalArgumentException("unrecognized OSCI request");
  }

  private static final String FEEDBACK =
    "<osci:Feedback><osci:Entry xml:lang=\"de\"><osci:Code>0</osci:Code>"
    + "<osci:Text>die nachricht wurde entgegengenommen. schoenen tag noch.</osci:Text>"
    + "</osci:Entry></osci:Feedback>";

  private static String envelope(String bodyContent, String headerExtras, String xsdName,
                                 String seqAttr, String conversationId, String echoedChallenge,
                                 List<String[]> extraParts) throws IOException
  {
    String freshChallenge = b64("challenge-" + RANDOM.nextInt(1_000_000));
    String responseElement = (echoedChallenge == null || echoedChallenge.isBlank())
      ? "" : "<osci:Response>" + echoedChallenge + "</osci:Response>";
    // Absent SequenceNumber stays absent (InitDialog semantics).
    String seqPart = (seqAttr == null) ? "" : " SequenceNumber=\"" + seqAttr + "\"";
    // The message-type marker (xsi:schemaLocation) rides on the Envelope
    // element itself — the client's parser reads it there, which the
    // request dump confirms twice over.
    String schemaLocation = SOAP_NS + " " + xsdName + " " + XSD_ENC_SIG;
    String xml = """
        <?xml version="1.0" encoding="utf-8"?>
        <soap:Envelope xmlns:ds="%s" xmlns:soap="%s" xmlns:osci="%s" xmlns:xenc="%s" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="%s">
         <soap:Header>
          <osci:ControlBlock Id="cb-1" ConversationId="%s"%s>%s
           <osci:Challenge>%s</osci:Challenge>
          </osci:ControlBlock>
        %s
         </soap:Header>
         <soap:Body Id="Body">
        %s
         </soap:Body>
        </soap:Envelope>
        """.formatted(TransportCrypto.DS_NS, SOAP_NS, OSCI_NS, TransportCrypto.XENC_NS,
                      schemaLocation, conversationId, seqPart, responseElement,
                      freshChallenge, headerExtras, bodyContent);

    // Signed dialect: sign before MIME framing, so the Content-Length
    // below covers the signed envelope (attachments included as cid refs).
    if (signer != null)
    {
      xml = signer.sign(xml, extraParts);
      if (tamperSignature)
      {
        // Flip the first base64 character of the SignatureValue: still
        // well-formed XML, cryptographically garbage. The client's
        // automatic verification must reject this loudly.
        int pos = xml.indexOf("<ds:SignatureValue>") + "<ds:SignatureValue>".length();
        char flipped = xml.charAt(pos) == 'A' ? 'B' : 'A';
        xml = xml.substring(0, pos) + flipped + xml.substring(pos + 1);
      }
    }

    // The client's response parser insists on full MIME framing — headers,
    // boundary, part headers, exact Content-Length. The request dump is the
    // blueprint; we speak the dialect the library itself speaks. Fetched
    // attachments ride as additional parts after the envelope.
    String boundary = "MIME_boundary_mock_" + Long.toHexString(RANDOM.nextLong());
    byte[] xmlBytes = xml.getBytes(StandardCharsets.UTF_8);
    StringBuilder parts = new StringBuilder();
    for (String[] part : extraParts)
    {
      parts.append(attachmentPart(boundary, part[0], part[1]));
    }
    return "MIME-Version: 1.0\r\n"
           + "Content-Type: Multipart/Related; boundary=" + boundary + "; type=text/xml\r\n"
           + "\r\n"
           + "--" + boundary + "\r\n"
           + "Content-Type: text/xml; charset=UTF-8\r\n"
           + "Content-Transfer-Encoding: 8bit\r\n"
           + "Content-ID: <osci@message>\r\n"
           + "Content-Length: " + xmlBytes.length + "\r\n"
           + "\r\n"
           + xml + "\r\n"
           + parts
           + "--" + boundary + "--\r\n";
  }

  /** Renders the attachment MIME part for fetched content, or nothing. */
  private static String attachmentPart(String boundary, String partId, String content)
  {
    if (partId == null)
      return "";
    return "--" + boundary + "\r\n"
           + "Content-Type: application/octet-stream\r\n"
           + "Content-Transfer-Encoding: binary\r\n"
           + "Content-ID: <" + partId + ">\r\n"
           + "\r\n"
           + content + "\r\n";
  }

  /** A response element with optional extra attributes and inner XML. */
  private static String bodyElement(String element, String attributes, String inner)
  {
    return "  <osci:" + element + attributes + ">\n"
           + "   " + inner + "\n"
           + "  </osci:" + element + ">";
  }

  private static String b64(String s)
  {
    return Base64.getEncoder().encodeToString(s.getBytes(StandardCharsets.UTF_8));
  }

  private static String element(String xml, String name)
  {
    Pattern p = Pattern.compile("<\\w*:" + name + ">([^<]*)</\\w*:" + name + ">");
    Matcher m = p.matcher(xml);
    return m.find() ? m.group(1) : null;
  }

  private static String attr(String xml, String attr, String dflt)
  {
    Pattern p = Pattern.compile(attr + "=\"([^\"]*)\"");
    Matcher m = p.matcher(xml);
    return m.find() ? m.group(1) : dflt;
  }
}
