package de.deshittifier.osci.mock;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

/**
 * A mock OSCI-1.2 intermediary,localhost only, for the e2e suite.
 *
 * It implements the minimum dialogue the client library expects:
 * challenge echo, sequence numbers, feedback code 0 and fresh message ids.
 * The response envelopes are plain (unencrypted, unsigned) SOAP — exactly
 * enough structure for the client's parser, without a single line of
 * CMS cryptography on this side. If a real intermediary ever behaved
 * this laxly, someone should write a strongly worded letter.
 *
 * Usage: java -jar osci-mock.jar &lt;port&gt; [dumpDir]
 * Prints "READY" on stdout once listening. Terminates on kill.
 */
public final class MockIntermediary
{
  private static final String SOAP_NS = "http://schemas.xmlsoap.org/soap/envelope/";
  private static final String OSCI_NS = "http://www.osci.de/2002/04/osci";
  private static final String XSD_ENC_SIG =
    "http://www.w3.org/2000/09/xmldsig# oscisig.xsd http://www.w3.org/2001/04/xmlenc# oscienc.xsd";

  private static final SecureRandom RANDOM = new SecureRandom();
  private static final AtomicInteger MESSAGE_IDS = new AtomicInteger(1);

  private static Path dumpDir = null;

  public static void main(String[] args) throws IOException
  {
    if (args.length < 1)
    {
      System.err.println("usage: MockIntermediary <port> [dumpDir]");
      System.exit(2);
    }
    int port = Integer.parseInt(args[0]);
    if (args.length > 1)
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
      String request = new String(body, StandardCharsets.UTF_8);
      dump(request);

      String response = respondTo(request);
      byte[] out = response.getBytes(StandardCharsets.UTF_8);
      // The MIME headers (with the boundary) travel inside the body — the
      // client's MIMEParser reads them from the stream, not from HTTP.
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

  private static void dump(String request)
  {
    if (dumpDir == null)
      return;
    try
    {
      Path file = dumpDir.resolve("request-" + MESSAGE_IDS.get() + ".xml");
      Files.writeString(file, request);
    }
    catch (IOException e)
    {
      System.err.println("cannot dump request: " + e);
    }
  }

  private static String respondTo(String request)
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
    String conversationId = attr(request, "ConversationId", "mock-conversation");

    // Response layouts are NOT uniform: some response elements live in the
    // SOAP body, others in the SOAP header. We follow each builder's
    // expectations to the letter, because the parser certainly does.
    String xsd;
    String headerExtras = "";
    String bodyContent = "";
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
        // Header layout, empty postbox: feedback only, no content package.
        xsd = "soapResponseToFetchDelivery.xsd";
        headerExtras = bodyElement("responseToFetchDelivery", " Id=\"rsp-1\"", FEEDBACK);
        break;
      case "fetchProcessCard":
        // No Laufzettel on file. The honest bureaucracy: nothing happened.
        xsd = "soapResponseToFetchProcessCard.xsd";
        bodyContent = bodyElement("responseToFetchProcessCard", "", FEEDBACK);
        break;
      default:
        throw new IllegalArgumentException("mock does not know this request type: " + type);
    }

    return envelope(bodyContent, headerExtras, xsd, seqAttr, conversationId, echoedChallenge);
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
                                 String seqAttr, String conversationId, String echoedChallenge)
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
        <soap:Envelope xmlns:soap="%s" xmlns:osci="%s" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="%s">
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
        """.formatted(SOAP_NS, OSCI_NS, schemaLocation, conversationId, seqPart, responseElement,
                      freshChallenge, headerExtras, bodyContent);

    // The client's response parser insists on full MIME framing — headers,
    // boundary, part headers, exact Content-Length. The request dump is the
    // blueprint; we speak the dialect the library itself speaks.
    String boundary = "MIME_boundary_mock_" + Long.toHexString(RANDOM.nextLong());
    byte[] xmlBytes = xml.getBytes(StandardCharsets.UTF_8);
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
           + "--" + boundary + "--\r\n";
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
