package de.deshittifier.osci.bridge;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import de.osci.osci12.OSCIException;
import de.osci.osci12.common.DialogHandler;
import de.osci.osci12.common.Constants;
import de.osci.osci12.messageparts.Attachment;
import de.osci.osci12.messageparts.Content;
import de.osci.osci12.messageparts.ContentContainer;
import de.osci.osci12.messageparts.EncryptedDataOSCI;
import de.osci.osci12.messageparts.Inspection;
import de.osci.osci12.messageparts.ProcessCardBundle;
import de.osci.osci12.messageparts.Timestamp;
import de.osci.osci12.messagetypes.ExitDialog;
import de.osci.osci12.messagetypes.FetchDelivery;
import de.osci.osci12.messagetypes.FetchProcessCard;
import de.osci.osci12.messagetypes.GetMessageId;
import de.osci.osci12.messagetypes.InitDialog;
import de.osci.osci12.messagetypes.OSCIMessage;
import de.osci.osci12.messagetypes.OSCIResponseTo;
import de.osci.osci12.messagetypes.ResponseToFetchDelivery;
import de.osci.osci12.messagetypes.ResponseToFetchProcessCard;
import de.osci.osci12.messagetypes.ResponseToGetMessageId;
import de.osci.osci12.messagetypes.ResponseToStoreDelivery;
import de.osci.osci12.messagetypes.StoreDelivery;
import de.osci.osci12.roles.Addressee;
import de.osci.osci12.roles.Intermed;
import de.osci.osci12.roles.Originator;
import de.osci.osci12.roles.Reader;
import de.deshittifier.osci.bridge.CryptoMaterial.P12Decrypter;
import de.deshittifier.osci.bridge.CryptoMaterial.P12Signer;

/**
 * The three OSCI flows this bridge exposes: send (StoreDelivery), fetch
 * (FetchDelivery) and process-card (FetchProcessCard / the Laufzettel).
 * No hidden state between requests — each request carries everything it
 * needs, the way line protocols intended.
 */
public final class OsciOps
{
  private OsciOps()
  {}

  // ------------------------------------------------------------------ send

  public static Protocol.Result send(Protocol.Request req)
  {
    requireSendShape(req);

    byte[] xta = Base64.getDecoder().decode(req.content.data);

    P12Signer signer = new P12Signer(b64(req.identity.signer_p12),
                                     pin(req.identity.signer_pin), true);
    byte[] decrypterP12 = req.identity.decrypter_p12 != null
      ? b64(req.identity.decrypter_p12) : b64(req.identity.signer_p12);
    String decrypterPin = req.identity.decrypter_pin != null
      ? req.identity.decrypter_pin : req.identity.signer_pin;
    P12Decrypter decrypter = new P12Decrypter(decrypterP12, pin(decrypterPin));

    Originator me = new Originator(signer, decrypter);
    X509Certificate intermedCipher = CryptoMaterial.parseCertificate(req.intermediary.cipher_cert);
    Intermed intermed = new Intermed(null, intermedCipher, URI.create(req.intermediary.url));

    DialogHandler dialog = newDialog(me, intermed, req);

    try
    {
      // Reserve a message id first — the intermediary hands them out like
      // queue numbers at the Amt, and nobody may skip the line.
      ResponseToGetMessageId mid = new GetMessageId(dialog).send();
      checkFeedback(mid);

      X509Certificate recipientCipher = CryptoMaterial.parseCertificate(req.recipient.cipher_cert);
      Addressee to = new Addressee(null, recipientCipher);

      StoreDelivery delivery = new StoreDelivery(dialog, to, mid.getMessageId());
      delivery.setSubject(req.subject != null ? req.subject : "");

      ContentContainer coco = new ContentContainer();
      String filename = req.content.filename != null ? req.content.filename : "message.xta";

      boolean sign = req.sign == null || req.sign;
      boolean encrypt = req.encrypt == null || req.encrypt;

      // Attachments inside an EncryptedDataOSCI must announce their cipher
      // algorithm; plain attachments must not. The library checks, and it
      // is right to — this once.
      Attachment attachment = encrypt
        ? new Attachment(new ByteArrayInputStream(xta), filename,
                         Constants.SYMMETRIC_CIPHER_ALGORITHM_AES256_GCM)
        : new Attachment(new ByteArrayInputStream(xta), filename);
      coco.addContent(new Content(attachment));

      if (sign)
        coco.sign(me);

      if (encrypt)
      {
        EncryptedDataOSCI encrypted = new EncryptedDataOSCI(Constants.SYMMETRIC_CIPHER_ALGORITHM_AES256_GCM,
                                                            coco);
        encrypted.encrypt(new Reader(recipientCipher));
        delivery.addEncryptedData(encrypted);
      }
      else
      {
        delivery.addContentContainer(coco);
      }

      ResponseToStoreDelivery rsp = delivery.send();
      checkFeedback(rsp);

      Protocol.Result result = new Protocol.Result();
      result.message_id = rsp.getMessageId();
      result.feedback = rsp.getFeedback();
      return result;
    }
    catch (IOException e)
    {
      throw new BridgeException(BridgeException.TRANSPORT, e.getMessage());
    }
    catch (OSCIException | GeneralSecurityException e)
    {
      throw new BridgeException(BridgeException.OSCI, e.getMessage());
    }
  }

  // ----------------------------------------------------------------- fetch

  public static Protocol.Result fetch(Protocol.Request req)
  {
    requireDialogShape(req);
    P12Signer signer = new P12Signer(b64(req.identity.signer_p12),
                                     pin(req.identity.signer_pin), true);
    byte[] decrypterP12 = req.identity.decrypter_p12 != null
      ? b64(req.identity.decrypter_p12) : b64(req.identity.signer_p12);
    String decrypterPin = req.identity.decrypter_pin != null
      ? req.identity.decrypter_pin : req.identity.signer_pin;
    P12Decrypter decrypter = new P12Decrypter(decrypterP12, pin(decrypterPin));

    Originator me = new Originator(signer, decrypter);
    Intermed intermed = new Intermed(null,
                                     CryptoMaterial.parseCertificate(req.intermediary.cipher_cert),
                                     URI.create(req.intermediary.url));
    DialogHandler dialog = newDialog(me, intermed, req);

    try
    {
      checkFeedback(new InitDialog(dialog).send());

      FetchDelivery fetch = new FetchDelivery(dialog);
      fetch.setSelectionMode(selectionMode(req.selection_mode));
      if (req.selection_rule != null)
        fetch.setSelectionRule(req.selection_rule);

      ResponseToFetchDelivery rsp = fetch.send();
      checkFeedback(rsp);

      Protocol.Result result = new Protocol.Result();
      result.feedback = rsp.getFeedback();
      List<Protocol.FetchedMessage> messages = new ArrayList<>();

      ContentContainer[] containers = rsp.getContentContainer();
      if (containers != null)
      {
        for (ContentContainer cc : containers)
        {
          Protocol.FetchedMessage m = new Protocol.FetchedMessage();
          m.signatures_valid = signaturesValidQuietly(cc);
          m.contents = new ArrayList<>();
          for (Content c : cc.getContents())
            m.contents.add(toFetchedContent(c, "plain"));
          messages.add(m);
        }
      }

      EncryptedDataOSCI[] encrypted = rsp.getEncryptedData();
      if (encrypted != null)
      {
        for (EncryptedDataOSCI ed : encrypted)
        {
          Protocol.FetchedMessage m = new Protocol.FetchedMessage();
          m.encrypted_contents = new ArrayList<>();
          try
          {
            ContentContainer inner = ed.decrypt(new Reader(decrypter));
            for (Content c : inner.getContents())
              m.encrypted_contents.add(toFetchedContent(c, "encrypted"));
          }
          catch (Exception e)
          {
            // Not encrypted to us, or extraction failed — report and move on,
            // but leave a trace. Silent catches are how mysteries become
            // traditions.
            org.slf4j.LoggerFactory.getLogger(OsciOps.class)
                                  .warn("encrypted content not extractable", e);
            m.subject = "<not decryptable with the supplied identity: " + e + ">";
          }
          messages.add(m);
        }
      }

      result.messages = messages;
      exitDialogQuietly(dialog);
      return result;
    }
    catch (IOException e)
    {
      throw new BridgeException(BridgeException.TRANSPORT, e.getMessage());
    }
    catch (OSCIException | GeneralSecurityException e)
    {
      throw new BridgeException(BridgeException.OSCI, e.getMessage());
    }
  }

  // ---------------------------------------------------------- process-card

  public static Protocol.Result processCard(Protocol.Request req)
  {
    requireDialogShape(req);
    require(req.selection_rule != null, "process-card needs selection_rule (the message id)");

    P12Signer signer = new P12Signer(b64(req.identity.signer_p12),
                                     pin(req.identity.signer_pin), true);
    byte[] decrypterP12 = req.identity.decrypter_p12 != null
      ? b64(req.identity.decrypter_p12) : b64(req.identity.signer_p12);
    String decrypterPin = req.identity.decrypter_pin != null
      ? req.identity.decrypter_pin : req.identity.signer_pin;

    Originator me = new Originator(signer, new P12Decrypter(decrypterP12, pin(decrypterPin)));
    Intermed intermed = new Intermed(null,
                                     CryptoMaterial.parseCertificate(req.intermediary.cipher_cert),
                                     URI.create(req.intermediary.url));
    DialogHandler dialog = newDialog(me, intermed, req);

    try
    {
      checkFeedback(new InitDialog(dialog).send());

      FetchProcessCard fetch = new FetchProcessCard(dialog);
      fetch.setSelectionMode(selectionMode(req.selection_mode != null ? req.selection_mode
                                                                    : "BY_MESSAGE_ID"));
      fetch.setSelectionRule(req.selection_rule);

      ResponseToFetchProcessCard rsp = fetch.send();
      checkFeedback(rsp);

      Protocol.Result result = new Protocol.Result();
      result.feedback = rsp.getFeedback();
      result.process_cards = new ArrayList<>();
      ProcessCardBundle[] bundles = rsp.getProcessCardBundles();
      if (bundles != null)
      {
        for (ProcessCardBundle b : bundles)
        {
          Protocol.ProcessCard card = new Protocol.ProcessCard();
          card.message_id = b.getMessageId();
          card.subject = b.getSubject();
          card.creation = timestamp(b.getCreation());
          card.forwarding = timestamp(b.getForwarding());
          card.reception = timestamp(b.getReception());
          card.inspections = new ArrayList<>();
          Inspection[] inspections = b.getInspections();
          if (inspections != null)
          {
            for (Inspection i : inspections)
            {
              Protocol.Inspection pi = new Protocol.Inspection();
              pi.subject = i.getX509SubjectName();
              pi.issuer = i.getX509IssuerName();
              pi.serial_number = i.getX509SerialNumber();
              pi.online_checked = i.isOnlineChecked();
              pi.timestamp = i.getTimeStamp() != null ? i.getTimeStamp().getTimeStamp() : null;
              card.inspections.add(pi);
            }
          }
          result.process_cards.add(card);
        }
      }
      exitDialogQuietly(dialog);
      return result;
    }
    catch (IOException e)
    {
      throw new BridgeException(BridgeException.TRANSPORT, e.getMessage());
    }
    catch (OSCIException | GeneralSecurityException e)
    {
      throw new BridgeException(BridgeException.OSCI, e.getMessage());
    }
  }

  // ------------------------------------------------------------------ ping

  public static Protocol.Result ping()
  {
    Protocol.Result result = new Protocol.Result();
    Map<String, String> versions = new LinkedHashMap<>();
    versions.put("protocol", Protocol.VERSION);
    versions.put("bridge", Bridge.VERSION);
    versions.put("java", System.getProperty("java.version", "unknown"));
    versions.put("osci_library", osciLibraryVersion());
    versions.put("bouncycastle",
                 new org.bouncycastle.jce.provider.BouncyCastleProvider().getVersionStr());
    result.versions = versions;
    return result;
  }

  private static String osciLibraryVersion()
  {
    try (InputStream in = Bridge.class.getResourceAsStream("/META-INF/maven/de.osci/osci-bibliothek/pom.properties"))
    {
      if (in == null)
        return "unknown";
      Properties props = new Properties();
      props.load(in);
      return props.getProperty("version", "unknown");
    }
    catch (IOException e)
    {
      return "unknown";
    }
  }

  // --------------------------------------------------------------- helpers

  /**
   * Builds the dialog handler, honoring the insecure-transport test mode:
   * SOAP-envelope encryption and transport signatures off, everything else
   * (content signing, content encryption) untouched.
   */
  private static DialogHandler newDialog(Originator me, Intermed intermed, Protocol.Request req)
  {
    DialogHandler dialog = new DialogHandler(me, intermed, new BridgeTransport(req.tls));
    if (Boolean.FALSE.equals(req.insecure_transport))
    {
      dialog.setEncryption(false);
      dialog.setCreateSignatures(false);
    }
    return dialog;
  }

  private static void requireSendShape(Protocol.Request req)
  {
    requireDialogShape(req);
    require(req.recipient != null && req.recipient.cipher_cert != null,
            "send needs recipient.cipher_cert");
    require(req.content != null && req.content.data != null, "send needs content.data (base64)");
  }

  private static void requireDialogShape(Protocol.Request req)
  {
    require(req.intermediary != null && req.intermediary.url != null, "missing intermediary.url");
    require(req.intermediary.cipher_cert != null, "missing intermediary.cipher_cert");
    require(req.identity != null && req.identity.signer_p12 != null, "missing identity.signer_p12");
  }

  private static void require(boolean cond, String message)
  {
    if (!cond)
      throw new BridgeException(BridgeException.PROTOCOL, message);
  }

  private static byte[] b64(String s)
  {
    try
    {
      return Base64.getDecoder().decode(s);
    }
    catch (IllegalArgumentException e)
    {
      throw new BridgeException(BridgeException.PROTOCOL, "invalid base64 payload");
    }
  }

  private static char[] pin(String s)
  {
    return s == null ? new char[0] : s.toCharArray();
  }

  private static int selectionMode(String mode)
  {
    if (mode == null || "BY_MESSAGE_ID".equals(mode))
      return OSCIMessage.SELECT_BY_MESSAGE_ID;
    switch (mode)
    {
      case "ALL": return OSCIMessage.SELECT_ALL;
      case "BY_DATE_OF_RECEPTION": return OSCIMessage.SELECT_BY_DATE_OF_RECEPTION;
      case "BY_RECENT_MODIFICATION": return OSCIMessage.SELECT_BY_RECENT_MODIFICATION;
      default:
        throw new BridgeException(BridgeException.PROTOCOL, "unknown selection_mode: " + mode);
    }
  }

  private static void checkFeedback(OSCIResponseTo rsp)
  {
    String[][] feedback = rsp.getFeedback();
    if (feedback == null)
      return;
    for (String[] row : feedback)
    {
      // Row layout per library convention: [text, code]. Codes starting with
      // '0' are the OSCI way of saying "yes, fine, everything ok, next please".
      if (row.length > 1 && row[1] != null && !row[1].startsWith("0"))
        throw new BridgeException(BridgeException.OSCI,
                                  "intermediary rejected the request: " + rowText(row),
                                  feedback);
    }
  }

  private static String rowText(String[] row)
  {
    return "code=" + (row.length > 1 ? row[1] : "?")
           + (row.length > 0 && row[0] != null ? " (" + row[0] + ")" : "");
  }

  private static Boolean signaturesValidQuietly(ContentContainer cc)
  {
    try
    {
      return cc.checkAllSignatures();
    }
    catch (Exception e)
    {
      return false;
    }
  }

  private static Protocol.FetchedContent toFetchedContent(Content c, String container)
  {
    Protocol.FetchedContent fc = new Protocol.FetchedContent();
    fc.container = container;
    try
    {
      switch (c.getContentType())
      {
        case Content.DATA:
          fc.filename = null;
          fc.content_type = "text/plain; charset=utf-8";
          fc.data = Base64.getEncoder()
                          .encodeToString(c.getContentData().getBytes(StandardCharsets.UTF_8));
          break;
        case Content.ATTACHMENT_REFERENCE:
          Attachment a = c.getAttachment();
          fc.filename = a.getRefID();
          fc.content_type = a.getContentType();
          try (InputStream in = a.getStream())
          {
            fc.data = Base64.getEncoder().encodeToString(in.readAllBytes());
          }
          break;
        default:
          fc.filename = null;
          fc.content_type = "application/octet-stream";
          fc.data = Base64.getEncoder()
                          .encodeToString(c.getContentStream().readAllBytes());
          break;
      }
    }
    catch (IOException | de.osci.osci12.OSCIException e)
    {
      throw new BridgeException(BridgeException.INTERNAL, "cannot read fetched content: " + e.getMessage());
    }
    return fc;
  }

  private static String timestamp(Timestamp t)
  {
    return t == null ? null : t.getTimeStamp();
  }

  private static void exitDialogQuietly(DialogHandler dialog)
  {
    // The polite goodbye. If it fails, the dialog dies of natural causes anyway.
    try
    {
      new ExitDialog(dialog).send();
    }
    catch (Exception e)
    {
      // ignored on purpose
    }
  }
}
