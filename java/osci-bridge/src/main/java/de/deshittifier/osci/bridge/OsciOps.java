package de.deshittifier.osci.bridge;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URI;
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
import de.osci.osci12.messageparts.ChunkInformation;
import de.osci.osci12.messageparts.Content;
import de.osci.osci12.messageparts.ContentContainer;
import de.osci.osci12.messageparts.EncryptedDataOSCI;
import de.osci.osci12.messageparts.Inspection;
import de.osci.osci12.messageparts.MessageMetaDataCustomHeader;
import de.osci.osci12.messageparts.ProcessCardBundle;
import de.osci.osci12.messageparts.Timestamp;
import eu.osci.ws._2014._10.transport.DestinationsType;
import eu.osci.ws._2014._10.transport.MessageMetaData;
import eu.osci.ws._2014._10.transport.MsgIdentificationType;
import eu.osci.ws._2014._10.transport.OriginatorsType;
import eu.osci.ws._2014._10.transport.PartyIdentifierType;
import eu.osci.ws._2014._10.transport.PartyType;
import de.osci.osci12.messagetypes.ExitDialog;
import de.osci.osci12.messagetypes.FetchDelivery;
import de.osci.osci12.messagetypes.FetchProcessCard;
import de.osci.osci12.messagetypes.GetMessageId;
import de.osci.osci12.messagetypes.InitDialog;
import de.osci.osci12.messagetypes.OSCIMessage;
import de.osci.osci12.messagetypes.OSCIResponseTo;
import de.osci.osci12.messagetypes.PartialFetchDelivery;
import de.osci.osci12.messagetypes.PartialStoreDelivery;
import de.osci.osci12.messagetypes.ResponseToFetchAbstract;
import de.osci.osci12.messagetypes.ResponseToFetchDelivery;
import de.osci.osci12.messagetypes.ResponseToFetchProcessCard;
import de.osci.osci12.messagetypes.ResponseToGetMessageId;
import de.osci.osci12.messagetypes.ResponseToPartialFetchDelivery;
import de.osci.osci12.messagetypes.ResponseToPartialStoreDelivery;
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
                                     pin(req.identity.signer_pin));
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

      // XTA MessageMetaData (Ergänzung): author/reader identification plus
      // the automatic message identification and size. Only attached when
      // at least one identifier was configured — an empty custom header is
      // ceremony without content.
      if (req.metadata_author != null || req.metadata_reader != null)
      {
        MessageMetaData mmd = new MessageMetaData();
        if (req.metadata_author != null)
        {
          PartyIdentifierType authorId = new PartyIdentifierType();
          authorId.setType("xoev");
          authorId.setValue(req.metadata_author);
          PartyType author = new PartyType();
          author.setIdentifier(authorId);
          OriginatorsType originators = new OriginatorsType();
          originators.setAuthor(author);
          mmd.setOriginators(originators);
        }
        if (req.metadata_reader != null)
        {
          PartyIdentifierType readerId = new PartyIdentifierType();
          readerId.setType("xoev");
          readerId.setValue(req.metadata_reader);
          PartyType reader = new PartyType();
          reader.setIdentifier(readerId);
          DestinationsType destinations = new DestinationsType();
          destinations.setReader(reader);
          mmd.setDestinations(destinations);
        }
        MsgIdentificationType identification = new MsgIdentificationType();
        org.apache.cxf.ws.addressing.AttributedURIType messageIdUri =
          new org.apache.cxf.ws.addressing.AttributedURIType();
        messageIdUri.setValue(mid.getMessageId());
        identification.setMessageID(messageIdUri);
        mmd.setMsgIdentification(identification);
        mmd.setMsgSize(java.math.BigInteger.valueOf(xta.length));
        delivery.addCustomHeaderExtention(new MessageMetaDataCustomHeader(mmd));
      }

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

      // Optional additional attachments: same container, same cipher
      // treatment as the main content, each with its own symmetric key
      // (the library generates one per Attachment).
      if (req.attachments != null)
      {
        int n = 1;
        for (Protocol.Payload att : req.attachments)
        {
          String refId = att.filename != null && !att.filename.isBlank()
            ? att.filename : "attachment-" + n;
          byte[] attBytes = Base64.getDecoder().decode(att.data);
          Attachment a = encrypt
            ? new Attachment(new ByteArrayInputStream(attBytes), refId,
                             Constants.SYMMETRIC_CIPHER_ALGORITHM_AES256_GCM)
            : new Attachment(new ByteArrayInputStream(attBytes), refId);
          if (att.content_type != null && !att.content_type.isBlank())
            a.setContentType(att.content_type);
          coco.addContent(new Content(a));
          n++;
        }
      }

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

      Protocol.Result result = new Protocol.Result();

      if (req.chunk_size_kb != null && req.chunk_size_kb > 0)
      {
        // EFFI chunked transfer: serialize the fully built StoreDelivery
        // (content, attachments, signatures, encryption and all), split it
        // and ship each chunk as a PartialStoreDelivery carrying the same
        // message id. The intermediary reassembles on its side; the last
        // chunk's response carries the inside feedback of the reassembled
        // StoreDelivery and its process card.
        ByteArrayOutputStream assembled = new ByteArrayOutputStream();
        delivery.writeMessage(assembled);
        byte[] full = assembled.toByteArray();
        int chunkBytes = req.chunk_size_kb.intValue() * 1024;
        int totalChunks = (int) Math.max(1L, (full.length + (long) chunkBytes - 1) / chunkBytes);
        long totalKb = full.length / 1024;

        ResponseToPartialStoreDelivery last = null;
        for (int i = 1; i <= totalChunks; i++)
        {
          int from = (i - 1) * chunkBytes;
          int len = (int) Math.min((long) chunkBytes, full.length - (long) from);
          ChunkInformation info = new ChunkInformation(req.chunk_size_kb, i, totalKb, totalChunks);
          PartialStoreDelivery partial =
            new PartialStoreDelivery(dialog, to, info, mid.getMessageId());
          partial.setChunkBlob(new ByteArrayInputStream(full, from, len));
          last = partial.send();
          checkFeedback(last);
        }

        // The reassembled StoreDelivery's own feedback is what the user
        // cares about; the chunk acks before it are bookkeeping.
        String[][] inside = last.getInsideFeedback();
        result.feedback = toProtocolFeedback(inside != null ? inside : last.getFeedback());
        result.message_id = mid.getMessageId();
        result.response_signed = last.isSigned();
        return result;
      }

      ResponseToStoreDelivery rsp = delivery.send();
      checkFeedback(rsp);

      result.message_id = rsp.getMessageId();
      result.feedback = toProtocolFeedback(rsp.getFeedback());
      result.response_signed = rsp.isSigned();
      return result;
    }
    catch (IOException e)
    {
      throw new BridgeException(BridgeException.TRANSPORT, e.getMessage());
    }
    catch (OSCIException | GeneralSecurityException e)
    {
      throw new BridgeException(BridgeException.OSCI,
                                  e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName());
    }
  }

  // ----------------------------------------------------------------- fetch

  public static Protocol.Result fetch(Protocol.Request req)
  {
    requireDialogShape(req);
    P12Signer signer = new P12Signer(b64(req.identity.signer_p12),
                                     pin(req.identity.signer_pin));
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

      ResponseToFetchDelivery rsp;
      if (req.chunk_size_kb != null && req.chunk_size_kb > 0)
      {
        // Chunked fetch (EFFI): pull a stored message in chunks. A message
        // smaller than the chunk size arrives as a plain response; anything
        // else comes back as chunk 1 of N and we pull the remaining chunks
        // before reassembling the response the usual parser can digest.
        int chunkKb = req.chunk_size_kb.intValue();
        ChunkInformation info = new ChunkInformation(chunkKb, 1);
        PartialFetchDelivery partial = new PartialFetchDelivery(dialog, info);
        partial.setSelectionMode(selectionMode(req.selection_mode != null
          ? req.selection_mode : "BY_MESSAGE_ID"));
        if (req.selection_rule != null)
          partial.setSelectionRule(req.selection_rule);

        ResponseToFetchAbstract first = partial.send();
        checkFeedback(first);
        if (first instanceof ResponseToFetchDelivery small)
        {
          rsp = small;
        }
        else
        {
          ResponseToPartialFetchDelivery chunk1 = (ResponseToPartialFetchDelivery)first;
          int total = chunk1.getChunkInformation().getTotalChunkNumbers();
          ByteArrayOutputStream assembled = new ByteArrayOutputStream();
          pipe(chunk1.getChunkBlob(), assembled);
          List<Integer> received = new ArrayList<>();
          received.add(1);
          for (int i = 2; i <= total; i++)
          {
            info.setChunkNumber(i);
            info.setReceivedChunks(received);
            PartialFetchDelivery next = new PartialFetchDelivery(dialog, info);
            // send() is typed to the abstract response; chunks 2..n are
            // partial responses by contract. Anything else is an error
            // with a name, not a ClassCastException.
            ResponseToFetchAbstract chunkRsp = next.send();
            checkFeedback(chunkRsp);
            if (!(chunkRsp instanceof ResponseToPartialFetchDelivery chunk))
              throw new BridgeException(
                BridgeException.OSCI,
                "chunked fetch: chunk " + i + " of " + total
                  + " arrived as a non-partial response");
            pipe(chunk.getChunkBlob(), assembled);
            received.add(i);
          }
          rsp = ResponseToFetchDelivery.parseResponseToFetchDelivery(
                  new ByteArrayInputStream(assembled.toByteArray()));
        }
      }
      else
      {
        FetchDelivery fetch = new FetchDelivery(dialog);
        fetch.setSelectionMode(selectionMode(req.selection_mode));
        if (req.selection_rule != null)
          fetch.setSelectionRule(req.selection_rule);
        rsp = fetch.send();
      }
      checkFeedback(rsp);

      Protocol.Result result = new Protocol.Result();
      result.feedback = toProtocolFeedback(rsp.getFeedback());
      result.response_signed = rsp.isSigned();
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
          catch (BridgeException e)
          {
            // Our own key material is broken (bad PKCS#12, wrong PIN) —
            // that is a crypto error of ours, not "not encrypted to us",
            // and must surface as one instead of masquerading as the
            // message subject.
            throw e;
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
      return result;
    }
    catch (IOException e)
    {
      throw new BridgeException(BridgeException.TRANSPORT, e.getMessage());
    }
    catch (OSCIException | GeneralSecurityException e)
    {
      throw new BridgeException(BridgeException.OSCI,
                                  e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName());
    }
    finally
    {
      // On success AND on every error path — a rejected fetch must not
      // abandon an open dialog (ConversationId, SequenceNumber) at the
      // intermediary while this bridge process lives on.
      exitDialogQuietly(dialog);
    }
  }

  // ---------------------------------------------------------- process-card

  public static Protocol.Result processCard(Protocol.Request req)
  {
    requireDialogShape(req);
    require(req.selection_rule != null, "process-card needs selection_rule (the message id)");

    P12Signer signer = new P12Signer(b64(req.identity.signer_p12),
                                     pin(req.identity.signer_pin));
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
      result.feedback = toProtocolFeedback(rsp.getFeedback());
      result.response_signed = rsp.isSigned();
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
      return result;
    }
    catch (IOException e)
    {
      throw new BridgeException(BridgeException.TRANSPORT, e.getMessage());
    }
    catch (OSCIException | GeneralSecurityException e)
    {
      throw new BridgeException(BridgeException.OSCI,
                                  e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName());
    }
    finally
    {
      // Same contract as fetch: the dialog dies with the request, whatever
      // the request died of.
      exitDialogQuietly(dialog);
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
    versions.put("jar_sha256", jarSha256());
    result.versions = versions;
    return result;
  }

  /**
   * SHA-256 of the running bridge jar — a per-invocation audit trail: what
   * ran is answerable, not just what was supposed to run.
   */
  private static String jarSha256()
  {
    try
    {
      java.net.URL jar = Bridge.class.getProtectionDomain()
                                    .getCodeSource()
                                    .getLocation();
      if (jar == null)
        return "unknown";
      try (InputStream in = jar.openStream();
           java.security.DigestInputStream din = new java.security.DigestInputStream(
             in, java.security.MessageDigest.getInstance("SHA-256")))
      {
        byte[] sink = new byte[8192];
        while (din.read(sink) > -1)
        {
          // Digest only; the bytes themselves are nobody's business.
        }
        return java.util.HexFormat.of().formatHex(din.getMessageDigest().digest());
      }
    }
    catch (Exception e)
    {
      return "unknown";
    }
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

  /**
   * Only modes the library's {@code FetchRequestAbstract.setSelectionMode}
   * actually accepts: it throws {@code IllegalArgumentException} for
   * SELECT_BY_RECENT_MODIFICATION (2), so that mapping used to crash the
   * bridge with a stack trace instead of a clean protocol error. Unknown
   * modes fail cleanly here.
   */
  static int selectionMode(String mode)
  {
    if (mode == null || "BY_MESSAGE_ID".equals(mode))
      return OSCIMessage.SELECT_BY_MESSAGE_ID;
    switch (mode)
    {
      case "ALL": return OSCIMessage.SELECT_ALL;
      case "BY_DATE_OF_RECEPTION": return OSCIMessage.SELECT_BY_DATE_OF_RECEPTION;
      default:
        throw new BridgeException(BridgeException.PROTOCOL, "unknown selection_mode: " + mode);
    }
  }

  private static void checkFeedback(OSCIResponseTo rsp)
  {
    checkFeedbackRows(rsp == null ? null : rsp.getFeedback());
  }

  /**
   * 0xxx are positive receipts ("Auftrag ausgeführt"). 3xxx are warnings
   * per spec §5 — "Erfolgsmeldung oder Warnung" means the order WAS
   * executed — but intermediaries use the 3-class for hard rejections
   * too (3707 „Certificate is selfsigned" refuses the delivery), so
   * warnings are not blindly accepted: only the spec's §6.6.10 indicator
   * for „weitere Zustellungen liegen vor" (3800) is tolerated, because a
   * fetch that delivers a message and notes „more pending" is a success,
   * not a rejection. Everything else fails loudly.
   */
  static void checkFeedbackRows(String[][] feedback)
  {
    if (feedback == null)
      return;
    for (String[] row : feedback)
    {
      // Row layout per the library: [lang, code, text] — see FeedbackObject
      // (lang = [0], code = [1], text = [2]). Codes starting with '0' are
      // the OSCI way of saying "yes, fine, everything ok, next please".
      if (row.length > 1 && row[1] != null && !row[1].startsWith("0")
          && !"3800".equals(row[1]))
        throw new BridgeException(BridgeException.OSCI,
                                  "intermediary rejected the request: " + rowText(row),
                                  toProtocolFeedback(feedback));
    }
  }

  private static String rowText(String[] row)
  {
    return "code=" + (row.length > 1 ? row[1] : "?")
           + (row.length > 2 && row[2] != null ? " (" + row[2] + ")" : "");
  }

  /**
   * Maps library feedback rows to the wire shape documented in
   * docs/PROTOCOL.md: {@code [text, code]} per row. The library hands out
   * three columns — {@code [lang, code, text]} — and forwarding them raw
   * used to make the CLI print the language kürzel where the rejection
   * reason belongs.
   */
  static String[][] toProtocolFeedback(String[][] rows)
  {
    if (rows == null)
      return null;
    String[][] mapped = new String[rows.length][];
    for (int i = 0; i < rows.length; i++)
    {
      String[] row = rows[i];
      String text = row.length > 2 && row[2] != null ? row[2]
                    : (row.length > 0 ? row[0] : null);
      String code = row.length > 1 ? row[1] : null;
      mapped[i] = new String[]{text, code};
    }
    return mapped;
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

  static Protocol.FetchedContent toFetchedContent(Content c, String container)
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
          // The stream, never getContentData(): that one is the library's
          // UTF-8 String *interpretation* of the bytes, and re-encoding it
          // does not survive contact with non-UTF-8 payloads.
          fc.data = readContentAsBase64(c.getContentStream());
          break;
        case Content.ATTACHMENT_REFERENCE:
          Attachment a = c.getAttachment();
          fc.filename = a.getRefID();
          fc.content_type = a.getContentType();
          fc.data = readContentAsBase64(a.getStream());
          break;
        default:
          fc.filename = null;
          fc.content_type = "application/octet-stream";
          fc.data = readContentAsBase64(c.getContentStream());
          break;
      }
    }
    catch (IOException | de.osci.osci12.OSCIException e)
    {
      throw new BridgeException(BridgeException.INTERNAL, "cannot read fetched content: " + e.getMessage());
    }
    return fc;
  }

  private static String readContentAsBase64(InputStream in) throws IOException
  {
    if (in == null)
      throw new BridgeException(BridgeException.INTERNAL, "fetched content carries no data");
    try (InputStream bounded = in)
    {
      return Base64.getEncoder().encodeToString(bounded.readAllBytes());
    }
  }

  private static void pipe(InputStream in, ByteArrayOutputStream out) throws IOException
  {
    byte[] buffer = new byte[64 * 1024];
    int read;
    while ((read = in.read(buffer)) >= 0)
      out.write(buffer, 0, read);
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
