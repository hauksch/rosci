package de.rosci.osci.bridge;

import java.util.List;
import java.util.Map;

/**
 * Line protocol v1 between the Rust CLI and this Java sidecar.
 *
 * Contract: one JSON object per line on stdin, exactly one JSON object per
 * line on stdout, logs go to stderr. The whole protocol fits on a beer mat —
 * a property certain other protocols in this domain famously lack
 * (looking at you, three-hundred-page transport specification).
 *
 * See docs/PROTOCOL.md for the canonical description.
 */
public final class Protocol
{
  private Protocol()
  {}

  public static final String VERSION = "1";

  public static final class Request
  {
    public String id;
    public String op; // send | fetch | process-card | ping | shutdown
    public Party intermediary; // send / fetch / process-card
    public Identity identity; // send / fetch / process-card
    public Party recipient; // send
    public String subject; // send
    public Payload content; // send: the XTA payload as opaque bytes
    public List<Payload> attachments; // send: optional additional content parts
    public String metadata_author; // send: XTA MessageMetaData author identifier (e.g. ags:NNNNNNNNNNN)
    public String metadata_reader; // send: XTA MessageMetaData reader identifier
    /**
     * send: opt-in EFFI chunked transfer — the fully built StoreDelivery is
     * serialized, split into chunks of this many KB and shipped as
     * PartialStoreDelivery sequence (spec „Effiziente Übertragung großer
     * Datenmengen"). fetch: partial fetch chunk size for messages that were
     * stored chunked. Unset = plain StoreDelivery/FetchDelivery.
     */
    public Long chunk_size_kb;
    public Boolean sign; // send, default true
    public Boolean encrypt; // send, default true
    /**
     * Test mode: disable SOAP-transport-level encryption and signatures so a
     * local mock intermediary can parse the envelope. Content signing and
     * content encryption remain fully active. Never point this at anything
     * you don't own — the name says insecure because it is.
     */
    public Boolean insecure_transport;
    public Tls tls; // optional TLS knobs for all ops that talk to an intermediary
    public String selection_mode; // fetch / process-card
    public String selection_rule; // fetch / process-card
  }

  public static final class Party
  {
    public String url; // intermediary entry URL
    public String cipher_cert; // base64 DER or PEM
    public String signature_cert; // optional, base64 DER or PEM
  }

  public static final class Identity
  {
    public String signer_p12; // base64 PKCS#12 with the signature key
    public String signer_pin;
    public String decrypter_p12; // optional, falls back to signer_p12
    public String decrypter_pin;
  }

  public static final class Payload
  {
    public String filename;
    public String content_type;
    public String data; // base64 — treated as sacred, opaque bytes
  }

  public static final class Tls
  {
    public List<String> trust_anchors; // base64/PEM certs; empty = JVM defaults
    public String client_p12; // base64 PKCS#12 for TLS client auth
    public String client_pin;
    public Integer connect_timeout_ms;
    public Integer read_timeout_ms;
  }

  public static final class Response
  {
    public String id;
    public String op;
    public boolean ok;
    public Result result;
    public Error error;

    public static Response ok(String id, String op, Result result)
    {
      Response r = new Response();
      r.id = id;
      r.op = op;
      r.ok = true;
      r.result = result;
      return r;
    }

    public static Response error(String id, String op, String kind, String message, String[][] feedback)
    {
      Response r = new Response();
      r.id = id;
      r.op = op;
      r.ok = false;
      r.error = new Error();
      r.error.kind = kind;
      r.error.message = message;
      r.error.feedback = feedback;
      return r;
    }
  }

  public static final class Result
  {
    public String message_id; // send
    public Boolean response_signed; // true when the intermediary signed the response (and it verified)
    public String[][] feedback; // send / fetch / process-card
    public List<FetchedMessage> messages; // fetch
    public List<ProcessCard> process_cards; // process-card
    public Map<String, String> versions; // ping
  }

  public static final class FetchedMessage
  {
    public String subject;
    public Boolean signatures_valid;
    public List<FetchedContent> contents;
    public List<FetchedContent> encrypted_contents;
  }

  public static final class FetchedContent
  {
    public String filename;
    public String content_type;
    public String data; // base64
    public String container; // "plain" | "encrypted"
  }

  public static final class ProcessCard
  {
    public String message_id;
    public String subject;
    public String creation;
    public String forwarding;
    public String reception;
    public List<Inspection> inspections;
  }

  public static final class Inspection
  {
    public String subject;
    public String issuer;
    public String serial_number;
    public Boolean online_checked;
    public String timestamp;
  }

  public static final class Error
  {
    public String kind; // protocol | crypto | transport | osci | internal
    public String message;
    public String[][] feedback;
  }
}
