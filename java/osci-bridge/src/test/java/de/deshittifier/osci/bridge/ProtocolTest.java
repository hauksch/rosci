package de.deshittifier.osci.bridge;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Base64;

import org.junit.jupiter.api.Test;

import com.google.gson.Gson;

/**
 * Line-protocol contract tests. These pin the JSON shape the Rust side
 * depends on — if these break, the CLI breaks, so they change only with a
 * protocol version bump, not "because gson felt like it".
 */
class ProtocolTest
{
  private final Gson gson = new Gson();

  @Test
  void parsesSendRequest()
  {
    String b64 = Base64.getEncoder().encodeToString(new byte[]{1, 2, 3});
    String json = """
        {"id":"42","op":"send",
         "intermediary":{"url":"http://localhost:8080/entry","cipher_cert":"AAECAw=="},
         "identity":{"signer_p12":"%s","signer_pin":"123456"},
         "recipient":{"cipher_cert":"AAECAw=="},
         "subject":"XMeld anzeige",
         "content":{"filename":"meldung.xta","data":"%s"},
         "sign":true,"encrypt":false}
        """.formatted(b64, b64);

    Protocol.Request req = gson.fromJson(json, Protocol.Request.class);

    assertEquals("42", req.id);
    assertEquals("send", req.op);
    assertEquals("http://localhost:8080/entry", req.intermediary.url);
    assertEquals("123456", req.identity.signer_pin);
    assertNull(req.identity.decrypter_p12);
    assertEquals("meldung.xta", req.content.filename);
    assertEquals("XMeld anzeige", req.subject);
    assertTrue(req.sign);
    assertFalse(req.encrypt);
  }

  @Test
  void errorResponseSerializesPredictably()
  {
    Protocol.Response rsp = Protocol.Response.error("7", "send", "transport", "connection refused",
                                                    new String[][]{{"verbindungsprobleme", "1050"}});
    String json = gson.toJson(rsp);

    assertTrue(json.contains("\"ok\":false"));
    assertTrue(json.contains("\"kind\":\"transport\""));
    assertTrue(json.contains("\"message\":\"connection refused\""));
    assertTrue(json.contains("1050"));
    assertFalse(json.contains("\"result\""));
  }

  @Test
  void okResponseCarriesResult()
  {
    Protocol.Result result = new Protocol.Result();
    result.message_id = "msgid-1";
    Protocol.Response rsp = Protocol.Response.ok("9", "send", result);
    String json = gson.toJson(rsp);

    assertTrue(json.contains("\"ok\":true"));
    assertTrue(json.contains("msgid-1"));
    assertFalse(json.contains("\"error\""));
  }

  @Test
  void omittedOptionalFieldsStayAbsent()
  {
    Protocol.Response rsp = Protocol.Response.ok(null, "shutdown", new Protocol.Result());
    String json = gson.toJson(rsp);
    assertFalse(json.contains("message_id"));
    assertFalse(json.contains("feedback"));
  }
}
