package de.rosci.osci.bridge;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

import com.google.gson.Gson;

/**
 * Exercises the request loop without touching the network: ping, protocol
 * violations, unknown ops, shutdown. The full send/fetch flows against a
 * local mock intermediary live in the Rust e2e suite (tests/), which drives
 * this exact jar.
 */
class BridgeLoopTest
{
  private final Gson gson = new Gson();

  @Test
  void pingReportsVersions()
  {
    Protocol.Response rsp = Bridge.handleLine("{\"id\":\"1\",\"op\":\"ping\"}");
    assertTrue(rsp.ok);
    assertEquals("ping", rsp.op);
    assertEquals("1", rsp.id);
    assertEquals(Protocol.VERSION, rsp.result.versions.get("protocol"));
    assertEquals(Bridge.VERSION, rsp.result.versions.get("bridge"));
    assertTrue(rsp.result.versions.containsKey("osci_library"));
    assertTrue(rsp.result.versions.containsKey("java"));
  }

  @Test
  void malformedJsonIsAProtocolError()
  {
    Protocol.Response rsp = Bridge.handleLine("{this is not json, ehrlich nicht");
    assertFalse(rsp.ok);
    assertEquals(BridgeException.PROTOCOL, rsp.error.kind);
  }

  @Test
  void missingOpIsAProtocolError()
  {
    Protocol.Response rsp = Bridge.handleLine("{\"id\":\"2\"}");
    assertFalse(rsp.ok);
    assertEquals(BridgeException.PROTOCOL, rsp.error.kind);
  }

  @Test
  void unknownOpIsAProtocolError()
  {
    Protocol.Response rsp = Bridge.handleLine("{\"id\":\"3\",\"op\":\"telefon-zettel\"}");
    assertFalse(rsp.ok);
    assertEquals(BridgeException.PROTOCOL, rsp.error.kind);
    assertTrue(rsp.error.message.contains("telefon-zettel"));
  }

  @Test
  void sendWithoutConfigIsAProtocolError()
  {
    Protocol.Response rsp = Bridge.handleLine(
        "{\"id\":\"4\",\"op\":\"send\",\"content\":{\"data\":\"QUJD\"}}");
    assertFalse(rsp.ok);
    assertEquals(BridgeException.PROTOCOL, rsp.error.kind);
    assertTrue(rsp.error.message.contains("intermediary"));
  }

  @Test
  void shutdownIsAcknowledged()
  {
    Protocol.Response rsp = Bridge.handleLine("{\"id\":\"5\",\"op\":\"shutdown\"}");
    assertTrue(rsp.ok);
    assertEquals("shutdown", rsp.op);
  }

  @Test
  void responseSurvivesJsonRoundTrip()
  {
    Protocol.Response rsp = Bridge.handleLine("{\"id\":\"6\",\"op\":\"ping\"}");
    String json = gson.toJson(rsp);
    Protocol.Response back = gson.fromJson(json, Protocol.Response.class);
    assertEquals(rsp.id, back.id);
    assertEquals(rsp.op, back.op);
    assertEquals(rsp.ok, back.ok);
  }
}
