package de.rosci.osci.bridge;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.jupiter.api.Test;

import com.sun.net.httpserver.HttpServer;

/**
 * Pins the request-streaming contract of {@link BridgeTransport}: the body
 * goes out with the exact announced Content-Length (fixed-length streaming
 * mode), not buffered on-heap with a silently ignored header.
 */
class BridgeTransportTest
{
  @Test
  void requestBodyArrivesCompleteWithExactContentLength() throws Exception
  {
    HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
    AtomicReference<byte[]> receivedBody = new AtomicReference<>();
    AtomicInteger receivedLength = new AtomicInteger(-1);
    server.createContext("/", exchange ->
    {
      byte[] body = exchange.getRequestBody().readAllBytes();
      receivedBody.set(body);
      receivedLength.set(Integer.parseInt(exchange.getRequestHeaders()
                                               .getFirst("Content-length")));
      byte[] ok = "ok".getBytes(StandardCharsets.UTF_8);
      exchange.getResponseHeaders().set("Content-Type", "text/plain");
      exchange.sendResponseHeaders(200, ok.length);
      try (OutputStream os = exchange.getResponseBody())
      {
        os.write(ok);
      }
    });
    server.start();
    try
    {
      BridgeTransport transport = new BridgeTransport(null);
      byte[] payload = new byte[64 * 1024];
      for (int i = 0; i < payload.length; i++)
        payload[i] = (byte) (i % 251);
      // > 8 KB so any internal buffering would have to spill; the fixed
      // length must match the actual bytes exactly, or HttpURLConnection
      // fails the write loudly (which is the point).
      try (OutputStream out = transport.getConnection(
          URI.create("http://127.0.0.1:" + server.getAddress().getPort() + "/entry"),
          payload.length))
      {
        out.write(payload);
      }
      try (InputStream in = transport.getResponseStream())
      {
        assertArrayEquals("ok".getBytes(StandardCharsets.UTF_8), in.readAllBytes());
      }
      assertArrayEquals(payload, receivedBody.get());
      assertEquals(payload.length, receivedLength.get(),
                   "the server must see the announced Content-Length");
    }
    finally
    {
      server.stop(0);
    }
  }
}
