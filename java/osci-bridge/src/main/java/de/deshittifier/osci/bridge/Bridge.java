package de.deshittifier.osci.bridge;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;
import java.security.Security;

import com.google.gson.Gson;
import com.google.gson.JsonParseException;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import de.osci.osci12.common.DialogHandler;

/**
 * Entry point and request loop of the sidecar bridge.
 *
 * Stdin: one JSON request per line. Stdout: one JSON response per line.
 * Stderr: logs (kept quiet). Exit: after "shutdown" or EOF. The process is
 * intentionally boring — all the ceremony lives in OSCI where it belongs.
 */
public final class Bridge
{
  public static final String VERSION = "0.1.0";

  static final Gson GSON = new Gson();

  public static void main(String[] args) throws IOException
  {
    // Configure slf4j-simple before anything logs: warn level, stderr only.
    System.setProperty("org.slf4j.simpleLogger.defaultLogLevel", "warn");
    System.setProperty("org.slf4j.simpleLogger.logFile", "System.err");

    Security.addProvider(new BouncyCastleProvider());
    DialogHandler.setSecurityProvider(Security.getProvider(BouncyCastleProvider.PROVIDER_NAME));

    try (BufferedReader in = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8));
         BufferedWriter out = new BufferedWriter(new OutputStreamWriter(System.out, StandardCharsets.UTF_8)))
    {
      String line;
      while ((line = in.readLine()) != null)
      {
        line = line.trim();
        if (line.isEmpty())
          continue;
        Protocol.Response rsp = handleLine(line);
        out.write(GSON.toJson(rsp));
        out.write('\n');
        out.flush();
        if (rsp.op != null && "shutdown".equals(rsp.op) && rsp.ok)
          return;
      }
    }
  }

  /** Parses one request line into a response. Never throws. */
  static Protocol.Response handleLine(String line)
  {
    String id = null;
    try
    {
      Protocol.Request req = GSON.fromJson(line, Protocol.Request.class);
      if (req == null || req.op == null || req.op.isBlank())
        return Protocol.Response.error(null, null, BridgeException.PROTOCOL,
                                       "request is missing 'op'", null);
      id = req.id;
      return dispatch(req);
    }
    catch (JsonParseException e)
    {
      return Protocol.Response.error(id, null, BridgeException.PROTOCOL,
                                     "malformed JSON request: " + e.getMessage(), null);
    }
  }

  static Protocol.Response dispatch(Protocol.Request req)
  {
    try
    {
      return switch (req.op)
      {
        case "ping" -> Protocol.Response.ok(req.id, req.op, OsciOps.ping());
        case "send" -> Protocol.Response.ok(req.id, req.op, OsciOps.send(req));
        case "fetch" -> Protocol.Response.ok(req.id, req.op, OsciOps.fetch(req));
        case "process-card" -> Protocol.Response.ok(req.id, req.op, OsciOps.processCard(req));
        case "shutdown" ->
        {
          Protocol.Result note = new Protocol.Result();
          yield Protocol.Response.ok(req.id, req.op, note);
        }
        default -> Protocol.Response.error(req.id, req.op, BridgeException.PROTOCOL,
                                           "unknown op: " + req.op, null);
      };
    }
    catch (BridgeException e)
    {
      return Protocol.Response.error(req.id, req.op, e.kind, e.getMessage(), e.feedback);
    }
    catch (Exception e)
    {
      return Protocol.Response.error(req.id, req.op, BridgeException.INTERNAL,
                                     e.getClass().getSimpleName() + ": " + e.getMessage(), null);
    }
  }
}
