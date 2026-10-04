package de.deshittifier.osci.bridge;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.Base64;

import org.junit.jupiter.api.Test;

import de.osci.osci12.messageparts.Content;

/**
 * Pins the two wire-fidelity contracts of {@link OsciOps}: feedback rows
 * travel as {@code [text, code]} (the library's raw rows are
 * {@code [lang, code, text]}), and fetched DATA content arrives as the
 * original bytes — not as the library's lossy UTF-8 string interpretation
 * of them.
 */
class OsciOpsTest
{
  @Test
  void feedbackRowsAreMappedToTextAndCode()
  {
    String[][] libraryRows = {
        {"de", "1050", "der amtliche Nachweis fehlt"},
        {"en", "0000", "message accepted"},
    };
    String[][] mapped = OsciOps.toProtocolFeedback(libraryRows);
    assertEquals(2, mapped.length);
    assertArrayEquals(new String[]{"der amtliche Nachweis fehlt", "1050"}, mapped[0]);
    assertArrayEquals(new String[]{"message accepted", "0000"}, mapped[1]);
  }

  @Test
  void degenerateFeedbackRowsDoNotBlowUp()
  {
    assertNull(OsciOps.toProtocolFeedback(null));
    String[][] mapped = OsciOps.toProtocolFeedback(new String[][]{{"nur-text"}, {}});
    assertArrayEquals(new String[]{"nur-text", null}, mapped[0]);
    assertArrayEquals(new String[]{null, null}, mapped[1]);
  }

  @Test
  void errorFeedbackRidesOnTheBridgeException()
  {
    // The rejection path must carry the mapped rows too — the CLI renders
    // them on stderr, and "[1050] de" was exactly the bug this pins shut.
    String[][] feedback = {{"de", "1050", "zugang verweigert"}};
    BridgeException e = new BridgeException(BridgeException.OSCI, "abgelehnt",
                                            OsciOps.toProtocolFeedback(feedback));
    assertArrayEquals(new String[]{"zugang verweigert", "1050"}, e.feedback[0]);
  }

  @Test
  void fetchedDataContentPreservesNonUtf8Bytes() throws IOException
  {
    // Not valid UTF-8 on purpose: the old getContentData() round-trip
    // turned the FF FE 80 sequence into replacement characters.
    byte[] raw = {0x00, (byte)0xFF, (byte)0xFE, 0x41, (byte)0x80, 0x10, 0x7F};
    Content c = new Content(new ByteArrayInputStream(raw));
    Protocol.FetchedContent fc = OsciOps.toFetchedContent(c, "plain");
    assertArrayEquals(raw, Base64.getDecoder().decode(fc.data));
    assertEquals("plain", fc.container);
  }

  @Test
  void fetchedDataContentRoundTripsUtf8Bytes() throws IOException
  {
    byte[] raw = "<?xml version=\"1.0\"?><XTA>moin</XTA>".getBytes(java.nio.charset.StandardCharsets.UTF_8);
    Content c = new Content(new ByteArrayInputStream(raw));
    Protocol.FetchedContent fc = OsciOps.toFetchedContent(c, "encrypted");
    assertArrayEquals(raw, Base64.getDecoder().decode(fc.data));
    assertEquals("encrypted", fc.container);
  }
}
