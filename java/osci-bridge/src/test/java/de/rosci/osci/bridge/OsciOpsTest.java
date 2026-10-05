package de.rosci.osci.bridge;

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

  @Test
  void positiveReceiptsAndThePendingDeliveriesWarningPass()
  {
    // 3800 „weitere Zustellungen liegen vor" is a spec §6.6.10 warning that
    // accompanies a SUCCESSFUL fetch (one message per FetchDelivery); it
    // must not fail the request.
    String[][] warningThenOk = {
        {"de", "3800", "Es liegen weitere Zustellungen für diesen Client vor"},
        {"de", "0801", "Auftrag ausgeführt, Dialog weiterhin geöffnet"},
    };
    OsciOps.checkFeedbackRows(warningThenOk); // must not throw
    OsciOps.checkFeedbackRows(new String[][]{{"de", "0800", "Auftrag ausgeführt, Dialog beendet"}});
  }

  @Test
  void errorCodesAndHardRejectionsFailLoudly()
  {
    assertThrowsFeedback(new String[][]{{"de", "9803", "keine Zustellung vorhanden"}});
    assertThrowsFeedback(new String[][]{{"de", "9804", "No or wrong messageId given"}});
    // 3707 lives in the 3-class but is a hard rejection (the delivery is
    // refused) — the narrow 3800 whitelist does not launder it.
    assertThrowsFeedback(new String[][]{
        {"de", "3707", "Certificate is selfsigned."},
        {"de", "0800", "Auftrag ausgeführt, Dialog beendet"},
    });
  }

  private void assertThrowsFeedback(String[][] feedback)
  {
    org.junit.jupiter.api.Assertions.assertThrows(BridgeException.class,
                                                  () -> OsciOps.checkFeedbackRows(feedback));
  }

  @Test
  void selectionModesMapToLibraryConstants()
  {
    assertEquals(de.osci.osci12.messagetypes.OSCIMessage.SELECT_BY_MESSAGE_ID,
                 OsciOps.selectionMode(null));
    assertEquals(de.osci.osci12.messagetypes.OSCIMessage.SELECT_BY_MESSAGE_ID,
                 OsciOps.selectionMode("BY_MESSAGE_ID"));
    assertEquals(de.osci.osci12.messagetypes.OSCIMessage.SELECT_ALL,
                 OsciOps.selectionMode("ALL"));
    assertEquals(de.osci.osci12.messagetypes.OSCIMessage.SELECT_BY_DATE_OF_RECEPTION,
                 OsciOps.selectionMode("BY_DATE_OF_RECEPTION"));
  }

  @Test
  void selectionModesTheLibraryCannotExpressFailCleanly()
  {
    // SELECT_BY_RECENT_MODIFICATION (2) exists as a constant but
    // setSelectionMode throws IllegalArgumentException for it — mapping it
    // used to crash the bridge with a stack trace instead of a clean
    // protocol error. It must fail like any unknown mode.
    org.junit.jupiter.api.Assertions.assertThrows(BridgeException.class,
                                                  () -> OsciOps.selectionMode("BY_RECENT_MODIFICATION"));
    org.junit.jupiter.api.Assertions.assertThrows(BridgeException.class,
                                                  () -> OsciOps.selectionMode("GIBBERISH"));
  }
}
