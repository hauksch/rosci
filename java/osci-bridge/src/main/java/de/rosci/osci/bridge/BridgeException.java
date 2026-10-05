package de.rosci.osci.bridge;

/**
 * The only exception taxonomy this bridge knows. Five kinds, no subcommittees,
 * no annexes, no transitional periods.
 */
public final class BridgeException extends RuntimeException
{
  // The exception is never serialized across the wire — the line protocol
  // carries the fields — but a Throwable without an explicit uid makes
  // strict javac grumble, and strict javac is right.
  private static final long serialVersionUID = 2026100300L;

  public static final String PROTOCOL = "protocol";
  public static final String CRYPTO = "crypto";
  public static final String TRANSPORT = "transport";
  public static final String OSCI = "osci";
  public static final String INTERNAL = "internal";

  public final String kind;
  public final String[][] feedback;

  public BridgeException(String kind, String message)
  {
    this(kind, message, null);
  }

  public BridgeException(String kind, String message, String[][] feedback)
  {
    super(message);
    this.kind = kind;
    this.feedback = feedback;
  }
}
