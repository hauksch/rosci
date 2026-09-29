package de.deshittifier.osci.bridge;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URLConnection;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.util.Base64;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

import de.osci.osci12.extinterfaces.TransportI;

/**
 * TransportI implementation with the knobs the reference sample politely
 * omitted: TLS trust anchors, TLS client auth, and timeouts. POSTs
 * text/xml to the intermediary like the spec wants. Default connect/read
 * timeouts are generous because some intermediaries apparently process
 * requests by hand, with a stamp.
 */
public final class BridgeTransport implements TransportI
{
  private static final int DEFAULT_CONNECT_TIMEOUT_MS = 30_000;
  private static final int DEFAULT_READ_TIMEOUT_MS = 180_000;

  private final Protocol.Tls cfg;
  private URLConnection con;

  public BridgeTransport(Protocol.Tls cfg)
  {
    this.cfg = (cfg == null) ? new Protocol.Tls() : cfg;
  }

  @Override
  public String getVendor()
  {
    return "osci-deshittifier";
  }

  @Override
  public String getVersion()
  {
    return "1.0";
  }

  @Override
  public BridgeTransport newInstance()
  {
    return new BridgeTransport(cfg);
  }

  @Override
  public InputStream getResponseStream() throws IOException
  {
    return con.getInputStream();
  }

  @Override
  public boolean isOnline(java.net.URI uri) throws IOException
  {
    try
    {
      con = open(uri);
      con.connect();
      return true;
    }
    catch (ClassCastException | IllegalArgumentException e)
    {
      throw new IOException("invalid URL: " + e.getMessage());
    }
    catch (IOException e)
    {
      return false;
    }
  }

  @Override
  public long getContentLength()
  {
    return con.getContentLengthLong();
  }

  @Override
  public OutputStream getConnection(java.net.URI uri, long length) throws IOException
  {
    con = open(uri);
    if (con instanceof HttpURLConnection http)
    {
      http.setInstanceFollowRedirects(false);
      http.setRequestMethod("POST");
      http.setRequestProperty("Content-Type", "text/xml");
      http.setRequestProperty("charset", "utf-8");
      http.setRequestProperty("Content-Length", Long.toString(length));
      http.setUseCaches(false);
      http.setDoOutput(true);
      return http.getOutputStream();
    }
    throw new IOException("unsupported URL scheme (wanted http/https): " + uri);
  }

  private URLConnection open(URI uri) throws IOException
  {
    URLConnection c = uri.toURL().openConnection();
    c.setConnectTimeout(cfg.connect_timeout_ms != null ? cfg.connect_timeout_ms : DEFAULT_CONNECT_TIMEOUT_MS);
    c.setReadTimeout(cfg.read_timeout_ms != null ? cfg.read_timeout_ms : DEFAULT_READ_TIMEOUT_MS);
    if (c instanceof HttpsURLConnection https)
    {
      try
      {
        https.setSSLSocketFactory(sslContext().getSocketFactory());
      }
      catch (GeneralSecurityException e)
      {
        throw new IOException("TLS setup failed: " + e.getMessage(), e);
      }
    }
    return c;
  }

  private SSLContext sslContext() throws GeneralSecurityException, IOException
  {
    KeyManagerFactory kmf = null;
    if (cfg.client_p12 != null && !cfg.client_p12.isBlank())
    {
      char[] pin = cfg.client_pin == null ? new char[0] : cfg.client_pin.toCharArray();
      KeyStore ks = KeyStore.getInstance("PKCS12");
      try (InputStream in = new java.io.ByteArrayInputStream(Base64.getDecoder().decode(cfg.client_p12)))
      {
        ks.load(in, pin);
      }
      catch (IOException e)
      {
        throw new GeneralSecurityException("cannot load TLS client PKCS#12: " + e.getMessage());
      }
      kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
      kmf.init(ks, pin);
    }

    TrustManagerFactory tmf = null;
    if (cfg.trust_anchors != null && !cfg.trust_anchors.isEmpty())
    {
      KeyStore ts = KeyStore.getInstance(KeyStore.getDefaultType());
      ts.load(null, null);
      int i = 0;
      for (String anchor : cfg.trust_anchors)
      {
        ts.setCertificateEntry("anchor-" + (i++), CryptoMaterial.parseCertificate(anchor));
      }
      tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
      tmf.init(ts);
    }

    SSLContext ctx = SSLContext.getInstance("TLS");
    ctx.init(kmf != null ? kmf.getKeyManagers() : null,
             tmf != null ? tmf.getTrustManagers() : null,
             null);
    return ctx;
  }
}
