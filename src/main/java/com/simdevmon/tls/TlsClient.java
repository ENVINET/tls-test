
package com.simdevmon.tls;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.KeyStore;
import java.security.cert.Certificate;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManagerFactory;

/**
 * Sample TLS client.
 *
 * @author simdevmon
 */
public class TlsClient
{

    public static final String CLIENT_CRT = "-----BEGIN CERTIFICATE-----\n"
        + "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\n"
        + "DeSv4CeTalaeZF5dzlzHZD6oR3dqqNY=\n"
        + "-----END CERTIFICATE-----";

    private static final String CLIENT_KEY
        = "-----BEGIN PRIVATE KEY-----\n"
        + "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\n"
        + "doo+Ok84wXiCP7WP6djjWovPH1OBCJ8=\n"
        + "-----END PRIVATE KEY-----";

    public static void main(String[] args) throws Exception
    {
        new TlsClient().start();
    }

    private void start() throws Exception
    {
        //System.setProperty("javax.net.debug", "all");
        String ksPw = "changeit";

        // Init Key Manager Factory.
        KeyStore ks = TlsCommon.createKeystore(ksPw);
        ks.setKeyEntry("client", TlsCommon.convertPrivateKey(CLIENT_KEY), ksPw.toCharArray(), new Certificate[]
        {
            TlsCommon.convertCertificate(CLIENT_CRT)
        });
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(ks, ksPw.toCharArray());

        // Init Trust Manager Factory.
        KeyStore ts = TlsCommon.createKeystore(ksPw);
        ts.setCertificateEntry("server", TlsCommon.convertCertificate(TlsServer.SERVER_CRT));
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(ts);

        // Init SSL context.
        SSLContext ctx = SSLContext.getInstance(TlsCommon.TLS_PROTOCOL);
        ctx.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);

        // Socket connection.
        SSLSocket socket = (SSLSocket) ctx.getSocketFactory().createSocket("localhost", TlsCommon.PORT);
        socket.setEnabledCipherSuites(TlsCommon.CIPHER_SUITES);
        socket.setEnabledProtocols(new String[]
        {
            TlsCommon.TLS_PROTOCOL
        });

        System.out.println("Connected: " + socket.isConnected());
        Thread.sleep(1000);
        InputStream is = new BufferedInputStream(socket.getInputStream());
        OutputStream os = new BufferedOutputStream(socket.getOutputStream());
        os.write("Hello World".getBytes());
        os.flush();
        byte[] data = new byte[2048];
        int len = is.read(data);
        if (len <= 0)
        {
            throw new IOException("No data received.");
        }
        System.out.printf("Client received %d bytes: %s%n", len, new String(data, 0, len));
    }
}
