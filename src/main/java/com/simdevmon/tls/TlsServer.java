
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
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManagerFactory;

/**
 * Sample TLS server.
 *
 * @author simdevmon
 */
public class TlsServer
{

    public static final String SERVER_CRT = "-----BEGIN CERTIFICATE-----\n"
        + "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\n"
        + "ILriyWbkO2ZeNP1ohwMqByACSobKkik=\n"
        + "-----END CERTIFICATE-----";

    private static final String SERVER_KEY
        = "-----BEGIN PRIVATE KEY-----\n"
        + "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\n"
        + "S9xP5lK56eooXRfv0+33Ux+VakYU3ssxEg==\n"
        + "-----END PRIVATE KEY-----";

    public static void main(String[] args) throws Exception
    {
        new TlsServer().start();
    }

    private void start() throws Exception
    {
        //System.setProperty("javax.net.debug", "all");
        String ksPass = "changeit";

        // Init Key Manager Factory.
        KeyStore kks = TlsCommon.createKeystore(ksPass);
        kks.setKeyEntry("server", TlsCommon.convertPrivateKey(SERVER_KEY), ksPass.toCharArray(), new Certificate[]
        {
            TlsCommon.convertCertificate(SERVER_CRT)
        });
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(kks, ksPass.toCharArray());

        // Init Trust Manager Factory.
        KeyStore tks = TlsCommon.createKeystore(ksPass);
        tks.setCertificateEntry("client", TlsCommon.convertCertificate(TlsClient.CLIENT_CRT));
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(tks);

        // Init SSL Context.
        SSLContext ctx = SSLContext.getInstance(TlsCommon.TLS_PROTOCOL);
        ctx.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);

        // Init Server Socket.
        SSLServerSocket serverSocket = (SSLServerSocket) ctx.getServerSocketFactory()
            .createServerSocket(TlsCommon.PORT);
        serverSocket.setNeedClientAuth(true);
        serverSocket.setEnabledCipherSuites(TlsCommon.CIPHER_SUITES);
        serverSocket.setEnabledProtocols(new String[]
        {
            TlsCommon.TLS_PROTOCOL
        });

        System.out.printf("Server started on port %d%n", TlsCommon.PORT);
        while (true)
        {
            try ( SSLSocket socket = (SSLSocket) serverSocket.accept())
            {
                System.out.println("Accept connection: " + socket.getRemoteSocketAddress());
                InputStream is = new BufferedInputStream(socket.getInputStream());
                OutputStream os = new BufferedOutputStream(socket.getOutputStream());
                byte[] data = new byte[2048];
                int len = is.read(data);
                if (len <= 0)
                {
                    throw new IOException("No data received.");
                }
                System.out.printf("Server received %d bytes: %s%n", len, new String(data, 0, len));
                os.write(data, 0, len);
                os.flush();
            }
            catch (Exception ex)
            {
                ex.printStackTrace();
            }
        }
    }
}
