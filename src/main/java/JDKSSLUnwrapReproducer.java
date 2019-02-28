import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLException;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.nio.ByteBuffer;
import java.security.KeyStore;
import java.security.cert.X509Certificate;

public class JDKSSLUnwrapReproducer {

    public static void main(String[] args) throws Exception {
        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        keyStore.load(JDKSSLUnwrapReproducer.class.getResourceAsStream("test.p12"), "test".toCharArray());
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(keyStore, "test".toCharArray());
        SSLContext serverCtx = SSLContext.getInstance("TLS");
        serverCtx.init(kmf.getKeyManagers(), null, null);
        SSLEngine server = serverCtx.createSSLEngine();
        server.setUseClientMode(false);
        server.setEnabledProtocols(new String[] { "TLSv1.2" });


        SSLContext clientCtx = SSLContext.getInstance("TLS");
        clientCtx.init(null, new TrustManager[] {
                new X509TrustManager() {
                    @Override
                    public void checkClientTrusted(X509Certificate[] x509Certificates, String s) {
                        // NOOP
                    }

                    @Override
                    public void checkServerTrusted(X509Certificate[] x509Certificates, String s) {
                        // NOOP
                    }

                    @Override
                    public X509Certificate[] getAcceptedIssuers() {
                        return new X509Certificate[0];
                    }
                }
        }, null);

        SSLEngine client = clientCtx.createSSLEngine();
        client.setUseClientMode(true);
        client.setEnabledProtocols(new String[] { "TLSv1.2" });

        ByteBuffer plainClientOut = ByteBuffer.allocate(client.getSession().getApplicationBufferSize());
        ByteBuffer plainServerOut = ByteBuffer.allocate(server.getSession().getApplicationBufferSize());

        ByteBuffer encryptedClientToServer = ByteBuffer.allocate(client.getSession().getPacketBufferSize());
        ByteBuffer encryptedServerToClient = ByteBuffer.allocate(server.getSession().getPacketBufferSize());
        ByteBuffer empty = ByteBuffer.allocate(0);

        handshake(client, server);

        // This will produce a close_notify
        client.closeOutbound();

        // Something still pending in the outbound buffer.
        assertFalse(client.isOutboundDone());
        assertFalse(client.isInboundDone());

        // Now wrap and so drain the outbound buffer.
        SSLEngineResult result = client.wrap(empty, encryptedClientToServer);
        encryptedClientToServer.flip();

        assertEquals(SSLEngineResult.Status.CLOSED, result.getStatus());
        // Need an UNWRAP to read the response of the close_notify
        //
        // This is NOT_HANDSHAKING for JDK 12+ !!!!
        assertEquals(SSLEngineResult.HandshakeStatus.NEED_UNWRAP, result.getHandshakeStatus());

        int produced = result.bytesProduced();
        int consumed = result.bytesConsumed();
        int closeNotifyLen = produced;

        assertTrue(produced > 0);
        assertEquals(0, consumed);
        assertEquals(produced, encryptedClientToServer.remaining());
        // Outbound buffer should be drained now.
        assertTrue(client.isOutboundDone());
        assertFalse(client.isInboundDone());

        assertFalse(server.isOutboundDone());
        assertFalse(server.isInboundDone());
        result = server.unwrap(encryptedClientToServer, plainServerOut);
        plainServerOut.flip();

        assertEquals(SSLEngineResult.Status.CLOSED, result.getStatus());
        // Need a WRAP to respond to the close_notify
        assertEquals(SSLEngineResult.HandshakeStatus.NEED_WRAP, result.getHandshakeStatus());

        produced = result.bytesProduced();
        consumed = result.bytesConsumed();
        assertEquals(closeNotifyLen, consumed);
        assertEquals(0, produced);
        // Should have consumed the complete close_notify
        assertEquals(0, encryptedClientToServer.remaining());
        assertEquals(0, plainServerOut.remaining());

        assertFalse(server.isOutboundDone());
        assertTrue(server.isInboundDone());

        result = server.wrap(empty, encryptedServerToClient);
        encryptedServerToClient.flip();

        assertEquals(SSLEngineResult.Status.CLOSED, result.getStatus());
        // UNWRAP/WRAP are not expected after this point
        assertEquals(SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING, result.getHandshakeStatus());

        produced = result.bytesProduced();
        consumed = result.bytesConsumed();
        assertEquals(closeNotifyLen, produced);
        assertEquals(0, consumed);

        assertEquals(produced, encryptedServerToClient.remaining());
        assertTrue(server.isOutboundDone());
        assertTrue(server.isInboundDone());

        result = client.unwrap(encryptedServerToClient, plainClientOut);

        plainClientOut.flip();
        assertEquals(SSLEngineResult.Status.CLOSED, result.getStatus());
        // UNWRAP/WRAP are not expected after this point
        assertEquals(SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING, result.getHandshakeStatus());

        produced = result.bytesProduced();
        consumed = result.bytesConsumed();
        assertEquals(closeNotifyLen, consumed);
        assertEquals(0, produced);
        assertEquals(0, encryptedServerToClient.remaining());

        assertTrue(client.isOutboundDone());
        assertTrue(client.isInboundDone());

        // Ensure that calling wrap or unwrap again will not produce a SSLException
        encryptedServerToClient.clear();
        plainServerOut.clear();

        result = server.wrap(plainServerOut, encryptedServerToClient);
        assertEngineRemainsClosed(result);

        encryptedClientToServer.clear();
        plainServerOut.clear();

        result = server.unwrap(encryptedClientToServer, plainServerOut);
        assertEngineRemainsClosed(result);

        encryptedClientToServer.clear();
        plainClientOut.clear();

        result = client.wrap(plainClientOut, encryptedClientToServer);
        assertEngineRemainsClosed(result);

        encryptedServerToClient.clear();
        plainClientOut.clear();

        result = client.unwrap(encryptedServerToClient, plainClientOut);
        assertEngineRemainsClosed(result);
    }


    private static void assertEngineRemainsClosed(SSLEngineResult result) {
        assertEquals(SSLEngineResult.Status.CLOSED, result.getStatus());
        assertEquals(SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING, result.getHandshakeStatus());
        assertEquals(0, result.bytesConsumed());
        assertEquals(0, result.bytesProduced());
    }

    private static void handshake(SSLEngine clientEngine, SSLEngine serverEngine) throws SSLException {
        ByteBuffer cTOs = ByteBuffer.allocate(clientEngine.getSession().getPacketBufferSize());
        ByteBuffer sTOc = ByteBuffer.allocate(serverEngine.getSession().getPacketBufferSize());

        ByteBuffer serverAppReadBuffer = ByteBuffer.allocate(
                serverEngine.getSession().getApplicationBufferSize());
        ByteBuffer clientAppReadBuffer = ByteBuffer.allocate(
                clientEngine.getSession().getApplicationBufferSize());

        clientEngine.beginHandshake();
        serverEngine.beginHandshake();

        ByteBuffer empty = ByteBuffer.allocate(0);

        SSLEngineResult clientResult;
        SSLEngineResult serverResult;

        boolean clientHandshakeFinished = false;
        boolean serverHandshakeFinished = false;

        do {
            if (!clientHandshakeFinished) {
                clientResult = clientEngine.wrap(empty, cTOs);
                runDelegatedTasks(clientResult, clientEngine);

                if (isHandshakeFinished(clientResult)) {
                    clientHandshakeFinished = true;
                }
            }

            if (!serverHandshakeFinished) {
                serverResult = serverEngine.wrap(empty, sTOc);
                runDelegatedTasks(serverResult, serverEngine);

                if (isHandshakeFinished(serverResult)) {
                    serverHandshakeFinished = true;
                }
            }

            cTOs.flip();
            sTOc.flip();

            if (!clientHandshakeFinished) {
                clientResult = clientEngine.unwrap(sTOc, clientAppReadBuffer);

                runDelegatedTasks(clientResult, clientEngine);

                if (isHandshakeFinished(clientResult)) {
                    clientHandshakeFinished = true;
                }
            }

            if (!serverHandshakeFinished) {
                serverResult = serverEngine.unwrap(cTOs, serverAppReadBuffer);
                runDelegatedTasks(serverResult, serverEngine);

                if (isHandshakeFinished(serverResult)) {
                    serverHandshakeFinished = true;
                }
            }

            sTOc.compact();
            cTOs.compact();
        } while (!clientHandshakeFinished || !serverHandshakeFinished);
    }

    private static boolean isHandshakeFinished(SSLEngineResult result) {
        return result.getHandshakeStatus() == SSLEngineResult.HandshakeStatus.FINISHED;
    }

    private static void runDelegatedTasks(SSLEngineResult result, SSLEngine engine) {
        if (result.getHandshakeStatus() == SSLEngineResult.HandshakeStatus.NEED_TASK) {
            for (;;) {
                Runnable task = engine.getDelegatedTask();
                if (task == null) {
                    break;
                }
                task.run();
            }
        }
    }


    private static void assertTrue(boolean result) {
        if (!result) {
            throw new AssertionError();
        }
    }

    private static void assertFalse(boolean result) {
        if (result) {
            throw new AssertionError();
        }
    }

    private static void assertEquals(Object o1, Object o2) {
        if (!o1.equals(o2)) {
            throw new AssertionError(o1 + " != " + o2);
        }
    }
}
