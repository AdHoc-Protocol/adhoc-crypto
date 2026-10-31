import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.channels.SocketChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.util.Arrays;
import java.util.function.Predicate;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import org.unirail.crypto.Tls13;

public class TestAll
{
    static int passed, failed;
    static final String OPENSSL = System.getenv("OPENSSL");

    static void check(String name, boolean ok, String note)
    {
        if (ok)
            passed++;
        else
            failed++;
        System.out.println((ok ? "  ok   " : "  FAIL ") + name + (note == null || note.isEmpty() ? "" : "  -- " + note));
    }

    //#region a connection over a socket
    static final class Conn
    {
        final SocketChannel ch;
        final Tls13 t;
        final ByteBuffer in = ByteBuffer.allocateDirect(1 << 17), out = ByteBuffer.allocateDirect(1 << 17);
        final long inAt = Tls13.address(in), outAt = Tls13.address(out);
        final long due;
        int step; //0 - read as much as there is

        int read() throws IOException
        {
            if (step != 0)
                in.limit(Math.min(in.capacity(), in.position() + step));
            final int n = ch.read(in);
            in.limit(in.capacity());
            return n;
        }

        Conn(long ctx, String connectTo, int port, String name, X509TrustManager trust, String alpn, int seconds) throws Exception
        {
            due = System.nanoTime() + seconds * 1_000_000_000L;
            ch = SocketChannel.open();
            ch.socket().connect(new InetSocketAddress(connectTo, port), 8000);
            ch.configureBlocking(false);
            t = new Tls13(ctx, name, trust, alpn);
            out.limit(0);
        }

        void flush() throws IOException
        {
            while (out.hasRemaining())
            {
                if (ch.write(out) == 0)
                    return;
            }
        }

        void handshake() throws Exception
        {
            for (; ; )
            {
                in.flip();
                out.compact();
                int status;
                try
                {
                    status = t.handshake(in, out);
                }
                finally
                {
                    in.compact();
                    out.flip();
                    try
                    {
                        flush();
                    }
                    catch (IOException ignored)
                    {
                    }
                }
                if (status == Tls13.DONE)
                    return;
                final int n = read();
                if (n < 0)
                    throw new IOException("the peer closed in the handshake");
                if (n == 0)
                    Thread.sleep(1);
                if (due < System.nanoTime())
                    throw new IOException("timeout");
            }
        }

        void send(byte[] data) throws Exception
        {
            for (int at = 0; at < data.length; )
            {
                final int n = Math.min(data.length - at, Tls13.MAX_DATA);
                while (out.hasRemaining())
                {
                    flush();
                    Thread.onSpinWait();
                }
                out.clear();
                out.put(Tls13.HEADER, data, at, n);
                out.limit(t.seal(outAt, n));
                flush();
                at += n;
            }
            while (out.hasRemaining())
                flush();
        }

        void sendControl() throws IOException
        {
            if (!t.needsControl)
                return;
            while (out.hasRemaining())
                flush();
            out.clear();
            out.limit(t.control(outAt));
            flush();
        }

        /** One pass over what the socket has. The data goes to the sink, false - the peer's FIN. */
        boolean receive(ByteArrayOutputStream sink) throws IOException
        {
            final int n = read();
            int at = 0;
            final int limit = in.position();
            for (int took; (took = t.open(inAt, at, limit)) > 0; at += took)
            {
                if (t.needsControl)
                    sendControl();
                if (0 < t.dataLen && sink != null)
                    for (int i = 0; i < t.dataLen; i++)
                        sink.write(in.get(t.dataAt + i));
                if (t.closed)
                    break;
            }
            in.limit(limit).position(at);
            in.compact();
            return 0 <= n;
        }

        String until(Predicate<String> done) throws Exception
        {
            final ByteArrayOutputStream sink = new ByteArrayOutputStream();
            while (System.nanoTime() < due)
            {
                final boolean open = receive(sink);
                final String text = sink.toString(StandardCharsets.ISO_8859_1);
                if (done.test(text) || !open || t.closed)
                    return text;
                Thread.sleep(1);
            }
            return sink.toString(StandardCharsets.ISO_8859_1);
        }

        void close()
        {
            try
            {
                t.closeNotify();
                sendControl();
                ch.close();
            }
            catch (IOException ignored)
            {
            }
            t.free();
        }
    }
    //#endregion

    //#region the record layer alone
    static final int[] CIPHERS = {0x1301, 0x1302, 0x1303};

    static byte[] secret(int cipher)
    {
        final byte[] s = new byte[cipher == 0x1302 ? 48 : 32];
        Arrays.fill(s, (byte)cipher);
        return s;
    }

    static boolean fails(Tls13 t, long at, int len)
    {
        try
        {
            t.open(at, 0, len);
            return false;
        }
        catch (IOException e)
        {
            return true;
        }
    }

    static void records() throws Exception
    {
        System.out.println("records");
        final ByteBuffer b = ByteBuffer.allocateDirect(1 << 17);
        final long at = Tls13.address(b);
        for (int cipher : CIPHERS)
        {
            final String name = Integer.toHexString(cipher) + " ";
            Tls13 a = Tls13.recordsOnly(cipher, secret(cipher)), z = Tls13.recordsOnly(cipher, secret(cipher));
            boolean all = true;
            for (int size : new int[]{0, 1, 15, 16, 17, 1024, 16383, 16384})
            {
                for (int i = 0; i < size; i++)
                    b.put(Tls13.HEADER + i, (byte)(i * 31 + size));
                final int n = a.seal(at, size);
                all &= n == size + Tls13.OVERHEAD;
                final int took = z.open(at, 0, n);
                all &= took == n && z.dataLen == size && z.dataAt == Tls13.HEADER;
                for (int i = 0; i < size; i++)
                    all &= b.get(Tls13.HEADER + i) == (byte)(i * 31 + size);
            }
            check(name + "round trip of all sizes", all, null);

            b.put(Tls13.HEADER, (byte)7);
            int n = a.seal(at, 1024);
            boolean partial = true;
            for (int have : new int[]{0, 1, 4, 5, 6, 100, n - 1})
                partial &= z.open(at, 0, have) == 0;
            check(name + "a partial record waits", partial && z.open(at, 0, n) == n, null);

            for (String region : new String[]{"header", "body", "tag"})
            {
                Tls13 x = Tls13.recordsOnly(cipher, secret(cipher)), y = Tls13.recordsOnly(cipher, secret(cipher));
                n = x.seal(at, 100);
                final int spot = region.equals("header") ? 2 : region.equals("body") ? 20 : n - 3;
                b.put(spot, (byte)(b.get(spot) ^ 1));
                check(name + "a forged " + region + " is refused", fails(y, at, n) && y.needsControl, null);
                x.free();
                y.free();
            }

            Tls13 x = Tls13.recordsOnly(cipher, secret(cipher)), y = Tls13.recordsOnly(cipher, secret(cipher));
            n = x.seal(at, 100);
            final byte[] copy = new byte[n];
            b.get(0, copy);
            y.open(at, 0, n);
            b.put(0, copy);
            check(name + "a replay is refused", fails(y, at, n), null);
            x.free();
            y.free();

            x = Tls13.recordsOnly(cipher, secret(cipher));
            y = Tls13.recordsOnly(cipher, secret(cipher));
            b.put(Tls13.HEADER, (byte)9).put(Tls13.HEADER + 1, (byte)8);
            n = Tls13.sealRaw(x, at, 2, 23, 200);
            int took = y.open(at, 0, n);
            check(name + "padding is stripped", took == n && y.dataLen == 2 && b.get(Tls13.HEADER) == 9, null);
            n = x.seal(at, 0);
            took = y.open(at, 0, n);
            check(name + "an empty data record passes", took == n && y.dataLen == 0, null);
            x.free();
            y.free();

            //Tickets, split over records, a real server's habit; then data under the same keys.
            x = Tls13.recordsOnly(cipher, secret(cipher));
            y = Tls13.recordsOnly(cipher, secret(cipher));
            final byte[] ticket = new byte[4 + 300];
            ticket[0] = 4;
            ticket[2] = 1;
            ticket[3] = 44;
            b.put(Tls13.HEADER, ticket, 0, 150);
            n = Tls13.sealRaw(x, at, 150, 22, 0);
            took = y.open(at, 0, n);
            boolean ok = took == n && y.dataLen == 0;
            b.put(Tls13.HEADER, ticket, 150, ticket.length - 150);
            n = Tls13.sealRaw(x, at, ticket.length - 150, 22, 0);
            took = y.open(at, 0, n);
            ok &= took == n && y.dataLen == 0;
            n = x.seal(at, 10);
            ok &= y.open(at, 0, n) == n && y.dataLen == 10;
            check(name + "a ticket split over records is dropped", ok, null);
            x.free();
            y.free();

            //The KeyUpdate we send opens under the old key, what follows under the new one.
            x = Tls13.recordsOnly(cipher, secret(cipher));
            y = Tls13.recordsOnly(cipher, secret(cipher));
            x.txLimit(3);
            ok = true;
            int updates = 0;
            for (int i = 0; i < 20; i++)
            {
                n = x.seal(at, 64);
                ok &= y.open(at, 0, n) == n && y.dataLen == 64;
                if (x.needsControl)
                {
                    n = x.control(at);
                    ok &= y.open(at, 0, n) == n && y.dataLen == 0;
                    updates++;
                }
            }
            check(name + "KeyUpdate turns the keys in both directions", ok && 0 < updates && x.txUpdates() == updates && y.rxUpdates() == updates, updates + " updates");
            x.free();
            y.free();

            //A KeyUpdate that asks for an answer.
            x = Tls13.recordsOnly(cipher, secret(cipher));
            y = Tls13.recordsOnly(cipher, secret(cipher));
            b.put(Tls13.HEADER, new byte[]{24, 0, 0, 1, 1});
            n = Tls13.sealRaw(x, at, 5, 22, 0);
            took = y.open(at, 0, n);
            check(name + "update_requested asks for ours", took == n && y.needsControl && y.rxUpdates() == 1, null);
            x.free();
            y.free();

            //What must end the connection.
            final Object[][] bad = {
                {"a KeyUpdate with data after it", new byte[]{24, 0, 0, 1, 0, 4}, 22},
                {"a KeyUpdate of a wrong size", new byte[]{24, 0, 0, 2, 0, 0}, 22},
                {"a KeyUpdate asking the unknown", new byte[]{24, 0, 0, 1, 2}, 22},
                {"a post-handshake request", new byte[]{13, 0, 0, 0}, 22},
                {"an empty handshake record", new byte[0], 22},
                {"an alert of a wrong size", new byte[]{1}, 21},
                {"a fatal alert", new byte[]{2, 40}, 21},
                {"an unknown content type", new byte[]{1, 2, 3}, 99},
            };
            for (Object[] c : bad)
            {
                x = Tls13.recordsOnly(cipher, secret(cipher));
                y = Tls13.recordsOnly(cipher, secret(cipher));
                final byte[] body = (byte[])c[1];
                b.put(Tls13.HEADER, body);
                n = Tls13.sealRaw(x, at, body.length, (int)c[2], 0);
                check(name + (String)c[0] + " ends it", fails(y, at, n), null);
                x.free();
                y.free();
            }

            x = Tls13.recordsOnly(cipher, secret(cipher));
            y = Tls13.recordsOnly(cipher, secret(cipher));
            b.put(Tls13.HEADER, new byte[]{1, 0});
            n = Tls13.sealRaw(x, at, 2, 21, 0);
            took = y.open(at, 0, n);
            check(name + "close_notify closes", took == n && y.closed, null);
            n = x.seal(at, 5);
            check(name + "nothing passes after it", fails(y, at, n), null);
            x.free();
            y.free();

            x = Tls13.recordsOnly(cipher, secret(cipher));
            b.put(0, (byte)23).put(1, (byte)3).put(2, (byte)3).put(3, (byte)0x41).put(4, (byte)1);
            check(name + "an oversized record ends it", fails(x, at, 40000), null);
            x.free();
            x = Tls13.recordsOnly(cipher, secret(cipher));
            b.put(0, (byte)22).put(3, (byte)0).put(4, (byte)100);
            check(name + "a plaintext record ends it", fails(x, at, 200), null);
            x.free();
            a.free();
            z.free();
        }
    }
    //#endregion

    //#region a JDK server: an independent TLS 1.3, which turns its keys often
    static SSLContext serverContext() throws Exception
    {
        final KeyStore ks = KeyStore.getInstance("PKCS12");
        try (FileInputStream f = new FileInputStream("server.p12"))
        {
            ks.load(f, "benchpass".toCharArray());
        }
        final KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(ks, "benchpass".toCharArray());
        final SSLContext c = SSLContext.getInstance("TLSv1.3");
        c.init(kmf.getKeyManagers(), null, null);
        return c;
    }

    static X509TrustManager trustOf(String pem) throws Exception
    {
        final KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(null, null);
        try (FileInputStream f = new FileInputStream(pem))
        {
            ks.setCertificateEntry("test", CertificateFactory.getInstance("X.509").generateCertificate(f));
        }
        return trust(ks);
    }

    static X509TrustManager trust(KeyStore ks) throws Exception
    {
        final TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(ks);
        return (X509TrustManager)tmf.getTrustManagers()[0];
    }

    static SSLServerSocket jdkServer(SSLContext c, String suite) throws Exception
    {
        final SSLServerSocket s = (SSLServerSocket)c.getServerSocketFactory().createServerSocket(0);
        s.setEnabledProtocols(new String[]{"TLSv1.3"});
        s.setEnabledCipherSuites(new String[]{suite});
        return s;
    }

    static void echo(ServerSocket server)
    {
        final Thread th = new Thread(() -> {
            try (Socket s = server.accept(); InputStream in = s.getInputStream(); OutputStream out = s.getOutputStream())
            {
                final byte[] b = new byte[1 << 16];
                for (int n; 0 < (n = in.read(b)); )
                    out.write(b, 0, n);
            }
            catch (IOException ignored)
            {
            }
        });
        th.setDaemon(true);
        th.start();
    }

    static void jdk(long ctx, X509TrustManager trust) throws Exception
    {
        System.out.println("a JDK server, echo");
        final SSLContext sc = serverContext();
        final String[] suites = {"TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256"};
        for (int k = 0; k < suites.length; k++)
        {
            final long total = 64L << 20;
            try (SSLServerSocket server = jdkServer(sc, suites[k]))
            {
                echo(server);
                final Conn c = new Conn(ctx, "localhost", server.getLocalPort(), "localhost", trust, null, 120);
                c.handshake();
                c.t.txLimit(500);
                long sent = 0, got = 0;
                long txState = 0x1234567L, rxState = 0x1234567L;
                java.util.SplittableRandom sizes = new java.util.SplittableRandom(k);
                boolean same = true;
                while (got < total && System.nanoTime() < c.due)
                {
                    c.flush();
                    if (!c.out.hasRemaining())
                    {
                        if (c.t.needsControl)
                            c.sendControl();
                        else if (sent < total)
                        {
                            final int n = (int)Math.min(total - sent, sizes.nextInt(Tls13.MAX_DATA) + 1);
                            c.out.clear();
                            for (int i = 0; i < n; i++)
                            {
                                txState = txState * 0x5DEECE66DL + 11;
                                c.out.put(Tls13.HEADER + i, (byte)(txState >>> 32));
                            }
                            c.out.limit(c.t.seal(c.outAt, n));
                            sent += n;
                            c.flush();
                        }
                    }
                    final int r = c.ch.read(c.in);
                    if (r < 0)
                        break;
                    int at = 0;
                    final int limit = c.in.position();
                    for (int took; (took = c.t.open(c.inAt, at, limit)) > 0; at += took)
                    {
                        if (c.t.needsControl && !c.out.hasRemaining())
                            c.sendControl();
                        for (int i = 0; i < c.t.dataLen; i++)
                        {
                            rxState = rxState * 0x5DEECE66DL + 11;
                            same &= c.in.get(c.t.dataAt + i) == (byte)(rxState >>> 32);
                        }
                        got += c.t.dataLen;
                    }
                    c.in.limit(limit).position(at);
                    c.in.compact();
                }
                final int tx = c.t.txUpdates(), rx = c.t.rxUpdates(), cipher = c.t.cipher();
                final String group = c.t.group();
                c.close();
                check(suites[k] + " 64 MiB echoed intact", got == total && same, "group " + group + ", our KeyUpdate " + tx + ", peer's " + rx + ", cipher " + Integer.toHexString(cipher));
                check(suites[k] + " keys turned both ways", 0 < tx && 0 < rx && cipher == 0x1301 + k, null);
            }
        }
    }
    //#endregion

    //#region OpenSSL as the server
    static void openssl(long ctx, X509TrustManager trust) throws Exception
    {
        System.out.println("an OpenSSL server, -www");
        int port = 24443;
        for (String suite : new String[]{"TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256"})
        {
            port++;
            final Process p = new ProcessBuilder(OPENSSL, "s_server", "-accept", "" + port, "-tls1_3", "-ciphersuites", suite, "-cert", "cert.pem", "-key", "key.pem", "-www").redirectErrorStream(true).redirectOutput(Path.of("openssl.log").toFile()).start();
            try
            {
                Thread.sleep(700);
                final Conn c = new Conn(ctx, "localhost", port, "localhost", trust, "http/1.1", 15);
                c.handshake();
                c.send("GET / HTTP/1.0\r\n\r\n".getBytes(StandardCharsets.US_ASCII));
                final String text = c.until(s -> s.contains("</HTML>") || s.contains("</BODY>"));
                check(suite, text.startsWith("HTTP/1.0 200") && text.contains(suite.replace("_", "_")), text.length() + " bytes, " + text.lines().findFirst().orElse(""));
                c.close();
            }
            finally
            {
                p.destroyForcibly();
            }
        }
    }
    //#endregion

    //#region certificates
    static void refused(long ctx, String name, String reason, String connect, int port, String host, X509TrustManager trust)
    {
        try
        {
            final Conn c = new Conn(ctx, connect, port, host, trust, null, 15);
            try
            {
                c.handshake();
                check(name, false, "the handshake passed");
            }
            finally
            {
                c.ch.close();
            }
        }
        catch (Exception e)
        {
            check(name, e.getMessage() != null && e.getMessage().contains(reason), e.getMessage());
        }
    }

    static void certificates(long ctx, X509TrustManager trust, X509TrustManager system) throws Exception
    {
        System.out.println("certificates");
        final SSLContext sc = serverContext();
        try (SSLServerSocket server = jdkServer(sc, "TLS_AES_128_GCM_SHA256"))
        {
            echo(server);
            refused(ctx, "another host's certificate", "not of this host", "localhost", server.getLocalPort(), "example.com", trust);
            echo(server);
            refused(ctx, "a certificate nobody trusts", "not trusted", "localhost", server.getLocalPort(), "localhost", system);
        }

        final KeyStore chain = KeyStore.getInstance("PKCS12");
        try (FileInputStream f = new FileInputStream("expired.p12"))
        {
            chain.load(f, "benchpass".toCharArray());
        }
        final KeyStore anchors = KeyStore.getInstance("PKCS12");
        anchors.load(null, null);
        anchors.setCertificateEntry("ca", chain.getCertificate("ca"));
        final KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        final KeyStore leaf = KeyStore.getInstance("PKCS12");
        leaf.load(null, null);
        leaf.setKeyEntry("leaf", chain.getKey("leaf", "benchpass".toCharArray()), "benchpass".toCharArray(), chain.getCertificateChain("leaf"));
        kmf.init(leaf, "benchpass".toCharArray());
        final SSLContext expired = SSLContext.getInstance("TLSv1.3");
        expired.init(kmf.getKeyManagers(), null, null);
        try (SSLServerSocket server = jdkServer(expired, "TLS_AES_128_GCM_SHA256"))
        {
            echo(server);
            refused(ctx, "an expired certificate from a trusted CA", "validity check failed", "localhost", server.getLocalPort(), "localhost", trust(anchors));
        }
    }

    static void trickle(long ctx, X509TrustManager trust) throws Exception
    {
        System.out.println("3 bytes at a time");
        try (SSLServerSocket server = jdkServer(serverContext(), "TLS_AES_128_GCM_SHA256"))
        {
            echo(server);
            final Conn c = new Conn(ctx, "localhost", server.getLocalPort(), "localhost", trust, null, 30);
            c.step = 3;
            c.handshake();
            final byte[] data = new byte[40000];
            new java.util.Random(5).nextBytes(data);
            c.send(data);
            final ByteArrayOutputStream sink = new ByteArrayOutputStream();
            while (sink.size() < data.length && System.nanoTime() < c.due)
                c.receive(sink);
            check("the handshake and 40000 bytes, in pieces of 3", Arrays.equals(sink.toByteArray(), data), sink.size() + " bytes");
            c.close();
        }
    }

    static void online(long ctx, X509TrustManager system) throws Exception
    {
        System.out.println("the internet");
        refused(ctx, "a server with TLS 1.2 only", "", "tls-v1-2.badssl.com", 443, "tls-v1-2.badssl.com", system);
        refused(ctx, "a real server under a name not its own", "not of this host", "www.google.com", 443, "www.example.com", system);

        for (String host : new String[]{"www.cloudflare.com", "www.google.com", "github.com"})
            try
            {
                final Conn c = new Conn(ctx, host, 443, host, system, "http/1.1", 20);
                c.handshake();
                final long ms = 0;
                c.send(("GET / HTTP/1.1\r\nHost: " + host + "\r\nConnection: close\r\nUser-Agent: adhoc-tls-test\r\n\r\n").getBytes(StandardCharsets.US_ASCII));
                final String text = c.until(s -> false);
                final String first = text.lines().findFirst().orElse("");
                check(host, first.startsWith("HTTP/1.1 "), first + ", " + text.length() + " bytes, " + Integer.toHexString(c.t.cipher()) + " " + c.t.group() + (c.t.closed ? ", close_notify" : ""));
                c.close();
            }
            catch (Exception e)
            {
                check(host, false, e.toString());
            }

        try
        {
            final String host = "echo.websocket.org";
            final Conn c = new Conn(ctx, host, 443, host, system, "http/1.1", 20);
            c.handshake();
            c.send(("GET / HTTP/1.1\r\nHost: " + host + "\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n").getBytes(StandardCharsets.US_ASCII));
            final String head = c.until(s -> s.contains("\r\n\r\n"));
            check("wss upgrade", head.startsWith("HTTP/1.1 101"), head.lines().findFirst().orElse(""));
            final byte[] text = "adhoc-wss-test".getBytes(StandardCharsets.US_ASCII);
            final byte[] frame = new byte[6 + text.length];
            frame[0] = (byte)0x81;
            frame[1] = (byte)(0x80 | text.length);
            frame[2] = 1;
            frame[3] = 2;
            frame[4] = 3;
            frame[5] = 4;
            for (int i = 0; i < text.length; i++)
                frame[6 + i] = (byte)(text[i] ^ frame[2 + i % 4]);
            c.send(frame);
            final String echoed = c.until(s -> s.contains("adhoc-wss-test"));
            check("wss frame echoed", echoed.contains("adhoc-wss-test"), echoed.length() + " bytes");
            c.close();
        }
        catch (Exception e)
        {
            check("wss", false, e.toString());
        }
    }
    //#endregion

    public static void main(String[] args) throws Exception
    {
        Security.setProperty("jdk.tls.keyLimits", "AES/GCM/NoPadding KeyUpdate 1048576, ChaCha20-Poly1305 KeyUpdate 1048576");
        final long ctx = Tls13.context();
        final X509TrustManager trust = trustOf("cert.pem"), system = trust((KeyStore)null);
        records();
        jdk(ctx, trust);
        if (OPENSSL != null)
            openssl(ctx, trust);
        certificates(ctx, trust, system);
        trickle(ctx, trust);
        if (args.length != 0 && args[0].equals("online"))
            online(ctx, system);
        System.out.println("passed " + passed + ", failed " + failed);
        System.exit(failed == 0 ? 0 : 1);
    }
}
