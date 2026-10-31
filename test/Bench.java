import com.sun.management.ThreadMXBean;
import java.io.FileInputStream;
import java.lang.management.ManagementFactory;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.security.KeyStore;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.TrustManagerFactory;
import org.unirail.crypto.Tls13;

public class Bench
{
    static final ThreadMXBean MX = (ThreadMXBean)ManagementFactory.getThreadMXBean();
    static final long[] SECRET = new long[0];

    static byte[] secret() { return new byte[32]; }

    //#region in memory: the same shape as the FFM measurement
    static void memory(int size) throws Exception
    {
        final Tls13 a = Tls13.recordsOnly(0x1301, secret()), z = Tls13.recordsOnly(0x1301, secret());
        final ByteBuffer b = ByteBuffer.allocateDirect(40000);
        final long at = Tls13.address(b);
        final long id = Thread.currentThread().threadId();
        long best = 0, allocs = 0, ops = 0;
        for (int round = 0; round < 8; round++)
        {
            long n = 0, t0 = System.nanoTime(), m0 = MX.getThreadAllocatedBytes(id), end = t0 + 1_000_000_000L;
            while (System.nanoTime() < end)
                for (int i = 0; i < 64; i++, n++)
                {
                    final int len = a.seal(at, size);
                    if (z.open(at, 0, len) != len)
                        throw new IllegalStateException();
                }
            final long ns = System.nanoTime() - t0, m1 = MX.getThreadAllocatedBytes(id);
            if (round >= 3)
            {
                best = Math.max(best, n * size * 1000 / ns);
                allocs += m1 - m0;
                ops += n;
            }
        }
        System.out.printf("memory  jar+JNI      %6d %7d MB/s %6d B/record%n", size, best, allocs / ops);
        a.free();
        z.free();
    }
    //#endregion

    //#region over a loopback socket, a sender and a receiver thread
    interface Side { void run(SocketChannel ch, long stopAt, long[] result) throws Exception; }

    static void sockets(String name, int size, Side sender, Side receiver) throws Exception
    {
        try (ServerSocketChannel server = ServerSocketChannel.open().bind(new InetSocketAddress("127.0.0.1", 0)))
        {
            final SocketChannel out = SocketChannel.open(server.getLocalAddress());
            final SocketChannel in = server.accept();
            out.socket().setTcpNoDelay(true);
            in.socket().setTcpNoDelay(true);
            final long[] tx = new long[2], rx = new long[2];
            final long stopAt = System.nanoTime() + 9_000_000_000L;
            final Thread s = new Thread(() -> {
                try
                {
                    sender.run(out, stopAt, tx);
                    out.close();
                }
                catch (Exception e)
                {
                    e.printStackTrace();
                }
            });
            final Thread r = new Thread(() -> {
                try
                {
                    receiver.run(in, stopAt, rx);
                }
                catch (Exception e)
                {
                    e.printStackTrace();
                }
            });
            s.start();
            r.start();
            s.join();
            r.join();
            System.out.printf("socket  %-12s %6d %7d MB/s  sender %6d B/record, receiver %6d B/record%n", name, size, rx[0], tx[1], rx[1]);
        }
    }

    static final long WARM = 4_000_000_000L;

    static void own(int size) throws Exception
    {
        sockets("jar+JNI", size, (ch, stopAt, result) -> {
            final Tls13 t = Tls13.recordsOnly(0x1301, secret());
            final ByteBuffer b = ByteBuffer.allocateDirect(40000);
            final long at = Tls13.address(b), id = Thread.currentThread().threadId();
            long m0 = 0, n = 0;
            final long warm = stopAt - 5_000_000_000L;
            boolean counting = false;
            while (System.nanoTime() < stopAt)
            {
                if (!counting && warm < System.nanoTime())
                {
                    counting = true;
                    m0 = MX.getThreadAllocatedBytes(id);
                    n = 0;
                }
                b.limit(b.capacity()).position(0);
                b.limit(t.seal(at, size));
                while (b.hasRemaining())
                    ch.write(b);
                n++;
            }
            result[1] = (MX.getThreadAllocatedBytes(id) - m0) / Math.max(n, 1);
        }, (ch, stopAt, result) -> {
            final Tls13 t = Tls13.recordsOnly(0x1301, secret());
            final ByteBuffer b = ByteBuffer.allocateDirect(40000);
            final long at = Tls13.address(b), id = Thread.currentThread().threadId();
            long m0 = 0, n = 0, bytes = 0, t0 = 0;
            final long warm = stopAt - 5_000_000_000L;
            boolean counting = false;
            for (; ; )
            {
                if (!counting && warm < System.nanoTime())
                {
                    counting = true;
                    m0 = MX.getThreadAllocatedBytes(id);
                    n = bytes = 0;
                    t0 = System.nanoTime();
                }
                if (ch.read(b) < 0)
                    break;
                int from = 0;
                final int limit = b.position();
                for (int took; (took = t.open(at, from, limit)) > 0; from += took)
                {
                    bytes += t.dataLen;
                    n++;
                }
                b.limit(limit).position(from);
                b.compact();
            }
            result[0] = bytes * 1000 / (System.nanoTime() - t0);
            result[1] = (MX.getThreadAllocatedBytes(id) - m0) / Math.max(n, 1);
        });
    }

    static void step(SSLEngine e, ByteBuffer out, ByteBuffer in, ByteBuffer empty, ByteBuffer sink) throws Exception
    {
        for (; ; )
            switch (e.getHandshakeStatus())
            {
                case NEED_WRAP -> e.wrap(empty, out);
                case NEED_UNWRAP, NEED_UNWRAP_AGAIN -> {
                    in.flip();
                    final SSLEngineResult r = e.unwrap(in, sink);
                    in.compact();
                    sink.clear();
                    if (r.getStatus() == SSLEngineResult.Status.BUFFER_UNDERFLOW)
                        return;
                }
                case NEED_TASK -> {
                    for (Runnable t; (t = e.getDelegatedTask()) != null; )
                        t.run();
                }
                default -> {
                    return;
                }
            }
    }

    static void jdk(int size) throws Exception
    {
        final KeyStore ks = KeyStore.getInstance("PKCS12");
        try (FileInputStream f = new FileInputStream("server.p12"))
        {
            ks.load(f, "benchpass".toCharArray());
        }
        final KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(ks, "benchpass".toCharArray());
        final TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(ks);
        final SSLContext c = SSLContext.getInstance("TLSv1.3");
        c.init(kmf.getKeyManagers(), new javax.net.ssl.TrustManager[]{new javax.net.ssl.X509TrustManager()
        {
            public void checkClientTrusted(java.security.cert.X509Certificate[] a, String b) { }

            public void checkServerTrusted(java.security.cert.X509Certificate[] a, String b) { }

            public java.security.cert.X509Certificate[] getAcceptedIssuers() { return new java.security.cert.X509Certificate[0]; }
        }}, null);
        final SSLEngine cl = c.createSSLEngine("localhost", 443), sv = c.createSSLEngine();
        cl.setUseClientMode(true);
        sv.setUseClientMode(false);
        final String[] suite = {"TLS_AES_128_GCM_SHA256"};
        cl.setEnabledCipherSuites(suite);
        sv.setEnabledCipherSuites(suite);
        final ByteBuffer a2b = ByteBuffer.allocateDirect(100000), b2a = ByteBuffer.allocateDirect(100000), empty = ByteBuffer.allocateDirect(0), sink = ByteBuffer.allocateDirect(40000);
        cl.beginHandshake();
        sv.beginHandshake();
        for (int i = 0; i < 1000 && (cl.getHandshakeStatus() != SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING || sv.getHandshakeStatus() != SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING); i++)
        {
            step(cl, a2b, b2a, empty, sink);
            step(sv, b2a, a2b, empty, sink);
        }
        b2a.flip();
        while (b2a.hasRemaining())
        {
            final SSLEngineResult r = cl.unwrap(b2a, sink);
            sink.clear();
            if (r.bytesConsumed() == 0)
                break;
        }
        sockets("SSLEngine", size, (ch, stopAt, result) -> {
            final ByteBuffer src = ByteBuffer.allocateDirect(size), net = ByteBuffer.allocateDirect(40000);
            final long id = Thread.currentThread().threadId();
            long m0 = 0, n = 0;
            final long warm = stopAt - 5_000_000_000L;
            boolean counting = false;
            while (System.nanoTime() < stopAt)
            {
                if (!counting && warm < System.nanoTime())
                {
                    counting = true;
                    m0 = MX.getThreadAllocatedBytes(id);
                    n = 0;
                }
                src.clear();
                net.clear();
                cl.wrap(src, net);
                net.flip();
                while (net.hasRemaining())
                    ch.write(net);
                n++;
            }
            result[1] = (MX.getThreadAllocatedBytes(id) - m0) / Math.max(n, 1);
        }, (ch, stopAt, result) -> {
            final ByteBuffer net = ByteBuffer.allocateDirect(40000), app = ByteBuffer.allocateDirect(40000);
            final long id = Thread.currentThread().threadId();
            long m0 = 0, n = 0, bytes = 0, t0 = 0;
            final long warm = stopAt - 5_000_000_000L;
            boolean counting = false;
            for (; ; )
            {
                if (!counting && warm < System.nanoTime())
                {
                    counting = true;
                    m0 = MX.getThreadAllocatedBytes(id);
                    n = bytes = 0;
                    t0 = System.nanoTime();
                }
                if (ch.read(net) < 0)
                    break;
                net.flip();
                for (; ; )
                {
                    app.clear();
                    final SSLEngineResult r = sv.unwrap(net, app);
                    if (r.getStatus() != SSLEngineResult.Status.OK)
                        break;
                    bytes += r.bytesProduced();
                    n++;
                }
                net.compact();
            }
            result[0] = bytes * 1000 / (System.nanoTime() - t0);
            result[1] = (MX.getThreadAllocatedBytes(id) - m0) / Math.max(n, 1);
        });
    }

    static void plain(int size) throws Exception
    {
        sockets("no TLS", size, (ch, stopAt, result) -> {
            final ByteBuffer b = ByteBuffer.allocateDirect(size);
            while (System.nanoTime() < stopAt)
            {
                b.clear();
                while (b.hasRemaining())
                    ch.write(b);
            }
        }, (ch, stopAt, result) -> {
            final ByteBuffer b = ByteBuffer.allocateDirect(40000);
            long bytes = 0, t0 = 0;
            final long warm = stopAt - 5_000_000_000L;
            boolean counting = false;
            for (; ; )
            {
                if (!counting && warm < System.nanoTime())
                {
                    counting = true;
                    bytes = 0;
                    t0 = System.nanoTime();
                }
                b.clear();
                final int n = ch.read(b);
                if (n < 0)
                    break;
                bytes += n;
            }
            result[0] = bytes * 1000 / (System.nanoTime() - t0);
        });
    }
    //#endregion

    public static void main(String[] args) throws Exception
    {
        for (int size : new int[]{1024, 16384})
            memory(size);
        for (int size : new int[]{1024, 16384})
        {
            plain(size);
            own(size);
            jdk(size);
        }
        final Tls13 t = Tls13.recordsOnly(0x1301, secret());
        System.out.println("per connection, native: " + t.nativeSize() + " B + two cipher contexts");
    }
}
