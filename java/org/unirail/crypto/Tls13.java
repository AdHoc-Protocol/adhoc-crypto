package org.unirail.crypto;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import javax.net.ssl.X509TrustManager;

/**
 * A TLS 1.3 client. BoringSSL does the handshake and is freed when it ends; every record after that is sealed and opened
 * in place in the caller's direct buffer, in one native call. No I/O here: the caller moves the bytes.
 * <p>
 * One thread at a time per connection. Past the handshake nothing allocates on the path of a record.
 */
public final class Tls13
{
    static
    {
        Native.load();
    }

    /** After {@link #openAll}: where the plaintext ends, where what is not opened yet begins. */
    public int dataEnd, consumedEnd;

    /**
     * Opens all the whole records from {@code at} below {@code limit}, in place, in one call: their data drawn together from {@code at}.
     *
     * @throws IOException the connection is over; {@link #control} has the alert for the peer, when {@link #needsControl}.
     */
    public void openAll(long address, int at, int limit) throws IOException
    {
        final long r = openAll(conn, address, at, limit);
        if (r < 0)
        {
            needsControl = true;
            throw new IOException(error(conn));
        }
        consumedEnd = (int)(r >>> 40);
        dataEnd = (int)(r >>> 2 & 0x3F_FFFF_FFFFL);
        needsControl = (r & 2) != 0;
        if ((r & 1) != 0)
            closed = true;
    }

    public static final int DONE = 0, NEED_READ = 1;
    public static final int HEADER = 5, TAG = 16, MAX_DATA = 16384;
    /** Past the data: the type byte and the tag. */
    public static final int OVERHEAD = HEADER + 1 + TAG;
    /** The longest record a peer may send, what a receive buffer must hold. */
    public static final int MAX_RECORD = HEADER + 16384 + 256;
    /** The longest record {@link #control} writes. */
    public static final int CONTROL_RECORD = OVERHEAD + 5;

    private static final int NEEDS_CONTROL = 1 << 16, PEER_CLOSED = 1 << 17, SIZE = NEEDS_CONTROL - 1;

    private long conn;
    private final X509TrustManager trust;

    /** After {@link #open}: the application data of the record, {@code dataLen} bytes from {@code dataAt}; 0 - it had none. */
    public int dataAt, dataLen;
    /** A record of the connection's own waits to go out before the next data: {@link #control}. */
    public boolean needsControl;
    /** The peer said close_notify. */
    public boolean closed;

    /** What the native chain runs over. */
    public long connection() { return conn; }

    public String error() { return error(conn); }

    /** One per trust policy, for all its connections. */
    public static long context() { return newContext(); }

    public Tls13(long context, String host, X509TrustManager trust, String alpn)
    {
        this.trust = trust;
        conn = newConnection(context, host, alpn == null ? null : alpn.getBytes(StandardCharsets.US_ASCII));
    }

    /** One per certificate, for all its connections: the chain and the key, PEM. */
    public static long serverContext(byte[] chain, byte[] key)
    {
        final long context = newServerContext(chain, key);
        if (context == 0)
            throw new IllegalArgumentException("The certificate chain and the key of TLS: they are not PEM, or do not match.");
        return context;
    }

    /** The server's end of a new connection. */
    public static Tls13 server(long context) { return new Tls13(newServerConnection(context)); }

    private static native long newServerContext(byte[] chain, byte[] key);

    private static native long newServerConnection(long context);

    private Tls13(long conn)
    {
        this.conn = conn;
        trust = null;
    }

    /** The record layer alone, both directions under one secret: for tests and measurements. */
    public static Tls13 recordsOnly(int cipher, byte[] secret) { return new Tls13(recordsOnly0(cipher, secret)); }

    public static long address(ByteBuffer direct) { return Crypto.address(direct); }

    /**
     * @param in  what came from the peer, ready to read: whole records are taken, a partial one stays, and what follows the
     *            handshake stays too, for {@link #open}.
     * @param out what to send goes here, at least {@link #MAX_RECORD} free; send it even when this throws: it may be the alert.
     */
    public int handshake(ByteBuffer in, ByteBuffer out) throws IOException
    {
        final long r = handshake(conn, address(in) + in.position(), in.remaining(), address(out) + out.position(), out.remaining());
        in.position(in.position() + (int)(r >> 24 & 0xFFFFFF));
        out.position(out.position() + (int)(r & 0xFFFFFF));
        final int status = (int)(r >> 48);
        if (status == 2)
            throw refusal == null ? new IOException(error(conn)) : new IOException(error(conn) + ": " + refusal.getMessage(), refusal);
        return status;
    }

    //Called from the handshake. The host name is checked natively, after this.
    private boolean verify(byte[][] chain)
    {
        try
        {
            final CertificateFactory factory = CertificateFactory.getInstance("X.509");
            final X509Certificate[] certs = new X509Certificate[chain.length];
            for (int i = 0; i < chain.length; i++)
                certs[i] = (X509Certificate)factory.generateCertificate(new ByteArrayInputStream(chain[i]));
            trust.checkServerTrusted(certs, "UNKNOWN");
            return true;
        }
        catch (Exception e)
        { //nothing may escape into native code
            refusal = e;
            return false;
        }
    }

    private Exception refusal;

    /**
     * Seals one record in place. The data lies at {@code record + HEADER}, at most {@link #MAX_DATA} bytes; {@link #OVERHEAD} more
     * bytes are written around it.
     *
     * @return the length of the record.
     */
    public int seal(long record, int len)
    {
        final int r = seal(conn, record, len);
        if (r < 0)
            throw new IllegalStateException("seal");
        needsControl = (r & NEEDS_CONTROL) != 0;
        return r & SIZE;
    }

    /**
     * Opens the record at {@code at} in place, when all of it is below {@code limit}.
     *
     * @return the bytes it took, 0 - not all here yet.
     * @throws IOException the connection is over; {@link #control} has the alert for the peer, when {@link #needsControl}.
     */
    public int open(long address, int at, int limit) throws IOException
    {
        final long r = open(conn, address + at, limit - at);
        if (r < 0)
        {
            needsControl = true;
            throw new IOException(error(conn));
        }
        final int flags = (int)r;
        dataAt = at + HEADER;
        dataLen = flags & SIZE;
        needsControl = (flags & NEEDS_CONTROL) != 0;
        if ((flags & PEER_CLOSED) != 0)
            closed = true;
        return (int)(r >>> 32);
    }

    /**
     * Writes the connection's own record: a KeyUpdate, an alert. {@link #CONTROL_RECORD} bytes at most.
     *
     * @return its length, 0 - none.
     */
    public int control(long record) throws IOException
    {
        needsControl = false;
        final int n = control(conn, record);
        if (n < 0)
            throw new IOException(error(conn));
        return n;
    }

    public void closeNotify()
    {
        closeNotify(conn);
        needsControl = true;
    }

    public void txLimit(long records) { txLimit(conn, records); }

    public int cipher() { return info(conn, 0); }

    public int txUpdates() { return info(conn, 1); }

    public int rxUpdates() { return info(conn, 2); }

    public String group() { return groupName(info(conn, 3)); }

    /** The bytes the connection keeps natively, past the handshake, apart from the cipher contexts. */
    public int nativeSize() { return info(conn, 4); }

    /** The keys are gone after this. */
    public void free()
    {
        free(conn);
        conn = 0;
    }

    int sealRaw(long record, int len, int type, int padding) { return sealRaw(conn, record, len, type, padding); }

    /** For tests: a record of any type, with padding. */
    public static int sealRaw(Tls13 t, long record, int len, int type, int padding) { return t.sealRaw(record, len, type, padding); }

    private static native long newContext();

    private static native long newConnection(long context, String host, byte[] alpn);

    private static native long recordsOnly0(int cipher, byte[] secret);

    private native long handshake(long conn, long in, int inLen, long out, int outCap);

    private static native int seal(long conn, long record, int len);

    private static native int sealRaw(long conn, long record, int len, int type, int padding);

    private static native long open(long conn, long record, int have);

    private static native long openAll(long conn, long address, int at, int limit);

    private static native int control(long conn, long record);

    private static native void closeNotify(long conn);

    private static native void txLimit(long conn, long records);

    private static native int info(long conn, int what);

    private static native String groupName(int id);

    private static native String error(long conn);

    private static native void free(long conn);
}
