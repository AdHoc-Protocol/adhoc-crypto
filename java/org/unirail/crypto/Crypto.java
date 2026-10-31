package org.unirail.crypto;

import java.nio.ByteBuffer;

/**
 * What the native library, adhoc-crypto, does: BoringSSL and the code around it. Addresses, not buffers: take the address of a direct
 * buffer once ({@link #address}) and nothing allocates per call. Nothing here checks bounds: the caller does.
 * <p>
 * The jar of the native library is needed only by what encrypts: this class loads it at the first call, and without it that call
 * is told what is missing. Whatever does not encrypt never comes here.
 */
public final class Crypto
{
    static
    {
        Native.load();
    }

    public static final int CHACHA20_POLY1305 = 0, AES_128_GCM = 1, AES_256_GCM = 2;
    public static final int TAG = 16;

    public static long address(ByteBuffer direct) { return address0(direct); }

    private static native long address0(ByteBuffer direct);

    //#region AEAD: text in place, the tag right after it
    public static native int aeadSize();

    /** The context in the memory at {@code ctx}, of {@link #aeadSize} bytes, aligned to 16. False - a key of a wrong size. */
    public static native boolean aeadInit(int kind, long ctx, byte[] key);

    /** The nonce of Noise: {@code 0⁴ ‖ n}, little-endian. */
    public static native boolean seal(long ctx, long n, long ad, int adLen, long text, int len);

    /** @return false - forged, and the text is cleared to zeros: nothing of it can be taken for data. */
    public static native boolean open(long ctx, long n, long ad, int adLen, long text, int len);

    /** Over arrays. {@code nonce} null - that of Noise, from {@code n}. {@code ad} may be {@code data}. */
    public static native boolean sealArrays(long ctx, byte[] nonce, long n, byte[] ad, int adAt, int adLen, byte[] data, int at, int len);

    public static native boolean openArrays(long ctx, byte[] nonce, long n, byte[] ad, int adAt, int adLen, byte[] data, int at, int len);

    /** The records of Noise.Stream a buffer holds, sealed in one call: the next number, -1 - failed. */
    public static native long sealRecords(long ctx, long n, long address, int bytes);

    /** All the whole records of Noise.Stream at the address, opened in one call: opened bytes {@code << 32 |} records, -1 - the stream is broken. */
    public static native long openRecords(long ctx, long n, long address, int have, int max);
    //#endregion

    //#region the keystream of a stage: Java writes its key and nonce into this memory itself
    public static native int streamSize();

    public static native void streamXor(long state, long address, int len);

    public static native void streamXorArray(long state, byte[] data, int at, int len);
    //#endregion

    //#region the handshake of Noise: one call a message
    public static native int noiseSize();

    public static native int noiseTx();

    public static native int noiseRx();

    public static native void noiseInit(long state, int pattern, boolean initiator, byte[] prologue, byte[] staticSecret, byte[] staticPublic, byte[] peer, byte[] ephemeral);

    public static native int noiseWrite(long state, byte[] dst, int at, byte[] payload, int off, int len);

    public static native int noiseRead(long state, byte[] msg, int at, int len, byte[] payload, int off);
    //#endregion

    /** {@code out = in XOR} the keystream of 32 bytes of key and 12 of nonce, from block {@code counter}, RFC 8439. {@code out} may be {@code in}. */
    public static native void chacha20(long out, long in, long len, long key, long nonce, int counter);

    /** 16 bytes to {@code out}, one-time key of 32 bytes. */
    public static native void poly1305(long out, long key, long in, long len);

    /** 32 bytes to {@code out}. */
    public static native void sha256(long out, long in, long len);

    /** 32 bytes to {@code out}. */
    public static native void hmacSha256(long out, long key, int keyLen, long in, long len);

    public static native void random(byte[] out);

    /** @return false - a low-order peer key. */
    public static native boolean x25519(byte[] shared, byte[] secret, byte[] peer);

    public static native void x25519Public(byte[] pub, byte[] secret);

    public static native void x25519KeyPair(byte[] secret, byte[] pub);

    /** A signing key: 64 bytes of secret, 32 public. {@code seed}, 32 bytes, gives the same pair again; null - a new one. */
    public static native void ed25519KeyPair(byte[] secret, byte[] pub, byte[] seed);

    public static native boolean ed25519Sign(byte[] signature, byte[] secret, long message, long len);

    public static native boolean ed25519Verify(byte[] signature, byte[] pub, long message, long len);

    /**
     * The key of a pair: both sides get the same from their own secret and the other's public key, for {@code label}, what it is for:
     * 32 bytes of key, 12 of base nonce, an id never 0. @return false - a low-order key.
     */
    public static native boolean pairKey(byte[] key, byte[] iv, int[] id, byte[] secret, byte[] their, byte[] label);

    /** A pack on its own: signed by its author, then sealed, in one call. {@code ctx}, {@code secret}: 0 - that step is not chosen. The whole length. */
    public static native int packSeal(long ctx, long n, long secret, long address, int header, int len);

    /** The length of the text; -1 - forged, or not signed by the one it must be. */
    public static native int packOpen(long ctx, long n, long pub, long address, int header, int total);

    private Crypto() { }
}
