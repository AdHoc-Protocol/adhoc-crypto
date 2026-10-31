package org.unirail.crypto;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.util.zip.CRC32;

/**
 * Loads the native library the way zstd-jni does: from {@code <os>/<arch>/libadhoc-crypto-<version>.<ext>} inside the jar,
 * unpacked into a temporary file. {@code -DAdHocCryptoNativePath=<file>} takes a file of your own,
 * {@code -DAdHocCryptoTempFolder=<dir>} says where to unpack, and without a matching resource the system library path is tried.
 */
final class Native
{
    private static boolean loaded;

    /** What this code expects of the native library. */
    private static final int ABI = 9;

    private static native int abi();

    private static String version() throws IOException
    {
        try (InputStream in = Native.class.getResourceAsStream("version"))
        {
            if (in == null)
                throw new IOException("the jar has no version");
            return new BufferedReader(new InputStreamReader(in, StandardCharsets.US_ASCII)).readLine().trim();
        }
    }

    private static String os()
    {
        final String name = System.getProperty("os.name").toLowerCase().replace(" ", "");
        if (name.startsWith("win"))
            return "win";
        if (name.startsWith("mac"))
            return "darwin";
        if (name.equals("linux"))
        { //a library built for glibc does not load on Alpine, and the other way round
            final String[] lib = new File("/lib").list();
            if (lib != null)
                for (String file : lib)
                    if (file.startsWith("ld-musl-"))
                        return "linux-musl";
        }
        return name;
    }

    static synchronized void load()
    {
        if (loaded)
            return;
        try
        {
            load_();
        }
        catch (UnsatisfiedLinkError | ExceptionInInitializerError e)
        {
            throw new UnsatisfiedLinkError("Encryption needs the jar of the native library, adhoc-crypto, on the class path, of this platform: " + System.getProperty("os.name") + " " + System.getProperty("os.arch") + ". " + e);
        }
        if (abi() != ABI)
            throw new UnsatisfiedLinkError("The jar adhoc-crypto does not match this lib: take the one of its release.");
    }

    private static void load_()
    {
        final String path = System.getProperty("AdHocCryptoNativePath");
        if (path != null)
        {
            System.load(path);
            loaded = true;
            return;
        }
        try
        {
            final String version = version(), os = os(), name = "libadhoc-crypto-" + version, ext = os.equals("win") ? "dll" : os.equals("darwin") ? "dylib" : "so";
            String arch = System.getProperty("os.arch");
            if (os.equals("darwin") && arch.equals("amd64"))
                arch = "x86_64";
            try (InputStream in = Native.class.getResourceAsStream("/" + os + "/" + arch + "/" + name + "." + ext))
            {
                if (in == null)
                    System.loadLibrary("adhoc-crypto-" + version);
                else
                {
                    final String folder = System.getProperty("AdHocCryptoTempFolder");
                    final File dir = folder == null ? null : new File(folder), tmp = File.createTempFile(name, "." + ext, dir);
                    if (os.equals("win"))
                    { //a loaded dll cannot be deleted, so every run would leave its copy: the runs share one, named by its content. %TEMP% belongs to the user
                        final byte[] lib = in.readAllBytes();
                        final CRC32 crc = new CRC32();
                        crc.update(lib);
                        final File file = new File(tmp.getParentFile(), name + "-" + Long.toHexString(crc.getValue()) + "." + ext);
                        if (file.length() == lib.length)
                            tmp.delete();
                        else
                        {
                            Files.write(tmp.toPath(), lib);
                            try { Files.move(tmp.toPath(), file.toPath(), StandardCopyOption.ATOMIC_MOVE); }
                            catch (IOException another_run_has_it_loaded) { tmp.delete(); }
                        }
                        System.load(file.getAbsolutePath());
                    }
                    else
                    { //a loaded library stays mapped without its file
                        Files.copy(in, tmp.toPath(), StandardCopyOption.REPLACE_EXISTING);
                        System.load(tmp.getAbsolutePath());
                        tmp.delete();
                    }
                }
            }
        }
        catch (IOException e)
        {
            throw new ExceptionInInitializerError(e);
        }
        loaded = true;
    }

    private Native() { }
}
