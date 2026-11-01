# adhoc-crypto

The native library of the [AdHoc protocol](https://github.com/AdHoc-Protocol/AdHoc-protocol) runtimes: ciphers, Noise, TLS 1.3 on BoringSSL, and
the chain of TLS, WebSocket frames and Noise in one call per buffer. The runtimes reach it through JNI (Java) and the plain C exports of
`src/adhoc_crypto.h` (the others).

You do not need this repository to use AdHoc: the library comes with the generated code. It exists to build the binaries.

**The short version.** Java and C# used to encrypt in managed code, and TLS cost garbage on every record. Now one small C library on BoringSSL does all of it:

| Measured on one i9-13900HX | Before | Now |
|:--|--:|--:|
| Java, TCP + Noise, 16 KB sends | 700 MB/s | **1728 MB/s** |
| C#, TCP + Noise, 16 KB sends | 910 MB/s | **1751 MB/s** |
| Java, TLS record of 16 KB, seal + open in memory | 2213 MB/s, 4760 bytes of garbage | **6526 MB/s, 0 bytes** |
| Java, TLS handshake, both ends | 1.32–2.40 ms | **0.218 ms** |
| X25519, one operation | 69 µs | **24 µs** |

The conditions, the caveats and the rest of the numbers are in [The numbers](#the-numbers).

## Why it exists

What the runtimes had:

- **Java** had its own ChaCha20 on the Vector API, its own Poly1305, X25519 and Noise, and refused `wss://`: TLS had to end at Cloudflare. The JDK's `SSLEngine` works on direct buffers,
  yet leaves about 4.7 KB of garbage per pair of records, most of it from JCE. The runtime's buffers are direct and come from the pool of the event loop, and low GC is its first requirement.
- **C#** had its own managed ciphers, and `SslStream`, which is a stream: frame headers and Noise cannot join it in one call.
- **Every language** kept its own copy of the same cryptography, and all of them have to stay byte-compatible on the wire.

What the library is for:

1. **TLS and end-to-end encryption at full speed, with nothing allocated per record.**
2. **One implementation.** Java, C#, Rust, C, C++, Swift, Python and Dart call the same C code. The ciphers are BoringSSL's: assembly on AVX2, AVX-512 and NEON picked at run time, and years of review that a home-grown cipher does not have.
3. **Few crossings of the native boundary.** The layers of a connection are chosen in the language and run inside the library, in one call per buffer each way.
4. **No cost for those who do not use it.** A host that does not encrypt never loads the library, and the Java and C# runtimes compile without it.

## What is inside

| Part | What it does | Used for | Reach it through |
|:--|:--|:--|:--|
| **AEAD**: ChaCha20-Poly1305, AES-128-GCM, AES-256-GCM | seals and opens in place, the tag right after the text | records of TLS and Noise, UDP datagrams, sealed packs | `Crypto.seal`, `open`; `ChaCha20.Aead` |
| **Record batches** | every whole Noise record in a buffer, in one call | the transport under Noise | `Crypto.sealRecords`, `openRecords` |
| **ChaCha20 keystream** | XOR in place, conceals only, proves nothing | the `[ChaCha20]` stage on a pack, a field or a `Stream` | `ChaCha20` stages |
| **X25519** | key agreement, refuses low-order keys | Noise, key pairs | `X25519` |
| **Noise** NK, IK, XX, KK | handshake in one call per message, then the session keys | encryption pinned by key, with no certificate authority | `Chain`, `Noise` |
| **TLS 1.3** client and server | the handshake is BoringSSL's, records are sealed in place in your buffer; KeyUpdate, `close_notify` | browsers, standard clients, port 443, certificates | `Chain.tls`, `tlsServer` |
| **The chain** | TLS, WebSocket frames and Noise in one call per buffer | every connection with a chain | `Chain` |
| **Ed25519 and sealed packs** | signs and seals one buffer in one call, with no connection | a message that is stored, or goes through hosts that must not read it | `Chain.Pack` |
| **SHA-256, HMAC-SHA-256, Poly1305, random** | the building blocks | keys and helpers | `Crypto` |

Root certificates are not here: the language supplies a function of trust (the JDK's roots, the system's roots in C#, on Windows through crypt32 in the others).

## The chain

The layers stack in one order, from the wire, and any of them may be left out:

```text
TCP  →  TLS 1.3  →  WebSocket frames  →  Noise  →  packs
```

A `Chain` is chosen in the language, once, and shared by all the connections that use it. The work happens in the library:

```text
 transmit                                     receive
 the buffer the packs were written to         the buffer the socket read into
   Noise:     "seal these records"              one call:
   WebSocket: "mask this frame"                   opens TLS records in place
   TLS:       "seal this record"                  finds frames, removes the mask
        └── one native call ──▶ socket            opens Noise records in place
                                                       └── a table of pieces ──▶ the packs
```

**On transmit nothing moves.** Room for the headers is reserved in advance: the buffers of the loop are 56 bytes longer than ordered, and the window stays what was ordered. Once the data is written its length is known, the header goes right before it, and sending starts at the header.

**On receive the holes stay.** Data stays where the socket put it, and the headers leave holes. The library writes a table of up to 8 pieces into memory shared with the language, which reads it with no crossing and hands the pieces on one by one. An extra call from the language is cheaper than a copy. Only what cannot be processed otherwise moves:

| What moves | How much | When |
|:--|:--|:--|
| The start of a Noise record, to its continuation | at most a record | a frame or TLS boundary cut the record: a cipher opens only contiguous bytes. Our sender writes whole records, so this is the case of a middlebox that cuts the stream |
| A frame header before a TLS hole | up to 14 bytes | a TLS boundary cut the header |
| The start of an unfinished record, to the start of the buffer | at most a record | the end of the buffer cut it, and the next read needs room |
| The ninth piece and later, to the eighth | the piece | many small frames in one read |
| What the language parses itself | usually a few bytes | PING, CLOSE, or a header cut by the end of the buffer |

**Crossings, measured:** 64 KB buffers, 20000-byte sends.

| Chain | Transmit, calls / buffers | Receive, calls / buffers |
|:--|--:|--:|
| TCP and Noise | 46 / 47 | 47 / 47 |
| WebSocket and Noise | 47 / 48 | 48 / 48 |
| TLS, TCP and Noise | 185 / 185 | 211 / 211 |
| TLS, WebSocket and Noise | 186 / 186 | 73 / 73 |

Elsewhere: 1 call for a Noise handshake message, 1 for a portion of a stage, 1 for a UDP datagram, 0 for a new stage key.

### What a connection costs

There are no permanent data buffers on a connection. A buffer may be as small as AdHoc's minimum window, 256 bytes.

| What | Where it lives |
|:--|:--|
| Transmit, and a partial write to the socket | the loop's buffer: the rest is written when the socket is ready, nothing is sealed twice |
| Receive, and the start of a record waiting for its end | the loop's buffer |
| A record longer than the buffer, the flight of a TLS handshake | a 33047-byte buffer from a pool of the loop, for that time only. A record cannot go up before its tag is checked, its length is the peer's choice, and BoringSSL implements neither `record_size_limit` nor `max_fragment_length` to ask for less |
| Noise handshake messages | two 128-byte arrays, for the handshake only |
| **Keys, permanently** | chain 400 bytes, Noise 1520, TLS 592 + 2 × 576: **3664 bytes** with everything, back to a pool when the connection closes |

On a ResumableTest exchange of about 50 KB a loop made one or two of the 33047-byte buffers, whatever the size of the connection's buffer.

## When to use what

| Scenario | Configuration | Why |
|:--|:--|:--|
| Hosts in one trusted network, as fast as possible | TCP, no key | nothing to pay for; the library is not even loaded |
| Your client and your server over the internet | TCP + server key (Noise NK) | encrypted and pinned by key, no certificates to renew |
| A browser | `wss://` + server key | a browser has only WebSocket and its own TLS; Noise seals past any terminator |
| Clients behind proxies that pass only the web | `wss://` on port 443 | it looks like the web |
| Someone else's client or server | TLS alone | the other side has no Noise |
| Cloudflare Tunnel and direct clients on one port | `chooseChain` by address | see below |
| The server must know the client by key | Noise IK or KK, `onPeer` | the client proves its key in the handshake |
| Two sides that have never met | Noise XX, `onPeer` | each proves its key, your code decides |
| A document for one reader, stored or forwarded | `Chain.Pack` | no connection at all |

**Why both TLS and Noise?** They protect against different things. TLS gives a certificate every client trusts, and it ends wherever a terminator stands. Noise goes end to end, so a CDN carries what it cannot read. Together they encrypt twice and take about half the speed, so use both only where a terminator or a standard client calls for TLS and the content must stay sealed past it.

### Cloudflare Tunnel and directly, on one port

![Two ways from a client to one port of a server. Through Cloudflare Tunnel: wss://cf.example.com carries TLS with Cloudflare's certificate as far as Cloudflare, which ends it and passes the bytes through the tunnel to cloudflared on the server's machine; the machine has no public port for this way, and cloudflared comes to the server over localhost with no TLS. Directly: wss://direct.example.com:8443 carries TLS with the server's own certificate all the way. The server's chooseChain looks at the address of the socket once, at connect: the local address gets null, no TLS; any other address gets the chain with TLS. Noise runs on both ways from the client to the server, through Cloudflare, sealed.](docs/img/cloudflare-and-direct.svg)

```java
final Chain tls = new Chain().tlsServer(certificateChainPem, keyPem); // one context for all the connections
server.key = secret;                                                  // Noise NK on both ways
server.chooseChain = address -> ((InetSocketAddress)address).getAddress().isLoopbackAddress() ? null : tls; // null: the socket as it is, and the key
```

The state comes from a pool when a connection opens and goes back when it closes. Six connections in turn on one port, with TLS and without, made one `Link`.

The choice is made once, at connect. TLS 1.3 has no way to turn off, and a buffer already read could hold open bytes and the start of TLS mixed; a branch for that would sit on the path of every buffer. To change the layers, open a new connection.

With Cloudflare Tunnel the machine has no public port for that way: `cloudflared` dials out to Cloudflare and comes to the server from the local address, so no stranger can arrive that way unless a process runs on the machine. Cloudflare itself sees all that its TLS carried, so keep Noise on this way.

Without a tunnel, Cloudflare comes to a public port from its own addresses, and the function decides by their list. Such an address does not prove the connection is yours: those addresses serve all of Cloudflare's customers. Give that way no more trust than the direct one.

## The API

The whole API in a language is a few choices on `Chain`. Generated code does not change: it runs over any of them.

### Java

The classes are in the Java runtime, `org.unirail`. The runtime compiles without the jar; the first call that encrypts loads the library, and without it that call says what is missing.

```java
// a client: TLS, then Noise IK, and a decision on the proved key
var chain = new Chain().tls("example.com", "http/1.1").noiseIK(serverPublic, mySecret).onPeer(key -> known(key));
tcpClient.connect(chain, address, 5000, (connection, failure) -> { });

// a WebSocket client: wss:// gives TLS by itself, the key goes inside it
wsClient.connect(URI.create("wss://example.com/"), 5000, serverPublic, (connection, failure) -> { });

// a server
server.key = secret;                                                  // Noise NK
server.chain = new Chain().tlsServer(certificateChainPem, keyPem);    // TLS under it
server.handshakeTimeout = 10_000;                                     // 30 s by default, zero or less: none
```

| Call | What it is |
|:--|:--|
| `tls(host, alpn)`, `tlsServer(chainPem, keyPem)` | TLS 1.3 under everything: client and server |
| `noiseNK(serverPublic)`, `noiseNKServer(secret)` | the client knows the server. The same as `connect(…, serverKey, …)` and `host.key` |
| `noiseIK(serverPublic, mySecret)`, `noiseIKServer(secret)` | the client also proves its own key in the first message |
| `noiseXX(mySecret)` | neither knows the other, each proves its key, three messages |
| `noiseKK(mySecret, theirPublic)` | both know each other |
| `onPeer(key -> boolean)` | hears the proved key, `false` closes. Not called where the pattern gives no key: the server of NK |
| `Chain.trust` | an `X509TrustManager` instead of the roots of the JDK; set it before the first connection |
| `host.key`, `host.chain`, `host.chooseChain`, `host.handshakeTimeout` | the server |
| `connect(chain, address or uri, timeout, callback)`, `connect(address or uri, timeout, serverKey, callback)`, `connectTls(address, name, alpn, timeout, serverKey, callback)` | the clients, `Network.TCP.Client` and `Network.TCP.WebSocket.Client` |
| `external.noise.peerKey` | the proved key after the handshake |

A pack on its own; `pair` seals (X25519, then ChaCha20-Poly1305), `signedBy` and `signerOf` sign and check (Ed25519), and either may be left out:

```java
final var out = new Chain.Pack().pair(mySecret, theirPublic, "envelope").signedBy(signingSecret);
final int total = out.seal(buf, 0, length);   // the text lies from Chain.Pack.HEADER; out.size(length) says how much room it takes
final var in = new Chain.Pack().pair(theirSecret, myPublic, "envelope").signerOf(signingPublic);
final int n = in.open(buf, 0, total);         // negative: forged, or not that author
```

Lower down, when you need the pieces: `X25519.keyPair`, `publicKey`, `agree`; `ChaCha20.Aead`; `Noise.NK` (`initiator`, `responder`, `writeMessage`, `readMessage`, `split`, `packKey`); and `org.unirail.crypto.Crypto`, the native calls themselves. `Crypto` takes addresses, not buffers: take the address of a direct buffer once and nothing allocates per call. It checks no bounds.

Several values from native come back in one `long`, and the rest is read from shared memory with no crossing:

| Call | Returns |
|:--|:--|
| `Chain.rx` | `>>> 42` end of what was consumed, `>>> 21 & 0x1FFFFF` end of what the frame parser reads, `& 0x1FFFFF` end of the data; -1: TLS is over |
| `Crypto.openRecords` | `>>> 32` bytes opened, the low 32 bits the number of records; -1: the stream is broken |
| `Tls13.handshake` | `>> 48` state (0 done, 1 needs data, 2 failed), `>> 24 & 0xFFFFFF` taken, `& 0xFFFFFF` written |

The jar has the layout of zstd-jni. On Windows a loaded DLL cannot be deleted, so all runs share one copy named by its content, `libadhoc-crypto-<version>-<crc32>.dll` in `%TEMP%`. Elsewhere a file of random name is deleted right after loading. On Android the library comes from the `.aar`.

### C#

The same library, the same wire, the same layout of shared memory, through the C exports. There are no managed ciphers any more. The names are those of Java in the style of C#:

```csharp
var chain = new Chain().Tls("example.com", "http/1.1").NoiseIK(serverPublic, mySecret).OnPeer(key => Known(key));
tcpClient.Connect(chain, endPoint, 5000, (connection, failure) => { });

var ws = new Network.TCP.WebSocketClient<Channel.Connection>("app", ext => new Channel.Connection(), 1 << 16);
ws.Connect(null, new Uri("wss://example.com/"), 5000, (connection, failure) => { }, serverPublic); // TLS, then Noise NK

server.key         = secret;
server.chooseChain = address => Cloudflare(address) ? null : tls;
```

| What | In C# |
|:--|:--|
| Choice | `Tls`, `TlsServer`, `NoiseNK`, `NoiseNKServer`, `NoiseIK`, `NoiseIKServer`, `NoiseXX`, `NoiseKK`, `OnPeer` |
| Trust | `Chain.trust = certificates => …`, an `X509Certificate2[]` with the leaf first; the roots of the system by default. The host name is checked by native either way |
| Server | `host.key`, `host.chain`, `host.chooseChain`, `host.handshakeTimeout` |
| Clients | `TCP.Client<T>`: `Connect(chain, endPoint, timeout, cb)`, `Connect(endPoint, timeout, cb, serverKey)`, `ConnectTls(endPoint, name, alpn, timeout, cb, serverKey)`. `TCP.WebSocketClient<T>`: `Connect(chain, uri, timeout, cb, serverKey)` |
| Two WebSocket clients | `TCP.WebSocketClient<T>` has its own socket and the whole chain in one call. `TCP.WebSocket.Client<T>` stays on the platform's `ClientWebSocket`: its TLS is `SslStream`, and only Noise is ours |
| Packs | `Chain.Pack`: `Pair`, `SignedBy`, `SignerOf`, `Size`, `Seal(byte[], from, len)`, `Open(byte[], from, total)`; `Crypto.Ed25519KeyPair`, `Ed25519Sign`, `Ed25519Verify`. A pack sealed in Java opens in C# and back |
| Below | `X25519`, `ChaCha20.Aead`, `NoiseNK`, `NoiseStream` |

What differs from Java because of the platform:

| What | How |
|:--|:--|
| Buffers | ordinary `byte[]` from `ArrayPool`, held by `fixed` for the call. So the addresses in the transmit queue are kept as offsets and turned into pointers just before the call |
| Cipher contexts, chain memory, Noise | native memory that does not move: a context must not move |
| Two directions | transmit and receive run on different threads. The TLS handshake is shared under a lock; the data shares nothing, the keys of each direction are separate |
| Finding the library | `ADHOC_CRYPTO_NATIVE`, next to the program, then the folder of this platform in the package `AdHoc.Crypto`, from `<program>.deps.json` |
| The pool of `Link` | one for the process; in Java, one per loop |

### The other languages

| Language | How |
|:--|:--|
| Rust, C, C++, Swift | all through this library: ciphers, Noise, the chain, TLS client and server |
| Python | a layer over the C runtime: `TCP.Chain`, `chain=`, `choose_chain=` |
| Dart | on `dart:io` the same through `dart:ffi`. In a browser, for UDP and for stages, its own ciphers in Dart |
| Go | does not use it, decided by measurement: `crypto/tls`, `crypto/ecdh`, `x/crypto`. Equal on ChaCha, and cgo breaks cross-compiling. The price: two more copies, the private buffer of `crypto/tls`, no pieces |
| TypeScript | TLS is the platform's. Noise and Ed25519 on its own WebAssembly |

The bytes on the wire are the same everywhere: a client in one language connects to a server in any other.

For a new language, every function is in `src/adhoc_crypto.h`. Load the library at run time, not at link time, so that a host that does not encrypt builds and runs without it, and check `adhoc_abi()`.

## Why it is built this way

**Why BoringSSL and a thin wrapper.** Native code alone gives nothing: Monocypher, scalar C, loses to Java with the Vector API. The gain comes only from hand-written assembly. Everything was measured on one machine, and every candidate was first checked byte for byte against the Java implementation:

| Option | X25519 | AEAD 64 B | 300 B | 1200 B | 16 KB |
|:--|--:|--:|--:|--:|--:|
| Java (own X25519, ChaCha20 on the Vector API, own Poly1305) | 69 µs | 260 ns | 388 MB/s | 750 MB/s | 968 MB/s |
| Monocypher, native | 58–65 µs | 270 ns | 450 MB/s | 620 MB/s | 680 MB/s |
| OpenSSL `libcrypto`, EVP API | 45 µs | 260 ns | 709 MB/s | 1650 MB/s | 2900 MB/s |
| Conscrypt 2.7.0, direct calls to `NativeCrypto` | 32 µs | 905 ns | 300 MB/s | 935 MB/s | 2400 MB/s |
| **Own wrapper over BoringSSL** | **24 µs** | **145 ns** | **1300 MB/s** | **2200 MB/s** | **3000 MB/s** |

Conscrypt has the same BoringSSL inside, and pays about 0.8 µs per AEAD call for JNI, a copy of `byte[]` and a context set up every time; its fast path is a private class as well. Libraries over JNA cost more per call. A wrapper with one call per record, a key expanded once and the work in place in a direct buffer gives the maximum.

**Why records in place and not `SSL_write`.** In C, `SSL_write`/`SSL_read` gives 4322 MB/s, and sealing in place with `EVP_AEAD_CTX_seal_scatter`/`open_gather` gives 5820 MB/s. So the handshake goes through `SSL_do_handshake`, and BoringSSL's connection state ends with it; every record after that is ours. For the same reason `tcnative` was not taken as the base, and AWS-LC reached 3640–3800 MB/s on the same test.

**Why JNI and the layout of zstd-jni.** JNI measured the same as FFM (6526 MB/s against 6000–6500), and `Linker.Option.critical` gave nothing. The packaging is the one the Java runtime already lives with: a jar with `<os>/<arch>/lib<name>-<version>.<ext>` and a class that unpacks and loads it.

**Why no Java implementation stays beside it.** The first plan kept Java as a fallback. Two implementations mean two sets of bugs on one wire, and the runtime already needs the library for TLS. The classes that call it live in the runtime, so it still compiles without the jar.

**Why not `memmove`.** On a close overlap of a few bytes it turned out very slow: about 30 µs on a 64 KB buffer, nearly half of the WebSocket speed. Shifts go through small loops, `shift_down` and `shift_up`.

**Why TLS is not a stage like `[Zstd]`.** A stage lies above the frames of the transport and carries bytes one way. TLS lies below the frames of a WebSocket and speaks on its own: handshake, KeyUpdate, alerts. So it stands where both transports meet, between the socket and the connection.

**Why no certificate authority inside.** What to trust is the application's decision, and each platform already keeps its roots.

**Why one repository, apart from the runtimes.** All the languages call one C code, and separate copies would only invite differences between them. The runtimes change often; this code changes rarely. This repository exists so that GitHub Actions can build what one machine cannot.

## The numbers

All on one i9-13900HX (no AVX-512). The tables were measured at different times, in September and October 2026, and are not one run: compare within a table.

### Primitives: Java against BoringSSL

Through the FFM prototype, JDK 26, on P-cores.

| | Java | BoringSSL | |
|:--|--:|--:|--:|
| X25519 | 69 µs | 24 µs | 2.9× |
| AEAD, 64 bytes | 272 ns | 145 ns | 1.9× |
| AEAD, 300 bytes | 756 ns | 231 ns | 3.3× |
| AEAD, 1200 bytes, a datagram | 1518 ns, 0.79 GB/s | 544 ns, 2.2 GB/s | 2.8× |
| AEAD, 16 KB | 15.4 µs, 1.07 GB/s | 5.5 µs, 3.0 GB/s | 2.8× |

A server's Noise handshake takes about 70 µs instead of 200, three times the new connections per second.

### TLS in Java

A record of 16 KB, seal + open on one thread, in memory, no sockets, AES-128-GCM, direct buffers.

| | Speed | Garbage per pair |
|:--|--:|--:|
| `SSLEngine`, JDK 26 | 1694–2213 MB/s | 4760 B |
| JCE directly | 2366 MB/s | 4008 B |
| AWS-LC, FFM, in place | 3640–3800 MB/s | 0 |
| BoringSSL, FFM, in place | 6000–6500 MB/s | 0 |
| **BoringSSL, JNI, in place: this library** | **6526 MB/s** | **0** |

A handshake of both ends: **0.218 ms** against 1.32–2.40 ms in the JDK. Over a loopback socket, 16 KB: **1020 MB/s** against 821 for `SSLEngine`, and 1167 with no TLS at all.

### Java: the whole exchange

`Exchange bench`: Noise in every chain, 64 KB buffers, one thread each way, with about 20 % of outside load on the machine.

| Chain | 64 bytes | 16 KB |
|:--|--:|--:|
| Old Java code, TCP | 205 MB/s | 700 MB/s |
| **TCP** | **403 MB/s** | **1728 MB/s** |
| Old Java code, WebSocket | 175–199 MB/s | 672 MB/s |
| **WebSocket** | **398 MB/s** | **1636 MB/s** |
| TLS over TCP, through a proxy on the JDK | 311 MB/s | 813 MB/s |
| TLS + WebSocket, through a proxy on the JDK | 297 MB/s | 792 MB/s |

The TLS rows go through a proxy on the JDK, so they show rather the proxy's limit. With this TLS on both ends: 939 MB/s at 16 KB and 318 MB/s at 64 bytes under Noise; 1369 MB/s at 16 KB with no Noise.

### C#: the whole exchange

| TCP client and server | 64 bytes | 16 KB |
|:--|--:|--:|
| Noise, old managed code | 207 MB/s | 910 MB/s |
| **Noise, native** | **395 MB/s** | **1751 MB/s** |
| TLS and Noise | 293 MB/s | 811 MB/s |
| TLS, no Noise | - | 1137 MB/s |
| No encryption | - | 1101 MB/s |

| `TCP.WebSocketClient`, `TCP.Server` | 64 bytes | 16 KB |
|:--|--:|--:|
| Noise | 387 MB/s | 1599 MB/s |
| TLS and Noise | 290 MB/s | 766 MB/s |
| TLS, no Noise | - | 1058 MB/s |
| No encryption | - | 1143 MB/s |

With no Noise, sends go in 64-byte portions, so the 64-byte figures say nothing there. TLS above no encryption on TCP is the spread of the measurement, not a gain.

`SslStream` on the same machine: 2500–2600 MB/s for a 16 KB record over in-memory pipes, against 6000–6500 for BoringSSL in the Java tests, so not one benchmark. Its handshake took 64 ms, but that is the first one in a fresh process, so most of it may be .NET warming up. `SslStream` was rejected for its speed and because it is a stream: frames and Noise cannot join it in one call.

### What the numbers do not say

- **Small packs in a steady state gain little from the cipher alone.** With 10 million small packs over 4–6 s, encryption in Java cost TCP about nothing (2.55 against 2.56 million/s) and UDP about 9 %, because the JIT had warmed up by then. That was measured in September, before the chain. On a short run of a second native looks far better: +50 % on UDP, most of it not waiting for the JIT.
- **So the gain lies elsewhere:** large records, a start with no warm-up, handshakes, TLS with no garbage, and the transport path with no copies.
- **TLS and Noise together encrypt twice,** which is about half the speed of Noise alone.
- **A larger buffer is what brings speed:** each send is one write of one buffer.

## How it was checked

| Check | What it covers |
|:--|:--|
| `test/TestAll`, on every tested platform at each push | records, a JDK server with KeyUpdate, OpenSSL when given, certificates; with `online`: Cloudflare, Google, GitHub, wss |
| Noise vectors | the published cacophony vectors for NK, IK, XX, KK; Ed25519 by RFC 8032 |
| Golden output | RFC 7748, RFC 8439, NK messages, pack keys, stages: byte for byte the output of the old Java code |
| Exchange, Java and C# | every chain both ways with the bytes compared; frames of 3, 700 and 20000 bytes in one write; PING in the middle of a record; a stream byte by byte; a flipped byte must close; a refusal by `onPeer` |
| Generated code over real sockets | ResumableTest, ArraysTest, GroupRpc, Stream: 120 runs, 24 connections, buffers from 256 bytes, no transfer errors. ResumableTest compared its sample file byte for byte on all 28 runs |
| Browsers | Chrome 156 and Edge 156 against Java and C# servers on one port, in turn with TLS and without: messages from 1 byte to 1 MB, buffers 256, 4096, 65536, 64 of 64 connections |

Only `TestAll` is in this repository; the others build with the runtimes and generated code.

## Limits

- **No independent security review, no tlsfuzzer.** The ciphers and the handshake are BoringSSL's; the record path, the chain and the frame parser are ours.
- **TLS secrets come through `SSL_CTX_set_keylog_callback`,** which BoringSSL documents as a debugging facility. They stay in native memory and are written nowhere. Cleaner would be a small patch to BoringSSL.
- **TLS 1.3 only.** No session resumption, no client certificates.
- **The certificate is checked on the connection's loop.**
- **`Chain.Pack` is not wired to attributes:** you call it from your code; `[AEAD]` and `[Signed]` do not exist.
- **Under a chain, not everything has been run live.** Multiplex between Java and C#, 24 of 24; tunnels and the Resumable journal on TypeScript on Node only. Noise under UDP is its own, per datagram.
- **Java to C# over a real socket** was run in the matrix of chains; values between languages are not compared, as each language generates its own expected ones. Integrity there rests on the authentication of Noise and TLS and on the set of packs.
- **Rust, C, C++, Swift and Dart read the roots of the system on Windows only:** elsewhere a client without a function of trust refuses every server.

## What a push to `main` does

`.github/workflows/release.yml` builds every platform BoringSSL builds for, tests those a runner can load, and replaces the latest release:

| File | What it is |
|:--|:--|
| `adhoc-crypto.jar` | for Java, in the layout of zstd-jni: `<os>/<arch>/libadhoc-crypto-<version>.<ext>` |
| `adhoc-crypto.aar` | for Java on Android: `jni/<abi>/libadhoc-crypto-<version>.so` |
| `adhoc-crypto.zip` | for the other languages: `<rid>/libadhoc-crypto-<version>.<ext>` |
| `AdHoc.Crypto.nupkg` | for C#: `runtimes/<rid>/native/libadhoc-crypto-<version>.<ext>`, Android too. The generated `Project.csproj` takes it from the address of the latest release, as the generated `pom.xml`, `build.gradle` and `build.sbt` take `adhoc-crypto.jar` |
| `SHA256SUMS.txt` | the sums of the four |

A push to `main` also publishes, each registry when its secrets are set, as `<VERSION>.<number of the run>`: `AdHoc.Crypto` on nuget.org ( `NUGET_USER`, Trusted Publishing ), `org.unirail:adhoc-crypto` on Maven Central ( `MAVEN_CENTRAL_USER`, `MAVEN_CENTRAL_TOKEN`, `GPG_PRIVATE_KEY`, `GPG_PASSPHRASE` ). Without them the jobs are skipped.

| System | Built and tested | Only built |
|:--|:--|:--|
| Windows | x64, arm64 | x86 |
| Linux | x64, arm64 | x86, arm, riscv64 |
| Linux with musl | x64, arm64 | |
| macOS | x64, arm64 | |
| FreeBSD | | x64 |
| Android, API 24, 16 KB pages | | arm64-v8a, armeabi-v7a, x86_64, x86 |

The platforms of zstd-jni that are not here have no BoringSSL: ppc64, ppc64le, s390x, loongarch64, aix, 32-bit FreeBSD.

BoringSSL is its latest main at every build. `VERSION` is the version in the name of the file, and the runtimes look for that name.

## Build by hand

```bash
bash scripts/build.sh linux amd64 "$(cat VERSION)"
bash scripts/jar.sh "$(cat VERSION)"
bash scripts/pack.sh
bash test/test.sh "out/adhoc-crypto-$(cat VERSION).jar"
```

`JAVA_HOME` gives `jni.h` and `jar`; `BORINGSSL` may name a checkout. Linux needs cmake, ninja and g++; Windows clang-cl, cmake, ninja, nasm and vcvars.
`java/` holds the classes that load the library, the same as in the Java runtime: the tests need them.

## License

Apache License 2.0, see `LICENSE` and `NOTICE`.
