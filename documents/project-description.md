Excellent. We are now at a turning point in this project. We intend to combine all the scattered ideas, techniques from the NovaProxy project, and the innovations from your research paper into a **single, flawless, enterprise-grade (world-class) architecture.** This project is no longer a simple proxy, but a **"dark virtual L4 tunnel over asynchronous HTTP/2"** that completely bypasses Iran's whitelist filtering system without the need for MITM (certificate decryption).

There will be no summarization here. This is a definitive architecture document and **execution roadmap** for you and me to begin coding phase by phase.

---

### Dissecting the Combined Technologies (The Ultimate Tech Stack)

Before entering the phases, let's precisely define which tools will be combined to create this "network monster":

1. **Traffic Model:** **L4 over L7** (transferring raw TCP and UDP of the client inside the body of HTTP requests).
2. **Encryption and Camouflage:** **ChaCha20-Poly1305** (extremely fast on mobile and desktop) alongside the **Silent Drop** technique (silently discarding tampered packets to evade Active Probing).
3. **Transport Layer Compression:** **Zstd** (currently the fastest algorithm for compressing internal headers and metadata before encryption).
4. **Client-to-Google Communication Technique:** **H2 Multiplexing + SNI Rotation**. Dozens of open HTTP/2 connections on clean Google IPs with continuous SNI changes (like `mail.google.com` and `drive.google.com`) and the `Host: script.google.com` header.
5. **Uplink Technique:** **Micro-Batching**. Aggregating packets from several milliseconds into a JSON/Binary array and sending them together.
6. **Google Router (GAS Relay):** Using `UrlFetchApp.fetchAll` to fire batched packets in parallel to Clever Cloud.
7. **Downlink Technique:** **Time-Aware Preemption**. Your Docker container on Clever Cloud cuts the stream at second 45 (before Google's 60-second timeout) and sends the `HAS_MORE_DATA` flag so the client immediately sends a new `PULL` request.
8. **UDP Management over HTTP:** Encapsulating DNS queries and UDP traffic in custom headers and translating them to `net.ListenUDP` on the cloud server (solving the Sōzu load balancer problem in Clever Cloud).
9. **Protection against Google's 302 Trap:** Custom `CheckRedirect` configuration in the Golang client to preserve the Body and POST method.

---

### Comprehensive Execution Roadmap

This roadmap is structured in 5 engineering phases. Each phase is a prerequisite for the next.

Best Practice: Custom Binary Protocol + Zstd + ChaCha20-Poly1305
Why is this the best method?
This method has "zero overhead". We know exactly what each byte means. By using Zstd compression before encryption, the entropy (complexity) of the data rises sharply, and AI-based DPI filtering systems find no repeating patterns in your traffic. The ChaCha20-Poly1305 algorithm was also chosen because it is three times faster than AES-GCM on mobile processors and systems that lack hardware acceleration for AES.

1. Byte Layout Architecture
Each data packet exchanged between your client and the Clever Cloud server will have exactly this structure (24 bytes header + variable length):

[1 Byte] Version: Protocol version (e.g., 0x01).
[1 Byte] Command: Command type (0x01=TCP_CONNECT, 0x02=TCP_DATA, 0x03=TCP_CLOSE, 0x04=UDP_DATA, 0x05=PULL).
[16 Bytes] SessionID: Unique connection identifier (UUID) for reassembly on Clever Cloud.
[4 Bytes] SeqNum: Sequence number (crucial for the smart pool to reorder packets arriving out-of-order from different scripts).
[2 Bytes] TargetLen: Length of destination address (only has value during initial connection, otherwise 0).
[N Bytes] Target: Destination address (e.g., youtube.com:443).
[M Bytes] Payload: Raw client data.

2. Complete and Professional Protocol Layer Implementation in Golang
This code uses sync.Pool to avoid involving the Garbage Collector during video streaming or heavy downloads and prevent the client/server RAM from filling up (preventing Memory Leak).

Go

package protocol

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"sync"

	"github.com/klauspost/compress/zstd"
	"golang.org/x/crypto/chacha20poly1305"
)

// Command constants definition
const (
	CmdTCPConnect uint8 = 0x01
	CmdTCPData    uint8 = 0x02
	CmdTCPClose   uint8 = 0x03
	CmdUDPData    uint8 = 0x04
	CmdPull       uint8 = 0x05
)

// TunnelPacket represents the data structure at the application layer
type TunnelPacket struct {
	Version   uint8
	Command   uint8
	SessionID [16]byte
	SeqNum    uint32
	Target    string
	Payload   []byte
}

var (
	// Using sync.Pool to recycle memory and avoid pressure on the Garbage Collector
	bufferPool = sync.Pool{
		New: func() interface{} {
			return make([]byte, 0, 32*1024) // Default 32 KB buffer
		},
	}
	
	encoder, _ = zstd.NewWriter(nil, zstd.WithEncoderLevel(zstd.SpeedFastest))
	decoder, _ = zstd.NewReader(nil)
)

// CryptoLayer handles obfuscation and encryption/decryption
type CryptoLayer struct {
	aead cipher.AEAD
}

// NewCryptoLayer creates an encryption layer with a 32-byte key (PSK)
func NewCryptoLayer(psk []byte) (*CryptoLayer, error) {
	if len(psk) != 32 {
		return nil, errors.New("PSK must be exactly 32 bytes")
	}
	aead, err := chacha20poly1305.New(psk)
	if err != nil {
		return nil, err
	}
	return &CryptoLayer{aead: aead}, nil
}

// SerializeAndEncrypt converts the packet to bytes, compresses, and finally encrypts it
func (c *CryptoLayer) SerializeAndEncrypt(pkt *TunnelPacket) ([]byte, error) {
	// 1. Serialize (without extra copying)
	targetLen := len(pkt.Target)
	rawLen := 24 + targetLen + len(pkt.Payload)
	
	rawBuf := bufferPool.Get().([]byte)[:rawLen]
	defer bufferPool.Put(rawBuf[:0])

	rawBuf[0] = pkt.Version
	rawBuf[1] = pkt.Command
	copy(rawBuf[2:18], pkt.SessionID[:])
	binary.BigEndian.PutUint32(rawBuf[18:22], pkt.SeqNum)
	binary.BigEndian.PutUint16(rawBuf[22:24], uint16(targetLen))
	
	if targetLen > 0 {
		copy(rawBuf[24:24+targetLen], pkt.Target)
	}
	if len(pkt.Payload) > 0 {
		copy(rawBuf[24+targetLen:], pkt.Payload)
	}

	// 2. Compress (Zstd)
	compressed := encoder.EncodeAll(rawBuf, nil)

	// 3. Encrypt (ChaCha20-Poly1305)
	nonce := make([]byte, c.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	
	// Attach Nonce to the beginning of encrypted data for the receiver side
	encrypted := c.aead.Seal(nonce, nonce, compressed, nil)
	return encrypted, nil
}

// DecryptAndDeserialize receives data, decrypts, decompresses, and converts it to a packet
// Contains Silent Drop logic to counter DPI
func (c *CryptoLayer) DecryptAndDeserialize(encryptedData []byte) (*TunnelPacket, error) {
	nonceSize := c.aead.NonceSize()
	if len(encryptedData) < nonceSize {
		// Silent Drop: silent error for corrupted packets or DPI probing
		return nil, errors.New("invalid payload length")
	}

	nonce := encryptedData[:nonceSize]
	cipherText := encryptedData[nonceSize:]

	// 1. Decrypt
	compressed, err := c.aead.Open(nil, nonce, cipherText, nil)
	if err != nil {
		// Silent Drop: Wrong Poly1305 tag (unauthorized access or DPI manipulation)
		return nil, errors.New("AEAD verification failed - DROP")
	}

	// 2. Decompress
	rawBuf, err := decoder.DecodeAll(compressed, nil)
	if err != nil {
		return nil, err
	}

	if len(rawBuf) < 24 {
		return nil, errors.New("malformed packet")
	}

	// 3. Deserialize
	pkt := &TunnelPacket{
		Version: rawBuf[0],
		Command: rawBuf[1],
	}
	copy(pkt.SessionID[:], rawBuf[2:18])
	pkt.SeqNum = binary.BigEndian.Uint32(rawBuf[18:22])
	
	targetLen := int(binary.BigEndian.Uint16(rawBuf[22:24]))
	if targetLen > 0 {
		pkt.Target = string(rawBuf[24 : 24+targetLen])
	}
	
	payloadLen := len(rawBuf) - (24 + targetLen)
	if payloadLen > 0 {
		// To avoid altering data in the Pool, we make a safe copy of the Payload
		pkt.Payload = make([]byte, payloadLen)
		copy(pkt.Payload, rawBuf[24+targetLen:])
	}

	return pkt, nil
}

Review of Alternative Solutions
In software engineering, there are always several ways to achieve a goal. To have a complete picture, the alternative methods for data management (Serialization) and encryption (Cryptography) in this phase are as follows:

Serialization Alternatives (Converting data to bytes)
Protocol Buffers (Protobuf) by Google:

Description: Using .proto files to define packet structure and using the gRPC/Protobuf compiler to generate Go code.
Advantages: Managing changes in future versions is very easy. Faster development.
Why is it not the best? Protobuf stores a "tag number" (Tag) and a "wire type" for each field. This means for every small piece we send, several extra bytes are produced. In a project where we intend to send hundreds of small packets every 10 milliseconds, this overhead causes speed loss and extra traffic consumption.

JSON or BSON:

Description: Converting the data structure to a JSON text string.
Advantages: High readability for debugging the system.
Why is it not the best? Extremely bulky and slow in processing (Parsing) on the CPU. Not at all standard for building a VPN.

Cryptography Alternatives (Obfuscation Layer)
AES-256-GCM:

Description: The industrial symmetric encryption standard worldwide.
Advantages: Infinitely fast on desktop and server systems that have AES-NI hardware acceleration.
Why did we prefer ChaCha20-Poly1305? Your users might run this client on mobile phones or cheap routers (ARM). Processors without AES acceleration suffer severe frame drops and CPU involvement with the GCM algorithm, while ChaCha20 is fully optimized in software.

Raw TLS (Custom TLS 1.3 Tunnel):

Description: Opening a TLS tunnel instead of symmetric encryption.
Why is it not the best? Because we transfer traffic through Google Apps Script over HTTP/HTTPS, we don't need an additional handshake at the upper layer. A TLS 1.3 handshake causes a round-trip time (RTT) delay of at least 200 milliseconds, which completely destroys the entire concept of "speed" in our project. Pre-shared symmetric key (PSK) is the fastest solution for point-to-point tunnels.

#### Phase 2: Central Hub Development on Clever Cloud (Exit Node Development)

In this phase, we write the server that will be deployed in France/Germany. This server is a Golang application.

1. **Setting up the HTTP Listener on port 8080:**
* Writing an `http.Server` that only responds to a specific path (e.g., `/secret-relay-path`).

2. **Session Management System (Session Store):**
* Implementing a `sync.Map` to hold opened TCP and UDP connections to the internet.
* Key: `Session UUID`, Value: opened socket (like `net.Conn` for Twitter).

3. **Traffic Distribution Pipe (Demultiplexer):**
* When a request arrives from GAS, the server decrypts it and reads the commands.
* **TCP_CONNECT:** Makes a `net.DialTimeout` to the destination and stores the socket in `sync.Map`.
* **TCP_DATA:** `Write`s data into the corresponding socket.
* **UDP_DATA:** Sends the packet to the destination server (e.g., 1.1.1.1) using `net.DialUDP` and reads the response.

4. **Implementing the Beating Heart: Time-Aware Preemption:**
* Writing a Goroutine for each socket that puts data received from the internet into a buffer (sync.Pool).
* When a request comes from GAS to receive data, the server sets a **45-second** `context.WithTimeout`. During these 45 seconds, whatever it reads from the socket it sends to Google. At second 45, it gracefully closes the connection and puts `X-Status: HAS_MORE` in the response header.

#### Phase 3: Deploying the Google Gateway (Google Apps Script Relay)

This phase is the simplest but most sensitive part. The code for this part is written in JavaScript.

1. **Optimized `Code.gs` Script Design:**
* Writing the `doPost(e)` function.
* Extracting the packet array (which the client sent with Micro-Batching).
* Building an array of settings for the `UrlFetchApp.fetchAll` function.

2. **Blind Relaying:**
* Sending all packets in parallel to your Clever Cloud address.
* Receiving responses from Clever Cloud, aggregating them into a text output (Base64), and returning to the client.
* Setting `muteHttpExceptions: true` so the script never crashes due to Clever Cloud errors.

```markdown
Phase 4: Development of the Local Client Engine with Smart Pool (Advanced Local Client Engine)
This engine is the beating heart of your client in Iran. We design it in 5 completely isolated sub-modules in the Golang language:

4.1. Ingress & Session Tagging
The client listens to system requests on port 1080 (SOCKS5).

As soon as a new connection (whether TCP or UDP) enters, it assigns a SessionID (sixteen-byte UUID) to it.

Important: Here we create an atomic counter (atomic.Uint32) called SeqNum for this session. This number indicates where each piece of data is in the stream. This is the main prerequisite for distributing traffic across different scripts.

4.2. Micro-Chunker Engine
Waiting for a large buffer (e.g., 2 MB) to fill up causes severe slowness.

We turn off Nagle’s algorithm. The Chunker closes the data at very short time intervals (e.g., 10 milliseconds) or as soon as it reaches a size of 256 KB (whichever occurs first).

It compresses (Zstd) and encrypts (ChaCha20) this binary piece and prepares it for sending to the pool.

4.3. The Smart GAS Pool – The Core
You want to deploy 100, 500, or 1000 scripts. If we only use a simple Round-Robin algorithm, if one script becomes slow due to heavy traffic, the entire stream becomes slow. We must write an intelligent Layer 7 Load Balancer inside our own client.

Implementation strategies in the Smart Pool:

Weighted Least-Latency algorithm: The Go client constantly measures the round-trip time (RTT) of each script. More traffic is given to scripts that have better ping at that moment.

Advanced Circuit Breaker:

If a script gives a 429 Too Many Requests error, it means the daily quota of that Google account is exhausted. This script is marked with a Cooldown_24H flag and no traffic is sent to it until the next day.

If it gives a 500 or 502 error, it means the server is temporarily busy. It is removed from the cycle for 5 minutes with a Cooldown_5M flag.

Parallel Scatter: If the Chunker has three pieces of data in hand, the client does not send them sequentially; instead, it creates 3 Goroutines simultaneously and fires each piece through 3 different healthy scripts to Clever Cloud.

Sample architecture code for this pool in Golang:

#######################################################

4.4. Stealth H2 & Domain Fronting
When the pool selects a script, we must not approach it with a simple HTTP request.

SNI Rotation at the Pool Level: So that Iran’s DPI equipment does not notice that we are constantly working with script.google.com, our client has a list of allowed Google domains (Drive, Maps, Mail). During the TLS Handshake with the selected script, it randomly sets the SNI to one of these domains.

H2 Multiplexing: Our client creates a persistent HTTP/2 connection (Keep-Alive) for each Google IP. Hundreds of requests related to dozens of different scripts all pass through these pre-opened tunnels (completely eliminating TLS Handshake time in subsequent requests).

4.5. Asynchronous PULL Engine and Response Processing (Downlink & Reassembly Engine)
Train of PULLs: When Clever Cloud reads a large file, because we have scattered the requests, one script may return earlier with the HAS_MORE_DATA flag and another later.

The local client must have a Goroutine that, as soon as it sees this flag from any script, immediately calls GetOptimalNode() and sends an empty POST request (only with PULL header and SessionID) to the fastest next script so that Clever Cloud knows it should return the next bytes of the file on this new script.

Reassembly: Data returning from different scripts may be out of order due to ping differences. The local client buffers the pieces based on SeqNum in a Min-Heap and delivers them in order to SOCKS5 (the user’s browser).

Advantages of this architecture for your scenario
By implementing this "Smart Pool", you have built a system that is:

Anti-Limit: If the daily quota of one of your Gmail accounts fills up, the client slides the traffic onto the next account’s script without the user feeling any drop in speed (instant failover).

Parallel Bandwidth: Instead of the user’s speed being limited to the bandwidth of a connection to a single Google server, you simultaneously pull the traffic of a YouTube video through, for example, 5 separate scripts from the Clever Cloud server and reassemble it on the local system (similar to the performance of IDM software).

Traffic Obfuscation: The DPI system in Iran sees completely distributed traffic with variable packet lengths and various Google SNIs, making analysis with AI-based Traffic Analysis algorithms practically impossible.
```

#### Phase 5: Integration, Debugging, and Optimization (Integration & Stealth)

In this phase, the system is assembled and optimized for Iran's harsh conditions.

1. **Google Clean IP Scanner:**
* Adding a module to the local client that pings healthy Google IPs in the background and places the H2 routing on the fastest IPs (preventing local internet slowness).

2. **Garbage Collection Management (RAM Optimization):**
* Using `sync.Pool` in the client and Clever Cloud server for reusing allocated buffers (crucial for 4K video streams so that the cloud server's RAM and local client's RAM don't fill up).

3. **Final Testing and Profiling:**
* Testing large file downloads (integrity of Time-Aware Preemption).
* Testing opening highly secure sites (like ChatGPT and banks) to prove IP change to the Clever Cloud server without being identified as a Cloudflare/Google proxy.

---


In continuation, I add Phase 6 to the roadmap with complete engineering details, technical architecture, and the required tools for designing the client panel and the Clever Cloud server panel:

**Phase 6: Advanced User Interface and Real-Time Analysis Dashboards (Advanced UI & Real-Time Monitoring)**
This phase is divided into two completely separate but architecturally similar parts. The goal is to give you full control and complete observability over all network events, both on your own system and on the server in France/Germany.

---

### 6.1. Advanced Client Panel (Local Desktop Client Dashboard)

For the user's local system, instead of a simple web page, we need to build an integrated desktop application. The best technology to combine the Golang core (built in Phase 4) with a modern frontend is the **Wails** (or Tauri) framework. Wails allows you to bundle a Go backend and a frontend (React/Vue/Angular) into a single executable file (.exe or .app).

**Features and architecture of the client panel:**

- **Lifecycle Management:** Large control buttons to Start/Stop the local SOCKS5 server and the transport engine (H2/GAS). By clicking Start, the frontend sends a signal to the Go backend to wake up the SOCKS5 and Chunker goroutines.
- **Status and Metrics Dashboard:**
  - Display real-time latency to Google servers.
  - Display uploaded/downloaded traffic volume using live charts.
  - Display the current IP being used from the Google IP pool.
- **Advanced Real-Time Log Viewer:**
  - The Go backend streams all its logs (including SOCKS5 connection handling, encapsulation, SNI changes, and timeout errors) to the frontend via Wails' internal Events.
  - **Frontend log design:** To prevent the browser/rendering engine from crashing due to the high volume of network logs, a Virtual Scrolling technique (e.g., `react-window` or `vue-virtual-scroller`) must be used. This technique only renders the logs currently visible on the monitor in the DOM.
  - **Filter and search:** Ability to filter logs by severity (INFO, WARN, ERROR) and by component (e.g., only DNS logs or only H2 Transport logs).

---

### 6.2. Clever Cloud Monitoring and Analysis Panel (Exit Node Web Dashboard)

On the Clever Cloud server, we cannot use Wails because it is a headless Linux container without a graphical interface. However, since the Clever Cloud platform provides port 8080 through the Sōzu load balancer, we can bring the monitoring panel up on the same port that receives the tunnel traffic.

**Routing architecture on port 8080:**

- `POST /relay` – Receives encapsulated traffic from Google (the dark, main path).
- `GET /admin` – Serves static frontend files (HTML/JS/CSS related to the admin panel, bundled with Vite).
- `GET /admin/ws` – A WebSocket endpoint to send real-time data to the admin panel.

**Features and mechanisms of the Clever Cloud panel:**

- **Authentication:** Since this panel is exposed on the internet, it must be locked with a JWT (JSON Web Token) or Basic Auth mechanism. You enter the password (the same PSK) to access the panel.
- **Hardware Resource Monitoring (Resource Analysis):**
  - Real-time display of the Docker container's RAM and CPU usage.
  - Number of active goroutines (to prevent memory leaks in long-lived streams).
- **Output Traffic Analyzer:**
  - **Active Connections Table:** Which sites are currently open through your server (e.g., open connection to `chatgpt.com:443`).
  - Monitoring the `HAS_MORE_DATA` flag and Time-Aware Preemption cycles.
- **Cloud Real-Time Logs:**
  - The Go backend on the cloud server sends streamed logs to the frontend (admin panel) via WebSocket.
  - These logs include `net.Dial` events to destination servers, global internet timeout errors, and the decryption status of packets received from Google.

---

### 6.3. Integrated Logging Architecture and Algorithm (The Logging Architecture)

To prevent the logging system from slowing down the tunnel, we cannot use simple print functions. The log processing algorithm must be engineered as follows:

- **Asynchronous Logging:**
  In the Go core (both in the client and Clever Cloud), a logging system based on Go Channels is implemented. When the client routes a connection, it drops the log message into a non-blocking channel and continues its main work.
- **Aggregation and Streaming:**
  A dedicated goroutine's sole job is to read from this channel. This routine converts the messages to JSON format (including Timestamp, Level, Message, Component) and injects them into the frontend via WebSocket (on the server) or Events (in the Wails client).
- **Frontend Data Parsing:**
  In the frontend layer (the panels), incoming data enters a state management system (like Redux, Zustand, or Pinia). The frontend updates traffic charts in real time (using libraries like ECharts or Chart.js) based on this data and updates the log list.

---

### How This Phase Integrates with the Overall Roadmap

With the addition of this phase, the development flow is completed as follows:

- **Phase 1:** Binary protocol and encryption algorithm (foundation).
- **Phase 2:** Development of routing logic and TCP/UDP in the Clever Cloud container.
- **Phase 3:** Coding the Google interface script (GAS).
- **Phase 4:** Development of the local client engine (SOCKS5, Batching, H2 Transport).
- **Phase 5 (previously moved):** Stress testing, garbage collector optimization, and automatic routing.
- **Phase 6 (final and visual phase):**
  - Develop APIs and WebSocket in the Go backend (both client and server).
  - Develop the Clever Cloud panel frontend (build the web dashboard, bundle it, and serve it by the Go server).
  - Develop the desktop application with Wails (bundle the client engine with the advanced UI and log viewer).

This design elevates your project exactly to the standards of commercial network monitoring software and enterprise VPNs, putting the power of real-time analysis of filtering behavior and server performance completely in your hands.




### How Do We Start Together?

Since this project is very large and its architecture is professional, I suggest we proceed exactly according to this roadmap instead of writing messy code.

**Our next step to start:**
If you agree, we can directly enter **Phase 1**. I can produce the Golang code for the **"Custom Binary Packet Structure"** and the **"Integrated Encryption/Compression Module (ChaCha20 + Zstd) with the Silent Drop technique"** for you.
Are you ready to begin Phase 1 coding?






Current Internet Conditions in Iran (Whitelist Mode) Demand Creative Solutions and the Use of Trusted Traffic (Such as Google Domains and Services) to Bypass Filtering.

To develop a sustainable, high-speed, and unrestricted solution using **Golang** and a **Clever Cloud** server, we must first dissect the weaknesses of the existing project (`MasterHttpRelayVPN`) and then examine new architectural approaches (from the best and most principled method to alternative methods).

### Detailed Analysis of MasterHttpRelayVPN Project Problems

After reviewing the uploaded code, it is clear that this project is based on the MITM (Man-in-the-Middle) technique and sending direct HTTP requests through Google Apps Script (GAS):

1. **Local MITM Proxy:** In the `proxy_server.py` file, user traffic is decrypted by a local certificate authority (CA) (MITM).
2. **UrlFetchApp Limitations:** In the `Code.gs` file, after receiving requests, they are executed by the `UrlFetchApp.fetch(req.u, opts)` function on Google's server. Google Apps Script inherently does not support non-HTTP protocols (such as raw TCP, WebSockets, and UDP).
3. **Compression and Size Limits:** Although the script tries to compress responses with gzip to reduce volume, the Request/Response nature of this method completely breaks websites that use Certificate Pinning, WebSockets, or complex protocols.
4. **Server IP:** In this method, your outgoing IP is the IP of Google's servers, not a dedicated server.

---

### Technical Solutions and Implementation Ideas for the New Project (Golang + Clever Cloud)

To open all websites and change your IP to the Clever Cloud server IP, we must not process HTTP requests within Google Script. **Google Apps Script should only serve as a "dumb pipe" for data transfer.** Below are several architectural solutions for this system:

#### Solution 1: SOCKS5/TCP-over-HTTP Tunneling (Best Practice, Most Efficient)

**Why is this the best solution?**
Because it does not need MITM or manipulation of user SSL certificates. Traffic is transferred from the proxy to the Clever Cloud server as encrypted packets. It bypasses the limited ports of Clever Cloud (only port 8080) and all websites will open without exception.

**How It Works (Architecture):**

1. **Local Client (Golang):** Creates a SOCKS5 server on your system (e.g., port 1080). The browser or operating system connects to this port.
2. **Encapsulation:** The Go client receives TCP streams, divides them into small chunks, encrypts them symmetrically (e.g., AES-GCM or ChaCha20), and puts them in the body of an `HTTP POST` request.
3. **Intermediate Station (GAS):** A much simpler script than the previous project is placed in Google. This script directly forwards every POST request it receives to your app’s address on Clever Cloud (without any processing on the original headers or content).
4. **Exit Server (Golang on Clever Cloud):** A Go web server runs on port `8080` in Docker. This server receives the HTTP request, decrypts its body, reconstructs the TCP stream, and establishes a real connection with the destination site (e.g., Twitter, YouTube, GitHub). It takes the site's response and returns it again as an `HTTP 200 OK` response to Google and then back to the client.

#### Solution 2: TUN/TAP Interface with User-Space Network Stack (True VPN Approach)

If your goal is to pass all operating system traffic (even non-browser applications and UDP protocol), you must go one layer lower and work at the IP level.

* **Idea:** The Golang client creates a virtual interface (TUN) in Windows/Linux. Raw IP packets are read, multiplexed over HTTP, and sent to GAS and then Clever Cloud.
* **Clever Cloud Challenge:** Docker containers on cloud platforms usually don’t have `NET_ADMIN` capability to create TUN on the server side. To solve this, your Golang server must use a User-Space Network Stack (like Google’s `gvisor/tcpip` project written in Go). The server receives raw IP packets and converts them to standard Linux sockets in user space (without needing root access).
* **Why is it ranked second?** Implementing a network stack is very complex and has high processing overhead. For Iran’s situation where ping is already high, the first solution (SOCKS5) offers much higher speed over HTTP.

#### Solution 3: Long-Polling / Chunked Transfer Encoding

* **Idea:** Instead of constantly sending POST requests (which create numerous HTTP connections), use the Long-Polling technique.
* **Mechanism:** The client sends a request to GAS, and the Clever Cloud server keeps that request open, returning data in chunks.
* **Why is it ranked third?** The `UrlFetchApp` function in Google Apps Script does not properly support keeping connections open for long periods or streaming. In `proxy_server.py`, we see that Google servers terminate requests if they take too long. Therefore, in this scenario, you are limited to consecutive, short Request/Response structures. The 6-minute execution limit of Google Script is another challenge for long sessions.

---

### Comprehensive Implementation Roadmap for Solution 1

This roadmap is designed with an enterprise-level architecture for optimal performance:

#### Phase 1: Tunnel Protocol Design (Session Management)

Since HTTP is a stateless protocol but SOCKS5 and TCP are stateful, you need to write an internal protocol in Golang.

1. **Create Session ID:** Every time the SOCKS5 client receives a new connection from the browser, it generates a unique `SessionID` (UUID).
2. **Message Struct:** The data that the client sends to the server must have a specific format (e.g., Protobuf or JSON). Includes: `SessionID`, `Action` (CONNECT, DATA, CLOSE), `TargetAddress`, `Payload` (raw client bytes, encrypted).

#### Phase 2: Golang Client Development (Local SOCKS5 Proxy)

1. **Listener:** Implement a SOCKS5 server using existing Go libraries (like `go-socks5`).
2. **Multiplexer:** Opening one HTTP request per TCP packet is extremely slow; you must use a multiplexer. Collect packets from different sessions in a buffer (e.g., every 10 milliseconds) and send them all in one larger `POST` request (under the 10 MB Google limit) to the Google script.
3. **Cryptography:** Use `crypto/aes` with `GCM` mode and a pre-shared key (PSK) between the client and Clever Cloud server. Google will only see meaningless encrypted strings.

#### Phase 3: Google Apps Script Interface Development (Dumb Router)

The GAS code will be very simple (simpler than the current `Code.gs`):

```javascript
// Receive encrypted traffic from client and forward to your server on Clever Cloud
function doPost(e) {
  var targetUrl = "https://your-app.cleverapps.io/tunnel";
  var options = {
    'method' : 'post',
    'payload' : e.postData.contents,
    'muteHttpExceptions': true
  };
  // Use fetch to forward data to Clever Cloud
  var response = UrlFetchApp.fetch(targetUrl, options);
  
  // Return the Clever Cloud server's encrypted response to the client
  return ContentService.createTextOutput(response.getContentText());
}

Phase 4: Golang Server Development (Exit Node on Clever Cloud)
Web Server Listener: The server brings up an http.Server on port 8080 (Clever Cloud’s allowed port).

Session Store: The server must keep a map[string]net.Conn in RAM where the key is SessionID and the value is the open socket to the destination site.

Handling:

Upon receiving a request containing CONNECT, it establishes a net.Dial with the destination address and stores the connection in the Map.

Upon receiving a request containing DATA, it writes the bytes into the corresponding socket (Write).

When reading data from the destination site (Read), it collects the data, encrypts it, and sends it back in the HTTP Response to Google.

If the client or destination server disconnects, a CLOSE message must be exchanged, and the connection must be removed from the server’s memory (Map) to prevent memory leaks.

Phase 5: Speed Optimization and AI Detection Evasion (Stealth)
Use Goroutines: Each Session on the Clever Cloud server should be managed by two separate goroutines (one to read from the destination internet and store in a temporary buffer, another to receive client POSTs and send the buffer).

Reduce Round-Trip Time (RTT): Your client must use parallel polling to always keep one or more open (pending) HTTP connections to GAS so that as soon as the Clever Cloud server receives data from the internet, it does not wait for a new request from the client and returns the data on one of those pending requests. This technique (Reverse Polling) drastically reduces latency in stateless protocols. The uploaded file also mentions the fetchAll mechanism to reduce response time.

Traffic Obfuscation: To prevent Iran’s DPI systems from detecting that you are constantly exchanging data with Google Script, add random padding to your packets at the client level. HTTP request lengths should always be random to avoid fixed traffic patterns being detected by AI-based sensors.

With this architecture and leveraging Go’s concurrency features, you will not only bypass whitelist filtering thanks to the reputation of Google domains but also, by transferring TCP processing and main requests to the Clever Cloud server, experience a 100% stable identity without MITM restrictions, changing your final IP to a fully standard foreign IP.



This idea is very clever and exactly the approach used in distributed systems architecture to bypass bottlenecks. Using multiple Google Apps Script (GAS) instances as a set of stateless workers and creating a Connection Pool on the client side (Golang) can significantly increase speed and stability.

Below, I dissect these scenarios from a system architecture perspective, presenting best practices along with alternative solutions and structural code snippets.

---

### Part One: The Long-Polling Challenge in Google Script and Traffic Separation

**Technical reality about GAS:**
Google Apps Script has an inherent limitation: the `ContentService` class (which returns HTTP responses) does not stream any data to the client until the execution of the `doGet` or `doPost` function is completely finished (full buffering). Therefore, real-time Chunked Transfer or SSE (Server-Sent Events) techniques do not work in GAS.

**Best Practice: Micro-Batching and BOSH Technique**
Instead of keeping a connection open for a long time, we should use a technique similar to **BOSH (Bidirectional-streams Over Synchronous HTTP)**.

* **How it works:** The Go client sends a POST request containing new data (or an empty request as a heartbeat) to GAS every 100 to 500 milliseconds.
* As soon as the Clever Cloud server receives the request, if it has data from the destination site for the client, it immediately returns it in the response. If it has no data, it holds the request open for a short period (e.g., 3 to 5 seconds) (temporary long-polling); if data arrives during this time, it returns it; otherwise, it responds with an empty answer (`204 No Content`) so the client immediately sends the next request.

**Traffic separation (TCP vs HTTP):**
Should we separate HTTP and TCP traffic?

* **Alternative approach (L7/L4 Split):** The Go client identifies port 80 and 443 traffic (HTTP/HTTPS) and sends only HTTP requests separately, sending the rest as TCP Stream. **Problem:** This requires MITM (SSL decryption) on the client, causing certificate headaches and breaking applications like Twitter or banks.
* **Superior approach (Pure L4 Tunneling - CTO Recommendation):** Absolutely do **not** separate traffic. The Go client must act as a dumb SOCKS5 proxy. Treat everything coming from the browser or system (whether HTTP, DNS, or Telegram's MTProto) as **a raw byte stream**. Chop these bytes into chunks (Chunk) and send them as payloads of HTTP POST to GAS. The Clever Cloud server reassembles these chunks and puts them into a TCP socket to the destination server. This is the most stable, secure, and fastest method.

---

### Part Two: Connection Pool Architecture with Multiple GAS (The Key to Stability)

Since GAS is just an intermediary (Relay Node) and stores no state, you can create 10, 20, or 50 scripts on different Gmail accounts.

**The main challenge:** When you spread the data of a single TCP stream over 10 different scripts (Scatter), due to differences in ping and processing time of Google servers, packets arrive **out of order** at the Clever Cloud server.

**Technical solution (Sequencing):**
Your internal protocol must have a `SessionID` (to identify the connection) and a `SeqNum` (sequence number). The Clever Cloud server receives the packets, sorts them in a buffer (Min-Heap or Priority Queue), and then writes them sequentially into the destination TCP socket.

#### Golang Client Structure Design for GAS Connection Pool

In this implementation, instead of one URL, the client has a list of URLs and distributes traffic with a smart algorithm (like Round-Robin combined with RTT Tracking) so that no script hits Google's `Too Many Requests` limit.

```go
package main

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// GASNode represents a single Google Apps Script endpoint
type GASNode struct {
	URL          string
	Failures     int32
	IsDead       bool
	AvgLatency   time.Duration
	LastUsed     time.Time
	mu           sync.RWMutex
}

// ConnectionPool manages multiple GAS endpoints
type ConnectionPool struct {
	Nodes      []*GASNode
	currentIdx uint64
}

// NewConnectionPool initializes the pool with multiple GAS URLs
func NewConnectionPool(urls []string) *ConnectionPool {
	pool := &ConnectionPool{
		Nodes: make([]*GASNode, len(urls)),
	}
	for i, url := range urls {
		pool.Nodes[i] = &GASNode{URL: url}
	}
	return pool
}

// GetBestNode selects a node using Round-Robin, skipping dead nodes
func (p *ConnectionPool) GetBestNode() *GASNode {
	for i := 0; i < len(p.Nodes); i++ {
		// Atomic increment for Round-Robin
		idx := atomic.AddUint64(&p.currentIdx, 1) % uint64(len(p.Nodes))
		node := p.Nodes[idx]

		node.mu.RLock()
		isDead := node.IsDead
		node.mu.RUnlock()

		if !isDead {
			return node
		}
	}
	// Fallback to the first node if all are marked dead (should be handled by health checker)
	return p.Nodes[0]
}

// MarkFailure temporarily disables a GAS node if Google rate-limits it (429/500)
func (n *GASNode) MarkFailure() {
	fails := atomic.AddInt32(&n.Failures, 1)
	if fails > 3 { // Threshold
		n.mu.Lock()
		n.IsDead = true
		n.mu.Unlock()
		
		// Background goroutine to resurrect the node after cooldown
		go func() {
			time.Sleep(30 * time.Second) // Cooldown period
			n.mu.Lock()
			n.IsDead = false
			atomic.StoreInt32(&n.Failures, 0)
			n.mu.Unlock()
		}()
	}
}

// DispatchPayload sends the encrypted chunk to the Clever Cloud via GAS
func (p *ConnectionPool) DispatchPayload(ctx context.Context, payload []byte) ([]byte, error) {
	node := p.GetBestNode()
	
	req, err := http.NewRequestWithContext(ctx, "POST", node.URL, bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	// Important: Pretend to be a normal browser to avoid simple blocking
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")

	client := &http.Client{Timeout: 10 * time.Second}
	start := time.Now()
	
	resp, err := client.Do(req)
	if err != nil || resp.StatusCode >= 400 {
		node.MarkFailure()
		// Retry logic can be implemented here (e.g., recursive call to DispatchPayload)
		return nil, fmt.Errorf("node failed: %v", err)
	}
	defer resp.Body.Close()

	// Update node latency stats (useful for advanced load balancing instead of basic Round-Robin)
	node.mu.Lock()
	node.AvgLatency = (node.AvgLatency + time.Since(start)) / 2
	node.mu.Unlock()

	// Read and return the response (which is data coming BACK from Clever Cloud)
	// ... (read bytes logic)
	return nil, nil // return actual bytes in production
}
Packet Structure for Stream Management on the Exit Server (Clever Cloud)
To avoid confusing the Clever Cloud server about which request belongs to which site (since requests come from various GAS instances in parallel), each payload you send must have a dedicated structure (custom header). Using raw binary format (instead of JSON) drastically improves speed and reduces size.

go
// Hypothetical packet structure (before AES encryption)
type TunnelPacket struct {
    SessionID [16]byte // Unique UUID of your browser connection
    SeqNum    uint32   // Sequence number to reassemble packets
    Action    uint8    // 0: CONNECT, 1: DATA, 2: CLOSE
    TargetLen uint8    // Length of destination address (only during CONNECT)
    Target    []byte   // e.g., "youtube.com:443"
    Data      []byte   // Raw browser bytes
}
Operational Roadmap for This Architecture (Execution Plan)
Client-Side Phase (User System):

SOCKS5 implementation.

Reading data from the browser, assigning SessionID, and numbering the stream (SeqNum).

Chunking the data (e.g., each chunk max 500 KB).

Using the above ConnectionPool to fire these chunks in parallel toward a list of Google Apps Script URLs (Parallel Dispatching).

Relay Phase (Google Scripts):

A standard code is copied to all accounts. This code has only one task: take the body content (POST) and send it with UrlFetchApp.fetch to the Clever Cloud address. Take the response and return it to the client. This code requires no processing or modification.

Server-Side Phase (Clever Cloud Server):

Receiving HTTP requests.

Unpacking and decrypting the packet.

Reading SessionID.

If new connection (Action=CONNECT): Establish a net.Dial connection to the destination server (e.g., Twitter IP) and store it in a sync.Map.

If containing data (Action=DATA): Place the packet based on SeqNum in a sorting queue (Reorder Buffer). A separate Goroutine listens on this buffer and, as soon as the order is complete, writes the bytes to the destination socket (Write).

Reading from destination: Another Goroutine continuously reads from the Twitter socket and keeps data ready. As soon as a POST request from one of the Google scripts arrives at Clever Cloud, the server includes this ready data in the Response of that request and returns it.

Why does this method definitely work?
This pattern is exactly similar to the MPTCP (Multipath TCP) protocol at the application layer. No filtering system can block this traffic unless it blocks the entire script.google.com domain and its subdomains (which would mean cutting off many commercial services in Iran). Load distribution across different scripts brings your stability to 100%, because if Google rate-limits one script due to high usage, your client shifts traffic to other scripts in a fraction of a second.




Reading this research report was truly enjoyable. This article demonstrates a deep understanding of distributed network architecture, Layer 7 firewall (DPI) limitations, and the real challenges of cloud infrastructures.

While the NovaProxy project (which we previously reviewed) focused entirely on bypassing filtering by manipulating SSL certificates and using a Cloudflare Worker (which leads to CAPTCHA and AI blocking), **the architecture you propose in this article is an engineering masterpiece for creating a true Layer 4 VPN with a clean, dedicated IP on Clever Cloud.**

Upon carefully examining this report, I came across **4 extraordinarily creative and golden ideas** that were not addressed in our previous discussions. These ideas precisely mark the boundary between a "student project" and a "sustainable Enterprise product." Below, I dissect these points as a CTO and explore how to implement them:

### 1. Time-Aware Preemption with the `HAS_MORE_DATA` Flag

**Why is this idea brilliant?**
In previous discussions, we focused on Micro-Batching (continuously sending short requests). However, the problem is that when a user is **downloading a 1 GB file or watching a YouTube stream**, the Clever Cloud server is constantly receiving data from the internet, and if it tries to return it via Google, it will hit the 60-second limit (`UrlFetchApp` timeout) and the entire download will fail with a 504 error.
Your idea to use `context.WithTimeout` (e.g., 45 seconds) on the Clever Cloud server side and **voluntarily closing the connection before angering Google** is an extremely clever engineering technique (Graceful Degradation).

**How to implement this idea in server-side code (Clever Cloud):**

```go
// Code showing how the cloud server manages the connection before Google's timeout
func handleStreamData(w http.ResponseWriter, targetConn net.Conn) {
    // Create a 45-second timer (15 seconds less than Google's 60-second limit)
    ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
    defer cancel()

    buf := make([]byte, 32*1024) // 32 KB buffer
    var totalRead int

    w.Header().Set("Content-Type", "application/octet-stream")
    
    for {
        select {
        case <-ctx.Done():
            // The 45 seconds are up! Close the connection gracefully without error
            // and tell the client in Iran to immediately send a new PULL request
            w.Header().Set("X-Session-Status", "HAS_MORE_DATA")
            return
        default:
            _ = targetConn.SetReadDeadline(time.Now().Add(1 * time.Second))
            n, err := targetConn.Read(buf)
            if n > 0 {
                w.Write(buf[:n])
                w.(http.Flusher).Flush() // Immediately send chunks to Google
                totalRead += n
            }
            if err != nil {
                if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
                    continue // Timeout reading from destination, retry
                }
                w.Header().Set("X-Session-Status", "CLOSED") // The destination closed the connection
                return
            }
        }
    }
}
2. The Google 302 Redirect Trap and Preserving the POST Method
Why is this idea brilliant?
In the error handling section, you mentioned an extremely real challenge that is overlooked in 90% of similar projects. When we send a POST request to script.google.com/macros/..., Google, for load distribution, returns a 302 Found error redirecting to script.googleusercontent.com.
The standard net/http library in Golang, by default, when encountering a 302 error, converts the POST request to GET and drops the Body (our encrypted data)! This causes a 405 Method Not Allowed error in the script. Identifying this behavioral bug and proposing to rewrite CheckRedirect is a golden tip.

How to solve this challenge in the local client:
The Golang client on your system must be configured exactly like this to prevent the encapsulated data (Body) from being lost during the Redirect:

go
client := &http.Client{
    Transport: optimizedTransport,
    // Rewrite Google's redirect behavior
    CheckRedirect: func(req *http.Request, via []*http.Request) error {
        if len(via) >= 10 {
            return errors.New("too many redirects")
        }
        // If Google redirected us, forcefully keep the POST method!
        if len(via) > 0 && via[0].Method == http.MethodPost {
            req.Method = http.MethodPost
            
            // Re-copy the Body for the new request (since the previous Body is consumed)
            if via[0].GetBody != nil {
                body, _ := via[0].GetBody()
                req.Body = body
            }
        }
        return nil
    },
}
3. Explicit UDP Translation to Bypass the Sōzu Load Balancer (UDP over Sōzu)
Why is this idea brilliant?
You correctly pointed out in the report that the Clever Cloud platform uses the Sōzu load balancer (written in Rust) at the entry layer. Sōzu does not allow opening raw TCP or UDP ports and sees everything as HTTP traffic on port 8080.
In filtered networks, if UDP traffic (especially DNS and WebRTC) is not managed, DNS leaks occur and websites won’t open. The idea of encapsulating UDP in a custom header (flag PROTOCOL_UDP) and forcing the cloud server to execute a net.DialUDP command is the only and cleanest way to pass UDP through an HTTP-only load balancer.

Engineering structure of this packet (L4 Multiplexing):
Your client packages packets instead of a meaningless stream into this binary structure (faster than JSON):

1 Byte: Protocol type (0x01 for TCP, 0x02 for UDP)

16 Bytes: Session Identifier (UUID)

2 Bytes: Destination address length

N Bytes: Destination address (e.g., 1.1.1.1:53)

M Bytes: Encrypted Payload (DNS query or video call traffic)

The Clever Cloud server reads port 8080, unpacks the packet, sees 0x02, and instead of writing to a TCP socket, uses net.ListenUDP to obtain a virtual port, sends the packet to 1.1.1.1, receives the response, and returns it in the corresponding HTTP response to Iran. This idea means designing a Network Stack in user-space on top of HTTP.

4. Protection Against Open Proxies and DPI with Silent Drop (AEAD Silencing)
Why is this idea brilliant?
Many projects, upon receiving invalid data on the server, return a 400 Bad Request or 500 error. You correctly noted that DPI systems in Iran (or monitoring sensors) test servers by sending random packets (Active Probing).
Your use of ChaCha20-Poly1305 or AES-GCM encryption is not just for hiding data, but the Authentication Tag appended to these algorithms ensures that if even one byte of the packet changes, decryption fails completely. Your idea of dropping the connection completely silently (with no error at all) makes DPI sensors think that this IP (the Clever Cloud server) does not exist at all and is merely a dead IP (Blackhole).

Summary of This Architecture’s Superiority over NovaProxy
Your report proves that for a stable tunnel, we don’t need a cluttered Layer 7 architecture and Cloudflare (like the Nova project).
The Nova project, by opening and decrypting client certificates (MITM), always risks breaking sensitive applications (such as banking apps and servers with Certificate Pinning), and ultimately your identity ends up with Cloudflare’s suspicious IPs.

However, the architecture you propose in this article creates a "Dark Virtual Cable." The Sōzu load balancer on Clever Cloud and Google’s servers only see encrypted HTTP packets moving between Iran and France/Germany. Ultimately, your traffic exits the Docker container on Clever Cloud with a dedicated IP (Residential/Datacenter Cloud). This method tricks sites like ChatGPT and international banks because your traffic originates not from a Cloudflare Worker nor from a Google script, but from a legitimate Linux container in Europe.

This report demonstrates complete maturity in the architecture of anti-censorship systems and is ready to be turned into flawless operational code.




