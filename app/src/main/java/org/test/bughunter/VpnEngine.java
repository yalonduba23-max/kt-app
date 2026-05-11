package org.test.bughunter;

import android.content.Intent;
import android.net.VpnService;
import android.os.ParcelFileDescriptor;
import android.util.Log;
import java.io.*;
import java.net.*;
import java.nio.ByteBuffer;
import java.util.UUID;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import okhttp3.*;
import okio.ByteString;

public class VpnEngine extends VpnService {

    private static final String TAG = "BugHunter";

    private ParcelFileDescriptor vpnInterface;
    private ExecutorService       executor;
    private ServerSocket          socksServer;
    private volatile boolean      running = false;

    private String bug;
    private String server;
    private String connectIp;
    private int    port;
    private String wsPath;
    private String uuid;

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        if (intent == null) return START_NOT_STICKY;

        String action = intent.getStringExtra("action");
        if ("STOP".equals(action)) {
            stopVpn();
            return START_NOT_STICKY;
        }

        // Read config from intent
        bug       = intent.getStringExtra("bug");
        server    = intent.getStringExtra("server");
        connectIp = intent.getStringExtra("connect_ip");
        port      = intent.getIntExtra("port", 443);
        wsPath    = intent.getStringExtra("ws_path");
        uuid      = intent.getStringExtra("uuid");

        startVpn();
        return START_STICKY;
    }

    private void startVpn() {
        try {
            Builder builder = new Builder();
            builder.setSession("BugHunter")
                   .setMtu(1500)
                   .addAddress("10.0.0.1", 24)
                   .addRoute("0.0.0.0", 0)
                   .addDnsServer("8.8.8.8");
            vpnInterface = builder.establish();
            Log.d(TAG, "TUN interface established");
        } catch (Exception e) {
            Log.e(TAG, "Failed to establish TUN", e);
            return;
        }

        running  = true;
        executor = Executors.newCachedThreadPool();

        // Start SOCKS5 proxy on 127.0.0.1:1080
        executor.submit(() -> {
            try {
                socksServer = new ServerSocket(1080, 50,
                    InetAddress.getByName("127.0.0.1"));
                Log.d(TAG, "SOCKS5 listening on :1080");
                while (running) {
                    Socket client = socksServer.accept();
                    executor.submit(() -> handleSocks(client));
                }
            } catch (Exception e) {
                if (running) Log.e(TAG, "SOCKS server error", e);
            }
        });

        // Route TUN packets to SOCKS proxy
        executor.submit(this::routeTunToSocks);
    }

    private void stopVpn() {
        running = false;
        try { if (socksServer  != null) socksServer.close();  } catch (Exception ignored) {}
        try { if (vpnInterface != null) vpnInterface.close(); } catch (Exception ignored) {}
        if (executor != null) executor.shutdownNow();
        stopSelf();
    }

    // ── TUN → SOCKS routing ────────────────────────────────────────────────
    private void routeTunToSocks() {
        FileInputStream  in  = new FileInputStream(vpnInterface.getFileDescriptor());
        FileOutputStream out = new FileOutputStream(vpnInterface.getFileDescriptor());
        byte[] packet = new byte[32767];
        while (running) {
            try {
                int len = in.read(packet);
                if (len <= 0) continue;
                // Basic IPv4 TCP packet parsing to extract dest addr/port
                // and forward via local SOCKS proxy
                ByteBuffer buf = ByteBuffer.wrap(packet, 0, len);
                int version = (buf.get(0) >> 4) & 0xF;
                if (version != 4) continue; // IPv4 only

                int protocol = buf.get(9) & 0xFF;
                if (protocol != 6) continue; // TCP only

                byte[] srcAddr  = new byte[4];
                byte[] destAddr = new byte[4];
                buf.position(12); buf.get(srcAddr);
                buf.position(16); buf.get(destAddr);

                int ihl     = (buf.get(0) & 0xF) * 4;
                buf.position(ihl + 2);
                int destPort = buf.getShort() & 0xFFFF;

                String destIp = (destAddr[0] & 0xFF) + "." + (destAddr[1] & 0xFF) + "."
                              + (destAddr[2] & 0xFF) + "." + (destAddr[3] & 0xFF);

                // Only handle non-local traffic
                if (!destIp.startsWith("10.0.0") && !destIp.startsWith("127.")) {
                    executor.submit(() -> tunnelViaSocks(destIp, destPort));
                }
            } catch (Exception ignored) {}
        }
    }

    // ── SOCKS5 handler ─────────────────────────────────────────────────────
    private void handleSocks(Socket client) {
        try {
            InputStream  in  = client.getInputStream();
            OutputStream out = client.getOutputStream();

            // Greeting
            in.read(); // version
            int nmethods = in.read();
            in.readNBytes(nmethods);
            out.write(new byte[]{0x05, 0x00}); // no auth

            // Request
            in.read(); // version
            int cmd  = in.read();
            in.read(); // reserved
            int atyp = in.read();

            String addr;
            if (atyp == 1) {
                byte[] ip = in.readNBytes(4);
                addr = (ip[0]&0xFF)+"."+( ip[1]&0xFF)+"."+( ip[2]&0xFF)+"."+( ip[3]&0xFF);
            } else if (atyp == 3) {
                int len = in.read();
                addr = new String(in.readNBytes(len));
            } else {
                client.close(); return;
            }
            int destPort = ((in.read() & 0xFF) << 8) | (in.read() & 0xFF);

            out.write(new byte[]{0x05,0x00,0x00,0x01, 0,0,0,0, 0,0});

            if (cmd == 1) { // CONNECT
                tunnelVlessWss(addr, destPort, in, out);
            }
        } catch (Exception e) {
            Log.d(TAG, "SOCKS handler: " + e.getMessage());
        } finally {
            try { client.close(); } catch (Exception ignored) {}
        }
    }

    // ── VLESS over WSS tunnel ──────────────────────────────────────────────
    private void tunnelVlessWss(String destAddr, int destPort,
                                InputStream clientIn, OutputStream clientOut) {
        OkHttpClient client = new OkHttpClient.Builder()
            .hostnameVerifier((h, s) -> true) // SNI set manually
            .build();

        Request request = new Request.Builder()
            .url("https://" + connectIp + ":" + port + wsPath)
            .header("Host",       server)
            .header("Upgrade",    "websocket")
            .header("Connection", "Upgrade")
            .build();

        Object lock = new Object();

        client.newWebSocket(request, new WebSocketListener() {
            volatile boolean firstDown = true;
            volatile boolean firstUp   = true;

            @Override
            public void onOpen(WebSocket ws, Response response) {
                Log.d(TAG, "WS open: " + destAddr + ":" + destPort);

                // Upstream: client → WebSocket
                executor.submit(() -> {
                    try {
                        byte[] buf = new byte[16384];
                        int    n;
                        while (running && (n = clientIn.read(buf)) > 0) {
                            byte[] data = java.util.Arrays.copyOf(buf, n);
                            if (firstUp) {
                                firstUp = false;
                                byte[] header = buildVlessHeader(destAddr, destPort, destPort);
                                byte[] full   = new byte[header.length + n];
                                System.arraycopy(header, 0, full, 0,            header.length);
                                System.arraycopy(data,   0, full, header.length, n);
                                ws.send(ByteString.of(full));
                            } else {
                                ws.send(ByteString.of(data));
                            }
                        }
                        ws.close(1000, null);
                    } catch (Exception e) {
                        ws.close(1000, null);
                    }
                });
            }

            @Override
            public void onMessage(WebSocket ws, ByteString bytes) {
                try {
                    byte[] data = bytes.toByteArray();
                    if (firstDown) {
                        firstDown = false;
                        // Skip 2-byte VLESS response header
                        if (data.length > 2)
                            clientOut.write(data, 2, data.length - 2);
                    } else {
                        clientOut.write(data);
                    }
                    clientOut.flush();
                } catch (Exception ignored) {}
            }

            @Override
            public void onFailure(WebSocket ws, Throwable t, Response r) {
                Log.e(TAG, "WS failure: " + t.getMessage());
            }
        });
    }

    private byte[] buildVlessHeader(String addr, int port, int destPort) throws Exception {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        // Version
        buf.write(0);
        // UUID (16 bytes)
        UUID u = UUID.fromString(uuid);
        ByteBuffer ub = ByteBuffer.allocate(16);
        ub.putLong(u.getMostSignificantBits());
        ub.putLong(u.getLeastSignificantBits());
        buf.write(ub.array());
        // Addon length
        buf.write(0);
        // Command: TCP
        buf.write(1);
        // Port (2 bytes big-endian)
        buf.write((destPort >> 8) & 0xFF);
        buf.write(destPort & 0xFF);

        // Address type
        try {
            InetAddress ia = InetAddress.getByName(addr);
            if (ia instanceof Inet4Address) {
                buf.write(1);
                buf.write(ia.getAddress());
            } else {
                buf.write(2);
                buf.write(addr.length());
                buf.write(addr.getBytes());
            }
        } catch (Exception e) {
            buf.write(2);
            buf.write(addr.length());
            buf.write(addr.getBytes());
        }
        return buf.toByteArray();
    }

    private void tunnelViaSocks(String destIp, int destPort) {
        // Placeholder for direct TUN → VLESS routing
        // Full implementation would parse TCP stream from TUN packets
    }

    @Override
    public void onDestroy() {
        stopVpn();
        super.onDestroy();
    }
}
