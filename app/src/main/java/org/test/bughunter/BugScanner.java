package org.test.bughunter;

import android.util.Log;
import java.io.*;
import java.net.*;
import java.util.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.regex.*;
import javax.net.ssl.*;
import okhttp3.*;

public class BugScanner {

    private static final String TAG = "BugHunter.Scanner";

    private final MainActivity activity;
    private final String        currentBug;
    private final String        actualServer;
    private final String        wsPath;
    private volatile boolean    running = true;

    private final OkHttpClient http = new OkHttpClient.Builder()
        .followRedirects(false)
        .connectTimeout(5, java.util.concurrent.TimeUnit.SECONDS)
        .readTimeout(10, java.util.concurrent.TimeUnit.SECONDS)
        .build();

    private static final Pattern DOMAIN_REGEX =
        Pattern.compile("(?i)((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.)" +
                         "+(?:com|net|org|io|me|be))",
                         Pattern.CASE_INSENSITIVE);

    private static final Pattern EXCLUDE =
        Pattern.compile("\\.(jpg|jpeg|png|gif|ico|svg|css|js|mp4|woff|woff2|ttf)$",
                         Pattern.CASE_INSENSITIVE);

    public interface OnBugFound   { void found(String bug); }
    public interface OnScanFinish { void done(); }

    public BugScanner(MainActivity activity, String currentBug,
                      String actualServer, String wsPath) {
        this.activity     = activity;
        this.currentBug   = currentBug;
        this.actualServer = actualServer;
        this.wsPath       = wsPath;
    }

    public void start(OnBugFound onFound, OnScanFinish onFinish) {
        ExecutorService exec = Executors.newSingleThreadExecutor();
        exec.submit(() -> {
            String result = scan();
            if (result != null && onFound != null) onFound.found(result);
            if (onFinish != null) onFinish.done();
            exec.shutdown();
        });
    }

    public void stop() { running = false; }

    private String scan() {
        try {
            activity.addLog("Phase 1: Portal Detection...");

            // Check for captive portal
            Request check = new Request.Builder()
                .url("http://connectivitycheck.gstatic.com/generate_204")
                .build();
            Response r = http.newCall(check).execute();
            String location = r.header("Location");
            r.close();

            if (location == null) {
                activity.addLog("No captive portal found.");
                return null;
            }

            String portalHost = new URL(location).getHost();
            activity.addLog("Phase 2: Mirroring " + portalHost);

            Request pageReq = new Request.Builder().url(location).build();
            Response pageRes = http.newCall(pageReq).execute();
            String content = pageRes.body() != null ? pageRes.body().string() : "";
            pageRes.close();

            // Download JS files
            Pattern jsPat = Pattern.compile("src=[\"'](.*?\\.js.*?)[\"']");
            Matcher jsMat = jsPat.matcher(content);
            List<String> jsPaths = new ArrayList<>();
            while (jsMat.find()) jsPaths.add(jsMat.group(1));

            for (String p : jsPaths) {
                if (!running) break;
                try {
                    String jsUrl = p.startsWith("http") ? p : new URL(new URL(location), p).toString();
                    activity.addLog("Downloading JS: " + p.substring(p.lastIndexOf('/') + 1));
                    Request jsReq = new Request.Builder().url(jsUrl).build();
                    Response jsRes = http.newCall(jsReq).execute();
                    if (jsRes.body() != null) content += "\n" + jsRes.body().string();
                    jsRes.close();
                } catch (Exception ignored) {}
            }

            // Find domain candidates
            Matcher m = DOMAIN_REGEX.matcher(content);
            Set<String> candidates = new LinkedHashSet<>();
            while (m.find()) candidates.add(m.group(1));

            for (String candidate : candidates) {
                if (!running) break;
                if (EXCLUDE.matcher(candidate).find()) continue;
                activity.addLog("Handshake Test: " + candidate);
                if (handshakeVerify(candidate)) {
                    activity.addLog("BUG FOUND: " + candidate + " (101 OK)");
                    return candidate;
                }
            }

            activity.addLog("Scan complete. No working bug found.");
            return null;

        } catch (Exception e) {
            activity.addLog("Scanner Error: " + e.getMessage());
            Log.e(TAG, "Scanner error", e);
            return null;
        }
    }

    private boolean handshakeVerify(String bug) {
        String req = "GET " + wsPath + " HTTP/1.1\r\n"
                   + "Host: " + actualServer + "\r\n"
                   + "Upgrade: websocket\r\n"
                   + "Connection: Upgrade\r\n\r\n";
        try {
            SSLContext ctx = SSLContext.getInstance("TLS");
            ctx.init(null, new TrustManager[]{
                new X509TrustManager() {
                    public void checkClientTrusted(java.security.cert.X509Certificate[] c, String a) {}
                    public void checkServerTrusted(java.security.cert.X509Certificate[] c, String a) {}
                    public java.security.cert.X509Certificate[] getAcceptedIssuers() { return new java.security.cert.X509Certificate[0]; }
                }
            }, null);

            SSLSocket sock = (SSLSocket) ctx.getSocketFactory()
                .createSocket(bug, 443);
            sock.setUseClientMode(true);

            SNIHostName sni = new SNIHostName(actualServer);
            SSLParameters params = sock.getSSLParameters();
            params.setServerNames(Collections.singletonList(sni));
            sock.setSSLParameters(params);

            sock.startHandshake();
            sock.getOutputStream().write(req.getBytes());
            byte[] buf = new byte[1024];
            int n = sock.getInputStream().read(buf);
            sock.close();

            String response = new String(buf, 0, n);
            return response.contains("101");
        } catch (Exception e) {
            return false;
        }
    }
}
