package com.bombolab.bughunter

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.BufferedReader
import java.io.InputStreamReader
import java.net.*
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory

// White & Green Theme Palette
val GreenPrimary = Color(0xFF2E7D32) // Forest Green
val GreenLight = Color(0xFFE8F5E9)   // Soft green tint
val WhiteBackground = Color(0xFFFFFFFF)
val TextDark = Color(0xFF1B5E20)

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            MaterialTheme {
                BugHunterApp()
            }
        }
    }
}

@Composable
fun BugHunterApp() {
    val coroutineScope = rememberCoroutineScope()
    var logs by remember { mutableStateOf("Ready to scan.\n") }
    var isRunning by remember { mutableStateOf(false) }

    fun appendLog(msg: String) {
        logs += "$msg\n"
    }

    Surface(
        modifier = Modifier.fillMaxSize(),
        color = WhiteBackground
    ) {
        Column(
            modifier = Modifier
                .padding(16.dp)
                .fillMaxSize()
        ) {
            // Header Text
            Text(
                text = "BOMBO-CLAT BUG HUNTER",
                fontSize = 22.sp,
                fontWeight = FontWeight.Bold,
                color = GreenPrimary
            )
            Text(
                text = "ALL-IN-ONE PORTAL AUDITING TOOL",
                fontSize = 12.sp,
                fontWeight = FontWeight.Medium,
                color = GreenPrimary.copy(alpha = 0.7f),
                modifier = Modifier.padding(bottom = 16.dp)
            )

            // Terminal/Console Logs Box
            Box(
                modifier = Modifier
                    .weight(1f)
                    .fillMaxWidth()
                    .background(GreenLight, shape = RoundedCornerShape(8.dp))
                    .padding(12.dp)
            ) {
                val scrollState = rememberScrollState()
                LaunchedEffect(logs) {
                    scrollState.animateScrollTo(scrollState.maxValue)
                }
                Text(
                    text = logs,
                    fontFamily = FontFamily.Monospace,
                    fontSize = 11.sp,
                    color = TextDark,
                    modifier = Modifier
                        .fillMaxSize()
                        .verticalScroll(scrollState)
                )
            }

            Spacer(modifier = Modifier.height(16.dp))

            // Action Button
            Button(
                onClick = {
                    if (!isRunning) {
                        isRunning = true
                        logs = "[*] Starting Audit...\n"
                        coroutineScope.launch {
                            runAudit { appendLog(it) }
                            isRunning = false
                        }
                    }
                },
                enabled = !isRunning,
                colors = ButtonDefaults.buttonColors(
                    containerColor = GreenPrimary,
                    disabledContainerColor = GreenPrimary.copy(alpha = 0.5f)
                ),
                shape = RoundedCornerShape(8.dp),
                modifier = Modifier.fillMaxWidth().height(50.dp)
            ) {
                Text(
                    text = if (isRunning) "SCANNING..." else "START AUDIT",
                    color = Color.White,
                    fontWeight = FontWeight.Bold,
                    fontSize = 16.sp
                )
            }
        }
    }
}

// Background Processing Block (Transpiled Port of your Shell script)
suspend fun runAudit(log: (String) -> Unit) {
    withContext(Dispatchers.IO) {
        try {
            // --- PHASE 1: Detection ---
            log("[*] Phase 1: Detecting Captive Portal...")
            val localIp = getLocalIpAddress()
            if (localIp == null) {
                log("[!] No internet/Wi-Fi Connection.")
                return@withContext
            }
            log("[+] Local IP Address: $localIp")

            var portalDomain = detectRedirectDomain()
            if (portalDomain == null) {
                log("[!] No Redirect found. Pinging gateway subnets...")
                portalDomain = tryGatewayFallback(localIp)
            }

            if (portalDomain == null) {
                log("[!] Failed to locate Captive Portal Gateway.")
                return@withContext
            }
            log("[+] Target Portal Found: $portalDomain")

            // --- PHASE 2: Extraction ---
            log("[*] Phase 2: Fetching site and scraping domains...")
            val htmlContent = fetchHtml("http://$portalDomain")
            if (htmlContent.isEmpty()) {
                log("[!] Failed to grab source HTML from portal page.")
                return@withContext
            }

            val domains = extractDomains(htmlContent)
            log("[+] Scraped ${domains.size} unique domains.")

            if (domains.isEmpty()) {
                log("[!] No subdomains identified in markup.")
                return@withContext
            }

            // --- PHASE 3: Embedded VLESS Handshake Checker ---
            log("[*] Phase 3: Resolving IPs & Auditing Handshakes...")
            val ipsToTest = mutableSetOf<String>()
            for (domain in domains) {
                try {
                    val address = InetAddress.getByName(domain)
                    ipsToTest.add(address.hostAddress)
                } catch (e: Exception) {
                    // DNS resolve failure, skip
                }
            }
            log("[+] Resolved ${ipsToTest.size} distinct IP addresses to audit.")

            var bugFound = false
            for (ip in ipsToTest) {
                log("[~] Auditing socket: $ip")
                val (ok, details) = verifyVlessHandshake(ip)
                if (ok) {
                    log("    ==> \u2714 SUCCESS! Host IP responds with 101 Switch: $ip")
                    bugFound = true
                } else {
                    log("    ==> \u2718 FAILED ($details)")
                }
            }

            log("\n------------------------------------------------")
            if (bugFound) {
                log("[✔] AUDIT COMPLETE! Check logs for SUCCESS items.")
            } else {
                log("[!] Audit finished. No valid handshakes detected.")
            }
            log("------------------------------------------------")

        } catch (e: Exception) {
            log("[!] Critical Runtime Error: ${e.localizedMessage}")
        }
    }
}

// Net helper implementations
private fun getLocalIpAddress(): String? {
    try {
        val interfaces = NetworkInterface.getNetworkInterfaces()
        while (interfaces.hasMoreElements()) {
            val networkInterface = interfaces.nextElement()
            val addresses = networkInterface.inetAddresses
            while (addresses.hasMoreElements()) {
                val address = addresses.nextElement()
                if (!address.isLoopbackAddress && address is Inet4Address) {
                    return address.hostAddress
                }
            }
        }
    } catch (ex: Exception) {
        ex.printStackTrace()
    }
    return null
}

private fun detectRedirectDomain(): String? {
    return try {
        val url = URL("http://connectivitycheck.gstatic.com/generate_204")
        val connection = url.openConnection() as HttpURLConnection
        connection.instanceFollowRedirects = false
        connection.connectTimeout = 3000
        connection.readTimeout = 3000
        connection.connect()
        val redirectLocation = connection.getHeaderField("Location")
        connection.disconnect()
        if (!redirectLocation.isNullOrEmpty()) {
            val uri = URI(redirectLocation)
            uri.host
        } else null
    } catch (e: Exception) {
        null
    }
}

private fun tryGatewayFallback(localIp: String): String? {
    val base = localIp.substringBeforeLast(".")
    val checkGateways = listOf("$base.1", "$base.254")
    for (ip in checkGateways) {
        try {
            val url = URL("http://$ip")
            val connection = url.openConnection() as HttpURLConnection
            connection.connectTimeout = 2000
            connection.readTimeout = 2000
            val code = connection.responseCode
            if (code in 200..302) {
                return ip
            }
        } catch (e: Exception) {
            // Unreachable IP, keep loop going
        }
    }
    return null
}

private fun fetchHtml(urlString: String): String {
    return try {
        val url = URL(urlString)
        val conn = url.openConnection() as HttpURLConnection
        conn.connectTimeout = 5000
        conn.readTimeout = 5000
        val reader = BufferedReader(InputStreamReader(conn.inputStream))
        val output = StringBuilder()
        var line: String?
        while (reader.readLine().also { line = it } != null) {
            output.append(line)
        }
        reader.close()
        output.toString()
    } catch (e: Exception) {
        ""
    }
}

private fun extractDomains(html: String): List<String> {
    // Ported your regex check precisely
    val regex = "(?i)([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\\.)+(com|net|org|io|me|be)".toRegex()
    val matchResults = regex.findAll(html)
    val excludeRegex = ".*\\.(jpg|jpeg|png|gif|ico|svg|css|js|mp4|woff|woff2|ttf)\$".toRegex(RegexOption.IGNORE_CASE)

    return matchResults.map { it.value }
        .filterNot { excludeRegex.matches(it) }
        .distinct()
        .toList()
}

// VLESS custom handshake socket test (Java Socket SSL connection setup)
private fun verifyVlessHandshake(ip: String): Pair<Boolean, String> {
    var socket: Socket? = null
    var sslSocket: SSLSocket? = null
    return try {
        val myServer = "web.chomba.tech"
        val wsPath = "/vless"
        val port = 443

        socket = Socket()
        socket.connect(InetSocketAddress(ip, port), 4000)

        val factory = SSLSocketFactory.getDefault() as SSLSocketFactory
        sslSocket = factory.createSocket(socket, myServer, port, true) as SSLSocket
        sslSocket.startHandshake()

        val requestHeader = (
                "GET $wsPath HTTP/1.1\r\n" +
                "Host: $myServer\r\n" +
                "Upgrade: websocket\r\n" +
                "Connection: Upgrade\r\n" +
                "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" +
                "Sec-WebSocket-Version: 13\r\n\r\n"
        )

        val out = sslSocket.outputStream
        out.write(requestHeader.toByteArray(Charsets.UTF_8))
        out.flush()

        val reader = BufferedReader(InputStreamReader(sslSocket.inputStream))
        val responseLine = reader.readLine() // Get status response

        if (responseLine != null && responseLine.contains("101")) {
            Pair(true, responseLine)
        } else {
            Pair(false, responseLine ?: "No Response Payload")
        }
    } catch (e: Exception) {
        Pair(false, e.localizedMessage ?: "Socket Error")
    } finally {
        try { sslSocket?.close() } catch (e: Exception) {}
        try { socket?.close() } catch (e: Exception) {}
    }
}
