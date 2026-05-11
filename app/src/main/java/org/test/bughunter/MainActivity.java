package org.test.bughunter;

import android.content.Intent;
import android.net.VpnService;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.view.View;
import android.widget.TextView;
import android.widget.Button;
import android.widget.EditText;
import androidx.activity.result.ActivityResultLauncher;
import androidx.activity.result.contract.ActivityResultContracts;
import androidx.appcompat.app.ActionBarDrawerToggle;
import androidx.appcompat.app.AppCompatActivity;
import androidx.core.view.GravityCompat;
import androidx.drawerlayout.widget.DrawerLayout;

public class MainActivity extends AppCompatActivity {

    // ── Config ──────────────────────────────────────────────────────────────
    public static final String USER_UUID     = "4224f578-6c71-4cf2-ae77-3cf1d8878fed";
    public static final String ACTUAL_SERVER = "web.chomba.tech";
    public static final String WS_PATH       = "/vless";
    public static final String CONNECT_IP    = "104.26.3.143";
    public static final int    PORT          = 443;
    // ────────────────────────────────────────────────────────────────────────

    private static final int VPN_REQUEST_CODE = 100;

    private boolean connected = false;
    private boolean scanning  = false;
    private String  selectedBug;

    // Views
    private TextView   statusLabel, bugInfo, logText;
    private Button     connectBtn, scanBtn, applyBugBtn;
    private EditText   bugInput;
    private DrawerLayout drawerLayout;
    private View       vpnScreen, logsScreen;
    private Button     vpnTab, logsTab;

    private final Handler uiHandler = new Handler(Looper.getMainLooper());

    private final ActivityResultLauncher<Intent> vpnPermLauncher =
        registerForActivityResult(new ActivityResultContracts.StartActivityForResult(), result -> {
            if (result.getResultCode() == RESULT_OK) {
                startVpnService();
            } else {
                addLog("VPN permission denied.");
                resetConnectButton();
            }
        });

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        selectedBug = ACTUAL_SERVER;

        // Bind views
        statusLabel  = findViewById(R.id.status_label);
        bugInfo      = findViewById(R.id.bug_info);
        logText      = findViewById(R.id.log_text);
        connectBtn   = findViewById(R.id.connect_btn);
        scanBtn      = findViewById(R.id.scan_btn);
        applyBugBtn  = findViewById(R.id.apply_bug_btn);
        bugInput     = findViewById(R.id.bug_input);
        drawerLayout = findViewById(R.id.drawer_layout);
        vpnScreen    = findViewById(R.id.vpn_screen);
        logsScreen   = findViewById(R.id.logs_screen);
        vpnTab       = findViewById(R.id.tab_vpn);
        logsTab      = findViewById(R.id.tab_logs);

        // Drawer toggle
        findViewById(R.id.menu_btn).setOnClickListener(v ->
            drawerLayout.openDrawer(GravityCompat.START));

        // Tabs
        vpnTab.setOnClickListener(v  -> switchScreen(true));
        logsTab.setOnClickListener(v -> switchScreen(false));

        // Buttons
        connectBtn.setOnClickListener(v  -> toggleVpn());
        scanBtn.setOnClickListener(v     -> toggleScan());
        applyBugBtn.setOnClickListener(v -> applyBug());

        bugInfo.setText("Bug: " + selectedBug);
        bugInput.setText(ACTUAL_SERVER);
        addLog("System Ready.");
    }

    // ── Screen switching ────────────────────────────────────────────────────
    private void switchScreen(boolean showVpn) {
        vpnScreen.setVisibility(showVpn ? View.VISIBLE : View.GONE);
        logsScreen.setVisibility(showVpn ? View.GONE   : View.VISIBLE);
    }

    // ── Logging ─────────────────────────────────────────────────────────────
    public void addLog(String message) {
        uiHandler.post(() -> {
            String current = logText.getText().toString();
            logText.setText(current + "[*] " + message + "\n");
        });
    }

    // ── Drawer / Bug ────────────────────────────────────────────────────────
    private void applyBug() {
        selectedBug = bugInput.getText().toString().trim();
        bugInfo.setText("Bug: " + selectedBug);
        addLog("Manual SNI updated: " + selectedBug);
        drawerLayout.closeDrawer(GravityCompat.START);
    }

    // ── VPN ─────────────────────────────────────────────────────────────────
    private void toggleVpn() {
        if (!connected) {
            Intent prepare = VpnService.prepare(this);
            if (prepare != null) {
                vpnPermLauncher.launch(prepare);
            } else {
                startVpnService();
            }
        } else {
            stopVpnService();
        }
    }

    private void startVpnService() {
        connected = true;
        connectBtn.setText("STOP");
        connectBtn.setBackgroundColor(0xFFCC0000);
        statusLabel.setText("CONNECTING...");
        statusLabel.setTextColor(0xFF4CAF50);

        Intent intent = new Intent(this, VpnEngine.class);
        intent.putExtra("action",      "START");
        intent.putExtra("bug",         selectedBug);
        intent.putExtra("server",      ACTUAL_SERVER);
        intent.putExtra("connect_ip",  CONNECT_IP);
        intent.putExtra("port",        PORT);
        intent.putExtra("ws_path",     WS_PATH);
        intent.putExtra("uuid",        USER_UUID);
        startService(intent);
    }

    private void stopVpnService() {
        connected = false;
        resetConnectButton();
        Intent intent = new Intent(this, VpnEngine.class);
        intent.putExtra("action", "STOP");
        startService(intent);
    }

    private void resetConnectButton() {
        connected = false;
        connectBtn.setText("CONNECT");
        connectBtn.setBackgroundColor(0xFF006600);
        statusLabel.setText("DISCONNECTED");
        statusLabel.setTextColor(0xFFFF5252);
    }

    // Called from VpnEngine via broadcast
    public void onVpnConnected() {
        uiHandler.post(() -> {
            statusLabel.setText("CONNECTED");
            statusLabel.setTextColor(0xFF4CAF50);
        });
    }

    // ── Scanner ─────────────────────────────────────────────────────────────
    private void toggleScan() {
        if (!scanning) {
            scanning = true;
            scanBtn.setText("STOP SCAN");
            statusLabel.setText("SCANNING...");
            BugScanner scanner = new BugScanner(this, selectedBug, ACTUAL_SERVER, WS_PATH);
            scanner.start(bug -> {
                selectedBug = bug;
                uiHandler.post(() -> {
                    bugInfo.setText("Bug: " + selectedBug);
                    scanBtn.setText("START SCAN");
                    statusLabel.setText("READY");
                    scanning = false;
                });
            }, () -> uiHandler.post(() -> {
                scanBtn.setText("START SCAN");
                statusLabel.setText("READY");
                scanning = false;
            }));
        } else {
            scanning = false;
            scanBtn.setText("START SCAN");
        }
    }

    @Override
    public void onBackPressed() {
        if (drawerLayout.isDrawerOpen(GravityCompat.START)) {
            drawerLayout.closeDrawer(GravityCompat.START);
        } else {
            super.onBackPressed();
        }
    }
}
