package local.nianyun.bridge;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;

import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTextField;
import java.awt.BorderLayout;
import java.awt.GridLayout;
import java.io.IOException;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * Entry point. Loads inside Burp, starts the bridge on 0.0.0.0:8765, and shows the bearer token
 * in a suite tab so the operator can paste it into the console settings once.
 */
public final class BridgeExtension implements BurpExtension {
    private static final String TOKEN_KEY = "nianyun.bridge.token";
    private static final int PORT = 8765;

    private MontoyaApi api;
    private String token;
    private BridgeServer server;

    @Override
    public void initialize(MontoyaApi montoyaApi) {
        api = montoyaApi;
        api.extension().setName("Nianyun Burp Bridge");
        token = api.persistence().preferences().getString(TOKEN_KEY);
        if (token == null || token.isBlank()) {
            token = createToken();
            api.persistence().preferences().setString(TOKEN_KEY, token);
        }
        api.userInterface().registerSuiteTab("Nianyun Bridge", createPanel());
        // Rewrite rules apply to everything Burp sends, not only to bridge-initiated traffic.
        Rules.engine(api).install();
        try {
            server = new BridgeServer(api, token, PORT);
            server.start();
            api.logging().logToOutput("Nianyun Burp Bridge v4 listening at 0.0.0.0:" + PORT);
        } catch (IOException error) {
            api.logging().logToError("Nianyun Burp Bridge could not bind 0.0.0.0:" + PORT + ": " + error.getMessage());
        }
        api.extension().registerUnloadingHandler(() -> {
            Rules.engine(api).uninstall();
            if (server != null) server.stop();
        });
    }

    private JPanel createPanel() {
        JPanel root = new JPanel(new BorderLayout(8, 8));
        JPanel details = new JPanel(new GridLayout(0, 1, 4, 4));
        details.add(new JLabel("Bridge for the Nianyun agent. Requests are host-scoped and read-only unless an action endpoint is called."));
        details.add(new JLabel("Listener: http://0.0.0.0:" + PORT + " (Docker uses host.docker.internal:" + PORT + ")"));
        details.add(new JLabel("Read: /proxy/history /proxy/entry /sitemap /issues /ws/history /scope /intercept"));
        details.add(new JLabel("Action: /http/send /repeater /organizer /decoder /collab/generate /collab/poll"));
        details.add(new JLabel("Full surface: /rules /websocket /bchecks /intruder /compare /convert /cookies /storage /control"));
        details.add(new JLabel("Scan: /scan/audit /scan/status /scan/stop (active mode must be enabled in agent rules)"));
        JTextField tokenField = new JTextField(token);
        tokenField.setEditable(false);
        JButton copy = new JButton("Copy token");
        copy.addActionListener(event -> {
            tokenField.selectAll();
            tokenField.copy();
        });
        JPanel tokenPanel = new JPanel(new BorderLayout(8, 0));
        tokenPanel.add(tokenField, BorderLayout.CENTER);
        tokenPanel.add(copy, BorderLayout.EAST);
        details.add(new JLabel("Bearer token:"));
        details.add(tokenPanel);
        root.add(details, BorderLayout.NORTH);
        return root;
    }

    private static String createToken() {
        byte[] bytes = new byte[32];
        new SecureRandom().nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}