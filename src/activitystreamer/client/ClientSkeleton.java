package activitystreamer.client;

import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

import activitystreamer.util.Settings;

public class ClientSkeleton extends Thread {
	private static final Logger log = LogManager.getLogger();
	private static ClientSkeleton clientSolution;
	private TextFrame textFrame;

    // maximum limit of login (redirection) attempts
    private static final int MAX_ATTEMPT = 5;
    // TCP IO components
	private Socket socket = null;
    private BufferedReader in = null;
    private PrintWriter out = null;
    private JSONParser parser = new JSONParser();
    // whether the application should be terminated
    private boolean term = false;
    // whether the connection is open
    private boolean open = false;
    // current redirection count
    private int redirectCount = 0;
	
	public static ClientSkeleton getInstance() {
		if (clientSolution == null) {
			clientSolution = new ClientSkeleton();
		}
		return clientSolution;
	}
	
	public ClientSkeleton() {
        setupConnection();
	    if (Settings.getSecret() == null && !Settings.getUsername().equals("anonymous")) {
            // register with new secret
            String secret = Settings.nextSecret();
            // print the secret to console
            System.out.println(String.format("Your new secret is %s", secret));
            Settings.setSecret(secret);
	        register();
        }
        else {
            // login with whatever in Settings
            login();
        }
        // start GUI and listener
        textFrame = new TextFrame();
		start();
	}

    /**
     * Wrap an activity object and send it to socket.
     * @param activityObj activity object to be sent.
     */
    public void sendActivityObject(JSONObject activityObj) {
        if (!open) {
            log.error("Connection closed");
            return;
        }
        JSONObject requestObj = new JSONObject();
        requestObj.put("command", "ACTIVITY_MESSAGE");
        requestObj.put("username", Settings.getUsername());
        requestObj.put("secret", Settings.getSecret());
        requestObj.put("activity", activityObj);
        send(requestObj.toString());
    }

    /**
     * Disconnect from server and terminate the application.
     */
    public void disconnect() {
	    term = true;
        if (open) logout();
        try {
            closeConnection();
        } catch (IOException e) {
            log.error("received exception when closing the connection: " + e);
        }
    }

    /**
     * Setup connection with server and handle exceptions.
     */
	private void setupConnection() {
	    try {
            socket = new Socket(Settings.getRemoteHostname(), Settings.getRemotePort());
            in = new BufferedReader(new InputStreamReader(new DataInputStream(socket.getInputStream())));
            out = new PrintWriter(new DataOutputStream(socket.getOutputStream()), true);
            open = true;
        } catch (IllegalArgumentException e) {
	        log.fatal("Illegal port number is used");
	        System.exit(-1);
        } catch (NullPointerException e) {
            log.fatal("Host address cannot be empty");
            System.exit(-1);
        } catch (IOException e) {
	        log.fatal("Failed to establish connection with server");
	        System.exit(-1);
        }
    }

    /**
     * Disconnect from server and set appropriate flags.
     * @throws IOException throws exceptions from close().
     */
    private void closeConnection() throws IOException {
	    if (open) {
            log.info("closing connection with server...");
            in.close();
            out.close();
            socket.close();
            open = false;
        }
    }

    /**
     * Build register JSON and send.
     */
    private void register() {
        JSONObject outObj = new JSONObject();
        outObj.put("command", "REGISTER");
        outObj.put("username", Settings.getUsername());
        outObj.put("secret", Settings.getSecret());
        send(outObj.toString());
    }

    /**
     * Build login JSON and send.
     */
    private void login() {
        JSONObject outObj = new JSONObject();
        outObj.put("command", "LOGIN");
        outObj.put("username", Settings.getUsername());
        outObj.put("secret", Settings.getSecret());
        send(outObj.toString());
    }

    /**
     * Build logout JSON and send.
     */
    private void logout() {
        JSONObject outObj = new JSONObject();
        outObj.put("command", "LOGOUT");
        send(outObj.toString());
    }

    /**
     * Handel redirect message.
     * @param obj redirect JSON object from server.
     * @return true if redirect success, false otherwise.
     */
    private boolean redirect(JSONObject obj) {
        // quit if maximum attempts exceeded
	    if (redirectCount++ >= MAX_ATTEMPT) {
	        log.fatal("Maximum redirect count exceeded");
	        return true;
        }
        // basic field check
        String hostname = (String) obj.get("hostname");
	    Long port = (Long) obj.get("port");
        if (hostname == null) {
            log.fatal("Received message does not contain a hostname");
            invalidMessage("received message does not contain a hostname");
            return true;
        }
        if (port == null) {
            log.fatal("Received message does not contain a port");
            invalidMessage("received message does not contain a port");
            return true;
        }
        // close current connection, change parameters and start a new one
        try {
            closeConnection();
        } catch (IOException e) {
            log.error("received exception when closing the connection: " + e);
            return true;
        }
        Settings.setRemoteHostname(hostname);
        Settings.setRemotePort(port.intValue());
        setupConnection();
        // login again
        login();
	    return false;
    }

    /**
     * Build INVALID_MESSAGE JSON and send.
     * @param info detailed information for INVALID_MESSAGE.
     */
	private void invalidMessage(String info) {
	    JSONObject outObj = new JSONObject();
        outObj.put("command", "INVALID_MESSAGE");
        outObj.put("info", info);
	    send(outObj.toString());
    }

    /**
     * Send helper function that send a given string to server.
     * @param msg text message to be send.
     * @return true if successfully sent, false otherwise.
     */
	private boolean send(String msg) {
	    if (open) {
            out.println(msg);
            out.flush();
            return true;
        }
        return false;
    }

    /**
     * Process TCP messages.
     * @param msg message to be processed
     * @return true if application should be terminated, false otherwise.
     */
    private boolean process(String msg) {
        JSONObject inObj;
        String command;
        // basic message format check
        try {
            inObj = (JSONObject) parser.parse(msg);
            command = (String) inObj.get("command");
            if (command == null) {
                log.error("the received message did not contain a command");
                invalidMessage("the received message did not contain a command");
                return true;
            }
        } catch (ParseException e) {
            log.error("JSON parse error while parsing message");
            invalidMessage("the message sent was not a valid json object");
            return true;
        }
        // handle different commands
        switch (command) {
            case "INVALID_MESSAGE":
                log.error(String.format("INVALID_MESSAGE: %s", inObj.get("info")));
                return true;
            case "REGISTER_SUCCESS":
                log.info("Register success");
                login();
                return false;
            case "REGISTER_FAILED":
                log.fatal(String.format("Register failed: %s", inObj.get("info")));
                return true;
            case "LOGIN_SUCCESS":
                log.info("Login success");
                return false;
            case "REDIRECT":
                log.info("Redirect");
                return redirect(inObj);
            case "LOGIN_FAILED":
                log.fatal((String) inObj.get("info"));
                return true;
            case "ACTIVITY_BROADCAST":
                log.info("Activity received");
                // format check
                JSONObject activity = (JSONObject) inObj.get("activity");
                if (activity == null) {
                    log.error("Received message does not contain an activity");
                    invalidMessage("message does not contain an activity");
                    return true;
                }
                textFrame.setOutputText(activity);
                return false;
            default:
                log.error("the received message contains a invalid command");
                invalidMessage("the received message contains a invalid command");
                return true;
        }
    }
	
	public void run() {
	    // Using a separate thread to keep reading messages
        try {
            String response;
            while (!term && (response = in.readLine()) != null) {
                term = process(response);
            }
            log.debug("stop receiving message from server");
            socket.close();
        } catch (IOException e) {
            log.error("exit with exception: " + e);
        }
        // Close GUI when connection closed
        System.exit(0);
	}
}
