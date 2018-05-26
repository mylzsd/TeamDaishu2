package activitystreamer.server;

import java.io.IOException;
import java.net.Socket;
import java.net.SocketException;
import java.util.*;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

import activitystreamer.util.Settings;

public class Control extends Thread {
	private static final Logger log = LogManager.getLogger();
	private static ArrayList<Connection> connections;
	private static boolean term = false;
	private static Listener listener;
    private JSONParser parser = new JSONParser();
    private final String id = Settings.nextSecret();
	
	protected static Control control = null;

	// fields for project2
    // type of server, -1 - undefined, 0 - Alpha central server, 1 - Beta central server, 2 - SUB server
    private int serverType = -1;
    private String backupHostname = null;
    private int backupPort = -1;
    private int serverload = 0;
    private int clientload = 0;
    private static Connection mainConnection;
    private static Connection backupConnection;

	// local database that store the username and secret
	private static Map<String, String> userInfo;
	// server info class that store the content of server announce
	class ServerInfo {
	    String id;
	    String hostname;
        int port;
        int serverLoad;
        int clientLoad;
	    ServerInfo(String id, String hostname, int port, int serverLoad, int clientLoad) {
	        this.id = id;
	        this.hostname = hostname;
	        this.port = port;
	        this.serverLoad = serverLoad;
	        this.clientLoad = clientLoad;
        }
    }
    // map server info with server id
    private static Map<String, ServerInfo> serverInfo;
	private static ServerInfo centralSI;
	// map awaiting lock request connection with requested username
	private static Map<String, Connection> registerMap;
	// map awaiting login request connection with requested username
    private static Map<String, Connection> loginMap;

	// message queue table
    private static Map<String, ArrayList<JSONObject>> verifyMsgQueueMap;

    // message history
    private static Map<String, JSONObject> messageHistory;
	
	public static Control getInstance() {
		if (control == null) {
			control = new Control();
		}
		return control;
	}
	
	public Control() {
		// initialize the connections array
        connections = new ArrayList<>();
		// initialize local database
        userInfo = new HashMap<>();
        serverInfo = new HashMap<>();
        registerMap = new HashMap<>();
        loginMap = new HashMap<>();
        verifyMsgQueueMap = new HashMap<>();
        messageHistory = new HashMap<>();
        if (Settings.getRemoteHostname() == null) serverType = 0;
		// start a listener
		try {
            // start listener
			listener = new Listener();
            // build initial connection
            initiateConnection();
		} catch (IOException e1) {
			log.fatal("failed to startup a listening thread: " + e1);
			System.exit(-1);
		}
		// start server activity thread
		start();
	}
	
	public void initiateConnection() {
		// make a connection to another server if remote hostname is supplied
		if (Settings.getRemoteHostname() != null) {
			try {
				mainConnection = outgoingConnection(new Socket(Settings.getRemoteHostname(), Settings.getRemotePort()));
				mainConnection.setMainConnection(true);
				// Send authentication to remote host
                JSONObject requestObj = new JSONObject();
                requestObj.put("command", "AUTHENTICATE");
                requestObj.put("secret", Settings.getSecret());
                requestObj.put("hostname", Settings.getLocalHostname());
                requestObj.put("port", Settings.getLocalPort());
                requestObj.put("type", "main");
                mainConnection.writeMsg(requestObj.toString());
			} catch (IOException e) {
			    mainConnection = null;
				log.error("failed to setup main server, retry in 5 seconds");
			}
		}
	}

    /**
     * Processing incoming messages from the connection.
     * @param con source connection
     * @param msg message to be processed
     * @return true if the connection should be closed, false otherwise.
     */
	public synchronized boolean process(Connection con, String msg) {
	    JSONObject requestObj;
	    // basic format checking
	    String command;
	    try {
	        requestObj = (JSONObject) parser.parse(msg);
	        command = (String) requestObj.get("command");
	        if (command == null) {
                log.error("the received message did not contain a command");
                invalidMessage(con, "the received message did not contain a command");
                return true;
            }
        } catch (ParseException e) {
            log.error("JSON parse error while parsing message");
            invalidMessage(con, "the message sent was not a valid json object");
            return true;
        }
        log.debug("receiving command " + command);
        // process different commands
        switch (command) {
	        /* Server communication part */
            case "AUTHENTICATE":
                return authenticate(con, requestObj);
            case "AUTHENTICATION_FAIL":
                log.error("authentication failed, running as a single server");
                serverType = 0;
                return true;
            case "INVALID_MESSAGE":
                log.error(String.format("An invalid message is sent, %s", requestObj.get("info")));
                return true;
            case "SERVER_ANNOUNCE":
                return serverAnnounce(con, requestObj);
            case "ACTIVITY_BROADCAST":
                return activityBroadcast(con, requestObj);
            case "LOCK_REQUEST":
                return lockRequest(con, requestObj);
            case "LOCK_ALLOWED":
                return lockAllowed(con, requestObj);
            case "LOCK_DENIED":
                return lockDenied(con, requestObj);
            /* new protocols for project 2 */
            case "AUTHENTICATE_SUCCESS":
                return authenticateSuccess(con, requestObj);
            case "SERVER_REDIRECT":
                return serverRedirect(con, requestObj);
            case "LOGIN_REQUEST":
                return loginRequest(con, requestObj);
            case "LOGIN_ALLOWED":
                return loginAllowed(con, requestObj);
            case "LOGIN_DENY":
                return loginDeny(con, requestObj);
            case "REDIRECT":
                return redirect(con, requestObj);
            case "ACTIVITY_RECEIPT":
                return activityReceipt(con, requestObj);
            case "SERVER_QUIT":
                con.setAuthenticated(false);
                if (con.equals(mainConnection)) {
                    if (serverType == 1) serverType = 0;
                    Settings.setRemoteHostname(null);
                    Settings.setRemotePort(0);
                }
                else if (con.equals(backupConnection)) {
                    backupHostname = null;
                    backupPort = 0;
                }
                verifyMsgQueueMap.remove(con.getSocketId());
                return true;
            case "STILL_ALIVE":
                return false;
            /* Client part */
            case "REGISTER":
                return register(con, requestObj);
            case "LOGIN":
                return login(con, requestObj);
            case "LOGOUT":
            	con.setAuthenticated(false);
                verifyMsgQueueMap.remove(con.getSocketId());
                return true;
            case "ACTIVITY_MESSAGE":
                return activityMessage(con, requestObj);
            // Request does not contain a command field
            default:
                log.error(String.format("the message contained an unknown command: %s", command));
                invalidMessage(con, String.format("the message contained an unknown command: %s", command));
                return true;
        }
	}

    /**
     * Build INVALID_MESSAGE JSON and send.
     * @param con connection whom send to.
     * @param info detailed information for INVALID_MESSAGE.
     */
	private void invalidMessage(Connection con, String info) {
        JSONObject outObj = new JSONObject();
        outObj.put("command", "INVALID_MESSAGE");
        outObj.put("info", info);
        con.writeMsg(outObj.toString());
	}

    /* new protocols for project 2 */
    private boolean authenticateSuccess(Connection con, JSONObject obj) {
        if (con.getType() != 1) {
            log.error("received AUTHENTICATE_SUCCESS from a non-server party");
            invalidMessage(con, "received AUTHENTICATE_SUCCESS from an unauthenticated server");
            return true;
        }
        String type = (String) obj.get("type");
        con.setAuthenticated(true);
        switch (type) {
            case "backupserver":
                serverType = 1;
                Map userInfoDup = (Map) obj.get("userinfo");
                if (userInfoDup != null) {
                    // put all rather than just assign
                    userInfo.putAll(userInfoDup);
                }
                return false;
            case "subserver":
                serverType = 2;
                try {
                    backupHostname = (String) obj.get("pairedhost");
                    backupPort = ((Number) obj.get("pairedport")).intValue();
                    backupConnection = outgoingConnection(new Socket(backupHostname, backupPort));
                    JSONObject requestObj = new JSONObject();
                    requestObj.put("command", "AUTHENTICATE");
                    requestObj.put("secret", Settings.getSecret());
                    requestObj.put("type", "backup");
                    backupConnection.writeMsg(requestObj.toString());
                    return false;
                } catch (Exception e) {
                    log.error("failed to start backup connection: " + e);
                    return false;
                }
            default:
                log.error("the message does not contain a valid server type");
                invalidMessage(con, "the message does not contain a valid server type");
                return true;
        }
    }

    private boolean serverRedirect(Connection con, JSONObject obj) {
        if (con.getType() != 1) {
            log.error("received SERVER_REDIRECT from a non-server party");
            invalidMessage(con, "received SERVER_REDIRECT from an unauthenticated server");
            return true;
        }
        // authenticate to new server
        String hostname = (String) obj.get("hostname");
        int port = ((Number) obj.get("port")).intValue();
        String type = (String) obj.get("type");
        JSONObject requestObj = new JSONObject();
        requestObj.put("command", "AUTHENTICATE");
        requestObj.put("secret", Settings.getSecret());
        requestObj.put("hostname", hostname);
        requestObj.put("port", port);
        if (type.equals("main")) {
            // set target server as main server
            Settings.setRemoteHostname(hostname);
            Settings.setRemotePort(port);
            try {
                mainConnection = outgoingConnection(new Socket(hostname, port));
                mainConnection.setMainConnection(true);
                requestObj.put("type", "main");
                mainConnection.writeMsg(requestObj.toString());
            } catch (IOException e) {
                log.error("failed to setup main server, retry in 5 seconds");
            }
            return true;
        }
        else {
            // set target server as backup server
            backupHostname = hostname;
            backupPort = port;
            try {
                backupConnection = outgoingConnection(new Socket(hostname, port));
                requestObj.put("type", "backup");
                backupConnection.writeMsg(requestObj.toString());
            } catch (IOException e) {
                log.error("failed to setup backup server, retry in 5 seconds");
            }
            return false;
        }
    }

    private boolean loginRequest(Connection con, JSONObject obj) {
        if (con.getType() != 1) {
            log.error("received LOGIN_REQUEST from a non-server party");
            invalidMessage(con, "received LOGIN_REQUEST from a non-server party");
            return true;
        }
        if (serverType == 2) {
            log.error("LOGIN_REQUEST is sent to a sub-server");
            invalidMessage(con, "LOGIN_REQUEST is sent to a sub-server");
            return true;
        }
        JSONObject responseObj = new JSONObject();
        String username = (String) obj.get("username");
        String secret = (String) obj.get("secret");
        int verify = userVerify(username, secret);
        switch (verify) {
            case 0: break;
            case 1:
                invalidMessage(con, "the message must contain non-null key username");
                return true;
            case 2:
                invalidMessage(con, "the message must contain non-null key secret");
                return true;
            case 3:
            case 4:
                log.debug("username and secret do not match database record");
                responseObj.put("command", "LOGIN_DENY");
                responseObj.put("username", username);
                responseObj.put("secret", secret);
                responseObj.put("key", obj.get("key"));
                con.writeMsg(responseObj.toString());
                return false;
        }
        // login allowed
        log.debug("login request allowed for user " + username);
        responseObj.put("command", "LOGIN_ALLOWED");
        responseObj.put("username", username);
        responseObj.put("secret", secret);
        responseObj.put("key", obj.get("key"));
        con.writeMsg(responseObj.toString());
        // check other servers' load and redirect
        String minHostname = null;
        int minPort = 0;
        int min = Integer.MAX_VALUE;
        for (ServerInfo si : serverInfo.values()) {
            if (si.clientLoad < min) {
                minHostname = si.hostname;
                minPort = si.port;
                min = si.clientLoad;
            }
        }
        responseObj.clear();
        responseObj.put("command", "REDIRECT");
        responseObj.put("username", username);
        responseObj.put("key", obj.get("key"));
        if (centralSI.clientLoad < clientload + 2 && centralSI.clientLoad * 4 < min) {
            // redirect to another central server
            responseObj.put("hostname", Settings.getRemoteHostname());
            responseObj.put("port", Settings.getRemotePort());
            con.writeMsg(responseObj.toString());
        }
        else if (min < clientload * 4 && minHostname != null && minPort != 0) {
            // redirect to sub-server
            responseObj.put("hostname", minHostname);
            responseObj.put("port", minPort);
            con.writeMsg(responseObj.toString());
        }
        return false;
    }

    private boolean loginAllowed(Connection con, JSONObject obj) {
        if (con.getType() != 1) {
            log.info("received LOGIN_ALLOWED from a non-server party");
            invalidMessage(con, "received LOGIN_ALLOWED from a non-server party");
            return true;
        }
        if (!con.equals(mainConnection)) {
            log.info("received LOGIN_ALLOWED from an unauthorized server");
            invalidMessage(con, "received LOGIN_ALLOWED from an unauthorized server");
            return true;
        }
        String username = (String) obj.get("username");
        String secret = (String) obj.get("secret");
        int verify = userVerify(username, secret);
        switch (verify) {
            case 1:
                invalidMessage(con, "the message must contain non-null key username");
                return true;
            case 2:
                invalidMessage(con, "the message must contain non-null key secret");
                return true;
        }
        // send login success to client
        // do not remove due to potential redirection
        log.debug("login allowed for user " + username);
        String key = (String) obj.get("key");
        Connection c = loginMap.get(username + key);
        JSONObject responseObj = new JSONObject();
        responseObj.put("command", "LOGIN_SUCCESS");
        responseObj.put("info", String.format("logged in as user %s", username));
        c.writeMsg(responseObj.toString());
        c.setAuthenticated(true);
        return false;
    }

    private boolean loginDeny(Connection con, JSONObject obj) {
        if (con.getType() != 1) {
            log.error("received LOCK_DENIED from a non-server party");
            invalidMessage(con, "received LOCK_DENIED from a non-server party");
            return true;
        }
        if (!con.equals(mainConnection)) {
            log.error("received LOCK_DENIED from an unauthorized server");
            invalidMessage(con, "received LOCK_DENIED from an unauthorized server");
            return true;
        }
        JSONObject responseObj = new JSONObject();
        String username = (String) obj.get("username");
        String secret = (String) obj.get("secret");
        int verify = userVerify(username, secret);
        switch (verify) {
            case 1:
                invalidMessage(con, "the message must contain non-null key username");
                return true;
            case 2:
                invalidMessage(con, "the message must contain non-null key secret");
                return true;
        }
        // send login failed to client
        log.debug("login failed for user " + username);
        String key = (String) obj.get("key");
        Connection c = loginMap.remove(username + key);
        responseObj.put("command", "LOGIN_FAILED");
        responseObj.put("info", "login request is denied by central server");
        c.writeMsg(responseObj.toString());
        c.setTerm(true);
        return false;
    }

    private boolean redirect(Connection con, JSONObject obj) {
        if (con.getType() != 1) {
            log.error("received REDIRECT from a non-server party");
            invalidMessage(con, "received REDIRECT from a non-server party");
            return true;
        }
        if (!con.equals(mainConnection)) {
            log.error("received REDIRECT from an unauthorized server");
            invalidMessage(con, "received REDIRECT from an unauthorized server");
            return true;
        }
        JSONObject responseObj = new JSONObject();
        String username = (String) obj.get("username");
        String key = (String) obj.get("key");
        // send redirect to client
        log.debug("user " + username + " needs to be redirected");
        Connection c = loginMap.remove(username + key);
        responseObj.put("command", "REDIRECT");
        responseObj.put("hostname", obj.get("hostname"));
        responseObj.put("port", obj.get("port"));
        c.writeMsg(responseObj.toString());
        c.setTerm(true);
        return false;
    }

    private boolean activityReceipt(Connection con, JSONObject obj) {
        if (con.getType() != 1) {
            log.error("received ACTIVITY_RECEIPT from a non-server party");
            invalidMessage(con, "received ACTIVITY_RECEIPT from an unauthenticated server");
            return true;
        }
        String confirmed = obj.get("message").toString();
        String key = con.equals(mainConnection) ? "main_connection" : con.getSocketId();
        List<JSONObject> vList = verifyMsgQueueMap.get(key);
        for (int i = 0; i < vList.size(); i++) {
            String awaiting = vList.get(i).get("message").toString();
            // remove activity message if it is confirmed to be received
            if (confirmed.equals(awaiting)) {
                vList.remove(i);
                i--;
            }
        }
        return false;
    }

    /**
     * Process AUTHENTICATE request. Modified in project 2
     */
	private boolean authenticate(Connection con, JSONObject obj) {
	    // Only connection type 0 (new connection) should send this message
        if (con.getType() == 2) {
            log.error("received AUTHENTICATION from a client");
            invalidMessage(con, "Client should not send authentication request");
            return true;
        }
        if (con.getType() == 1) {
            log.error("AUTHENTICATION is not the first message from this server");
            invalidMessage(con, "Authentication should be the first message");
            return true;
        }
        JSONObject responseObj = new JSONObject();
        String secret = (String) obj.get("secret");
        String type = (String) obj.get("type");
        if (secret == null || !secret.equals(Settings.getSecret())) {
            log.error("the supplied secret is incorrect");
            responseObj.put("command", "AUTHENTICATION_FAIL");
            responseObj.put("info", String.format("the supplied secret is incorrect: %s", secret == null ? "" : secret));
            con.writeMsg(responseObj.toString());
            return true;
        }
        else if (serverType != 0 && serverType != 1) {
            log.info("authenticate to a non-central server, redirect to my main server");
            responseObj.put("command", "SERVER_REDIRECT");
            responseObj.put("hostname", Settings.getRemoteHostname());
            responseObj.put("port", Settings.getRemotePort());
            responseObj.put("type", "main");
            con.writeMsg(responseObj.toString());
            return true;
        }
        else {
            con.setType(1);
            if (type.equals("main")) {
                // only redirect request for a main server
                if (centralSI != null && serverload > centralSI.serverLoad + 5) {
                    log.info("load balancing, redirect to another central server");
                    responseObj.put("command", "SERVER_REDIRECT");
                    responseObj.put("hostname", Settings.getRemoteHostname());
                    responseObj.put("port", Settings.getRemotePort());
                    responseObj.put("type", "main");
                    con.writeMsg(responseObj.toString());
                    return true;
                }
                serverload++;
                boolean redirectNeeded = false;
                responseObj.put("command", "AUTHENTICATE_SUCCESS");
                String host = (String) obj.get("hostname");
                int port = ((Number) obj.get("port")).intValue();
                if (serverType == 0 && Settings.getRemoteHostname() == null) {
                    // this is a brand new backup server, need redirect sub-servers to it
                    Settings.setRemoteHostname(host);
                    Settings.setRemotePort(port);
                    log.info(String.format("Backup server hostname: %s, port: %d", host, port));
                    connections.remove(con);
                    mainConnection = con;
                    con.setMainConnection(true);
                    responseObj.put("type", "backupserver");
                    JSONObject userInfoDup = new JSONObject();
                    userInfoDup.putAll(userInfo);
                    responseObj.put("userinfo", userInfoDup);
                    // redirect sub-servers
                    redirectNeeded = true;
                }
                else if (serverType == 0 && Settings.getRemoteHostname().equals(host) && Settings.getRemotePort() == port) {
                    // this is the previous backup server
                    connections.remove(con);
                    mainConnection = con;
                    con.setMainConnection(true);
                    responseObj.put("type", "backupserver");
                    JSONObject userInfoDup = new JSONObject();
                    userInfoDup.putAll(userInfo);
                    responseObj.put("userinfo", userInfoDup);
                }
                else {
                    responseObj.put("type", "subserver");
                    responseObj.put("pairedhost", Settings.getRemoteHostname());
                    responseObj.put("pairedport", Settings.getRemotePort());
                }
                con.writeMsg(responseObj.toString());
                if (redirectNeeded) {
                    log.info("a new backup server connected, let sub-servers connect to it");
                    for (Connection c : connections) {
                        if (c.getType() == 1) {
                            JSONObject outObj = new JSONObject();
                            outObj.put("command", "SERVER_REDIRECT");
                            outObj.put("hostname", Settings.getRemoteHostname());
                            outObj.put("port", Settings.getRemotePort());
                            outObj.put("type", "backup");
                            c.writeMsg(outObj.toString());
                        }
                    }
                }
            }
            con.setAuthenticated(true);
            return false;
        }
    }

    /**
     * Process SERVER_ANNOUNCE request. Modified in project 2
     */
    private boolean serverAnnounce(Connection con, JSONObject obj) {
        if (con.getType() != 1) {
            log.error("received SERVER_ANNOUNCE from a non-server party");
            invalidMessage(con, "received SERVER_ANNOUNCE from an unauthenticated server");
            return true;
        }
        if (serverType == 2) {
            log.error("Announce to a non-central server");
            invalidMessage(con, "Announce to a non-central server");
        }
        String id = (String) obj.get("id");
        String hostname = (String) obj.get("hostname");
        Number port = (Number) obj.get("port");
        Number serverLoad = (Number) obj.get("serverload");
        Number clientLoad = (Number) obj.get("clientload");
        if (id == null || hostname == null || port == null || serverLoad == null || clientLoad == null) {
            log.error("some fields are missing");
            invalidMessage(con, "some fields are missing");
        }
        // check if this announce comes from another central server
        if (con.equals(mainConnection)) {
            centralSI = new ServerInfo(id, hostname, port.intValue(), serverLoad.intValue(), clientLoad.intValue());
        }
        else {
            // update values in serverInfo map
            ServerInfo si = serverInfo.getOrDefault(con.getSocketId(), new ServerInfo(id, hostname, port.intValue(), serverLoad.intValue(), clientLoad.intValue()));
            if (!si.hostname.equals(hostname) || !(si.port == port.intValue())) {
                log.error("new information does not match with old one");
                invalidMessage(con, "Server hostname/port is changed");
                return true;
            }
            si.serverLoad = serverLoad.intValue();
            si.clientLoad = clientLoad.intValue();
            serverInfo.put(con.getSocketId(), si);
        }
        return false;
    }

    /**
     * Process ACTIVITY_BROADCAST request. Modified in project 2
     */
    private boolean activityBroadcast(Connection con, JSONObject obj) {
        if (con.getType() != 1) {
            log.error("received ACTIVITY_BROADCAST from a non-server party");
            invalidMessage(con, "received ACTIVITY_BROADCAST from an unauthenticated server");
            return true;
        }
        // check if this message is processed before
        String key = obj.toString();
        JSONObject prevAnswer = messageHistory.get(key);
        if (prevAnswer != null) {
            con.writeMsg(prevAnswer.toString());
            return false;
        }
        // broadcast to all connection, including servers and clients except source, if the message is correct
        for (Connection c : connections) {
            if (c.equals(con)) continue;
            if (c.getType() == 1) {
                // use message verify system for server;
                verifyMsgQueueMap.get(c.getSocketId()).add(obj);
            }
            // simply send to client
            c.writeMsg(obj.toString());
        }
        // put the receipt into history and send receipt back
        JSONObject responseObj = new JSONObject();
        responseObj.put("command", "ACTIVITY_RECEIPT");
        responseObj.put("activity", obj);
        con.writeMsg(responseObj.toString());
        messageHistory.put(key, responseObj);
        return false;
    }

    /**
     * Verify the username and secret. Helper function for lock, register, login, and activity.
     * @param username
     * @param secret
     * @return 1 if username is null,
     *         2 if secret is null,
     *         3 if username is not found in local database,
     *         4 if username is found but secret does not match,
     *         0 if username and secret match or username is "anonymous".
     */
    private int userVerify(String username, String secret) {
        if (username == null) {
            log.info("received message does not contain a username");
            return 1;
        }
        if (username.equals("anonymous")) return 0;
        if (secret == null) {
            log.info("received message does not contain a secret");
            return 2;
        }
        if (!userInfo.containsKey(username)) return 3;
        if (!userInfo.get(username).equals(secret)) return 4;
        return 0;
    }

    /**
     * Process LOCK_REQUEST request. Modified in project 2
     */
    private boolean lockRequest(Connection con, JSONObject obj) {
	    if (con.getType() != 1) {
	        log.error("received LOCK_REQUEST from a non-server party");
	        invalidMessage(con, "received LOCK_REQUEST from a non-server party");
	        return true;
        }
        if (serverType == 2) {
	        log.error("LOCK_REQUEST is sent to a sub-server");
	        invalidMessage(con, "LOCK_REQUEST is sent to a sub-server");
	        return true;
        }
        JSONObject responseObj = new JSONObject();
        String username = (String) obj.get("username");
	    String secret = (String) obj.get("secret");
	    int verify = userVerify(username, secret);
	    switch (verify) {
            case 1:
                invalidMessage(con, "the message must contain non-null key username");
                return true;
            case 2:
                invalidMessage(con, "the message must contain non-null key secret");
                return true;
            case 0:
            case 4:
                log.error("username is already registered");
                responseObj.put("command", "LOCK_DENIED");
                responseObj.put("username", username);
                responseObj.put("secret", secret);
                con.writeMsg(responseObj.toString());
                return false;
        }
        if (serverType != 2) {
            // Store user's information in central servers regardless the result of lock request.
            userInfo.put(username, secret);
        }
	    // if this request is from a central server, simply response, otherwise lock request to another central server
        if (con.equals(mainConnection)) {
            responseObj.put("command", "LOCK_ALLOWED");
            responseObj.put("username", username);
            responseObj.put("secret", secret);
        }
        else {
            // Send lock request to main server
            JSONObject requestObj = new JSONObject();
            requestObj.put("command", "LOCK_REQUEST");
            requestObj.put("username", username);
            requestObj.put("secret", secret);
            registerMap.put(username, con);
        }
        if (mainConnection != null)
            mainConnection.writeMsg(responseObj.toString());
	    return false;
    }

    /**
     * Process LOCK_ALLOWED request. Modified in project 2
     */
    private boolean lockAllowed(Connection con, JSONObject obj) {
	    if (con.getType() != 1) {
	        log.error("received LOCK_ALLOWED from a non-server party");
	        invalidMessage(con, "received LOCK_ALLOWED from a non-server party");
	        return true;
        }
        if (!con.equals(mainConnection)) {
	        log.error("received LOCK_ALLOWED from an unauthorized server");
	        invalidMessage(con, "received LOCK_ALLOWED from an unauthorized server");
	        return true;
        }
        JSONObject responseObj = new JSONObject();
        String username = (String) obj.get("username");
        String secret = (String) obj.get("secret");
        int verify = userVerify(username, secret);
        switch (verify) {
            case 1:
                invalidMessage(con, "the message must contain non-null key username");
                return true;
            case 2:
                invalidMessage(con, "the message must contain non-null key secret");
                return true;
        }
        Connection c = registerMap.remove(username);
        // Send lock allowed to server, and register success to client.
        if (c.getType() == 1) {
            responseObj.put("command", "LOCK_ALLOWED");
            responseObj.put("username", username);
            responseObj.put("secret", secret);
            c.writeMsg(responseObj.toString());
        }
        else {
            responseObj.put("command", "REGISTER_SUCCESS");
            responseObj.put("info", String.format("register success for %s", username));
            c.writeMsg(responseObj.toString());
        }
	    return false;
    }

    /**
     * Process LOCK_DENIED request. Modified in project 2
     */
    private boolean lockDenied(Connection con, JSONObject obj) {
	    if (con.getType() != 1) {
	        log.error("received LOCK_DENIED from a non-server party");
	        invalidMessage(con, "received LOCK_DENIED from a non-server party");
	        return true;
        }
        if (!con.equals(mainConnection)) {
            log.error("received LOCK_DENIED from an unauthorized server");
            invalidMessage(con, "received LOCK_DENIED from an unauthorized server");
            return true;
        }
        JSONObject responseObj = new JSONObject();
        String username = (String) obj.get("username");
        String secret = (String) obj.get("secret");
        int verify = userVerify(username, secret);
        switch (verify) {
            case 1:
                invalidMessage(con, "the message must contain non-null key username");
                return true;
            case 2:
                invalidMessage(con, "the message must contain non-null key secret");
                return true;
        }
        if (serverType != 2) {
            // remove userinfo in local database of central servers
            userInfo.remove(username);
        }
        Connection c = registerMap.remove(username);
        // Send lock denied to server, and register failed to client.
        if (c.getType() == 1) {
            responseObj.put("command", "LOCK_DENIED");
            responseObj.put("username", username);
            responseObj.put("secret", secret);
            c.writeMsg(responseObj.toString());
        }
        else {
            responseObj.put("command", "REGISTER_FAILED");
            responseObj.put("info", String.format("%s is already registered with the system", username));
            c.writeMsg(responseObj.toString());
            c.setTerm(true);
        }
        return false;
    }

    /**
     * Process REGISTER request. Modified in project 2.
     */
    private boolean register(Connection con, JSONObject obj) {
	    if (con.getType() == 1) {
	        log.error("received REGISTER from a server");
	        invalidMessage(con, "Server should not send REGISTER request");
	        return true;
        }
        if (con.getType() == 0) {
            con.setType(2);
            clientload++;
        }
        JSONObject responseObj = new JSONObject();
	    String username = (String) obj.get("username");
        String secret = (String) obj.get("secret");
        int verify = userVerify(username, secret);
        switch (verify) {
            case 1:
                invalidMessage(con, "the message must contain non-null key username");
                return true;
            case 2:
                invalidMessage(con, "the message must contain non-null key secret");
                return true;
            case 0:
            case 4:
                log.error("username is already registered");
                responseObj.put("command", "REGISTER_FAILED");
                responseObj.put("info", String.format("%s is already registered with the system", username));
                con.writeMsg(responseObj.toString());
                return true;
        }
        if (serverType != 2) {
            // Store user's information regardless the result of lock request.
            userInfo.put(username, secret);
            if (Settings.getRemoteHostname() == null) { // no other central server
                responseObj.put("command", "REGISTER_SUCCESS");
                responseObj.put("info", String.format("register success for %s", username));
                con.writeMsg(responseObj.toString());
                return false;
            }
        }
        // Send lock request to main server
        JSONObject requestObj = new JSONObject();
        requestObj.put("command", "LOCK_REQUEST");
        requestObj.put("username", username);
        requestObj.put("secret", secret);
        if (mainConnection != null)
            mainConnection.writeMsg(requestObj.toString());
        registerMap.put(username, con);
        return false;
    }

    /**
     * Process LOGIN request. Modified in project 2
     */
    private boolean login(Connection con, JSONObject obj) {
		if (con.getType() == 1) {
			log.info("received LOGIN from a server");
			invalidMessage(con, "Server should not send LOGIN request");
			return true;
		}
		if (con.getType() == 0) {
		    con.setType(2);
		    clientload++;
        }
        JSONObject responseObj = new JSONObject();
		String username = (String) obj.get("username");
		String secret = (String) obj.get("secret");
		int verify = userVerify(username, secret);
        switch (verify) {
            case 1:
                invalidMessage(con, "the message must contain non-null key username");
                return true;
            case 2:
                invalidMessage(con, "the message must contain non-null key secret");
                return true;
        }
		if (serverType == 2) {
            // send login request to main server
            log.debug("login request for user " + username);
            JSONObject requestObj = new JSONObject();
            requestObj.put("command", "LOGIN_REQUEST");
            requestObj.put("username", username);
            requestObj.put("secret", secret);
            requestObj.put("key", con.getSocketId());
            if (mainConnection != null)
                mainConnection.writeMsg(requestObj.toString());
            loginMap.put(username + con.getSocketId(), con);
            return false;
        }
        else {
            switch (verify) {
                case 3:
                    log.error("username is not found in database");
                    responseObj.put("command", "LOGIN_FAILED");
                    responseObj.put("info", String.format("user %s is not registered", username));
                    con.writeMsg(responseObj.toString());
                    return true;
                case 4:
                    log.error("username and secret do not match");
                    responseObj.put("command", "LOGIN_FAILED");
                    responseObj.put("info", String.format("the supplied secret is incorrect: %s", secret));
                    con.writeMsg(responseObj.toString());
                    return true;
            }
            // login allowed
            log.debug("login allowed for user " + username);
            responseObj.put("command", "LOGIN_SUCCESS");
            responseObj.put("info", String.format("logged in as user %s", username));
            con.writeMsg(responseObj.toString());
            // check other servers' load and redirect
            String minHostname = null;
            int minPort = 0;
            int min = Integer.MAX_VALUE;
            for (ServerInfo si : serverInfo.values()) {
                if (si.clientLoad < min) {
                    minHostname = si.hostname;
                    minPort = si.port;
                    min = si.clientLoad;
                }
            }
            responseObj.clear();
            responseObj.put("command", "REDIRECT");
            if (centralSI != null && centralSI.clientLoad < clientload + 2 && centralSI.clientLoad * 4 < min) {
                // redirect to another central server
                responseObj.put("hostname", Settings.getRemoteHostname());
                responseObj.put("port", Settings.getRemotePort());
                con.writeMsg(responseObj.toString());
                return true;
            }
            else if (min < clientload * 4 && minHostname != null && minPort != 0) {
                // redirect to sub-server
                responseObj.put("hostname", minHostname);
                responseObj.put("port", minPort);
                con.writeMsg(responseObj.toString());
                return true;
            }
            con.setAuthenticated(true);
        }
        return false;
	}

    /**
     * Process ACTIVITY_MESSAGE request. Modified in project 2
     */
	private boolean activityMessage(Connection con, JSONObject obj) {
	    if (con.getType() != 2) {
	        log.error("received ACTIVITY_MESSAGE from a non-client party");
	        invalidMessage(con, "Non-client should not send ACTIVITY_MESSAGE");
	        return true;
        }
        JSONObject responseObj = new JSONObject();
        String username = (String) obj.get("username");
	    String secret = (String) obj.get("secret");
	    JSONObject activity = (JSONObject) obj.get("activity");
        int verify = userVerify(username, secret);
        switch (verify) {
            case 0: break;
            case 1:
                invalidMessage(con, "the message must contain non-null key username");
                return true;
            case 2:
                invalidMessage(con, "the message must contain non-null key secret");
                return true;
            case 3:
            case 4:
                log.error("username and secret do not match");
                responseObj.put("command", "AUTHENTICATION_FAIL");
                responseObj.put("info", "username and/or secret is incorrect");
                con.writeMsg(responseObj.toString());
                return true;
        }
        // check if this user logged in
        if (!con.isAuthenticated()) {
            log.error("user has not logged in");
            responseObj.put("command", "AUTHENTICATION_FAIL");
            responseObj.put("info", "must send a LOGIN message first");
            con.writeMsg(responseObj.toString());
            return true;
        }
        // build ACTIVITY_BROADCAST JSON and send to all server and client connections
        activity.put("authenticated_user", username);
        responseObj.put("command", "ACTIVITY_BROADCAST");
        responseObj.put("activity", activity);
        // get current system time and put it in message
        String time = Long.toString(System.currentTimeMillis());
        responseObj.put("time", time);
        if (serverType == 2 && mainConnection != null) {
            mainConnection.writeMsg(responseObj.toString());
            verifyMsgQueueMap.get("main_connection").add(responseObj);
        }
        for (Connection c : connections) {
            if (c.getType() == 1) {
                // use message verify system for server
                verifyMsgQueueMap.get(c.getSocketId()).add(responseObj);
            }
            // simply send to client
            c.writeMsg(responseObj.toString());
        }
	    return false;
    }

	/*
	 * The connection has been closed by the other party.
	 */
	public synchronized void connectionClosed(Connection con, boolean partition) {
		if (term) return;
		if (con.equals(mainConnection)) {
		    serverload--;
            mainConnection = null;
            centralSI = null;
            if (serverType == 1 && !partition) {
                serverType = 0;
                Settings.setRemoteHostname(null);
                Settings.setRemotePort(0);
            }
            if (serverType == 2) {
                if (backupConnection == null) {
                    log.error("no central server is connected, keep pinging main server");
                }
                mainConnection = backupConnection;
                mainConnection.setMainConnection(true);
                String tempHostname = Settings.getRemoteHostname();
                int tempport = Settings.getRemotePort();
                Settings.setRemoteHostname(backupHostname);
                Settings.setRemotePort(backupPort);
                backupConnection = null;
                backupHostname = tempHostname;
                backupPort = tempport;
            }
        }
        else if (con.equals(backupConnection)) {
		    serverload--;
            backupConnection = null;
        }
        else {
		    connections.remove(con);
		    serverInfo.remove(con.getSocketId());
            if (con.getType() == 1) serverload--;
            else clientload--;
        }
	}
	
	/*
	 * A new incoming connection has been established, and a reference is returned to it
	 */
	public synchronized Connection incomingConnection(Socket s) throws IOException {
		log.debug("incoming connection: " + Settings.socketAddress(s));
		Connection c = new Connection(s);
        verifyMsgQueueMap.put(Settings.socketAddress(s), new ArrayList<>());
		connections.add(c);
		return c;
	}
	
	/*
	 * A new outgoing connection has been established, and a reference is returned to it
	 */
	public synchronized Connection outgoingConnection(Socket s) throws IOException{
		log.debug("outgoing connection: " + Settings.socketAddress(s));
		Connection c = new Connection(s);
        verifyMsgQueueMap.put(Settings.socketAddress(s), new ArrayList<>());
		c.setType(1);
		serverload++;
		return c;
	}

    /**
     * Get the entire verify message list associates to given socket id
     */
    public ArrayList<JSONObject> getVerifyMsgList(String key) {
        return verifyMsgQueueMap.get(key);
    }

    /**
     * Enqueue
     */
    public boolean addVerifyMsg(String key, JSONObject msgInfo) {
        ArrayList l = verifyMsgQueueMap.get(key);
        if (l == null) return false;
        l.add(msgInfo);
        return true;
    }

    /**
     * Whether this server is ready to work
     * @return
     */
	public boolean initialized() {
	    return serverType != -1;
    }
	
	@Override
	public void run() {
		log.info("using activity interval of " + Settings.getActivityInterval() + " milliseconds");
		while (!term) {
			// do something with 5 second intervals in between
			try {
				Thread.sleep(Settings.getActivityInterval());
			} catch (InterruptedException e) {
				log.info("received an interrupt, system is shutting down");
				break;
			}
			if (!term) {
				term = doActivity();
			}
		}
        listener.setTerm(true);

		// notify all connections
        JSONObject outObj = new JSONObject();
        outObj.put("command", "SERVER_QUIT");
        if (serverType != 2) {
            for (Connection c : connections)
                if (c.getType() == 1)
                    c.writeMsg(outObj.toString());
        }
        else if (backupConnection != null) {
            backupConnection.writeMsg(outObj.toString());
        }
        if (mainConnection != null)
            mainConnection.writeMsg(outObj.toString());

        // clean up
		log.info("closing " + connections.size() + " connections");
		for(Connection connection : connections){
			connection.closeCon();
		}
	}
	
	public boolean doActivity() {
	    // wrap up current server info and send to server connections
	    JSONObject outObj = new JSONObject();
	    outObj.put("command", "SERVER_ANNOUNCE");
	    outObj.put("id", id);
	    outObj.put("type", serverType == 2 ? "subserver" : "centralserver");
	    outObj.put("serverload", serverload);
	    outObj.put("clientload", clientload);
	    outObj.put("hostname", Settings.getLocalHostname());
	    outObj.put("port", Settings.getLocalPort());
	    log.debug(String.format("server load: %d, client load: %d", serverload, clientload));
	    if (serverType != 0 && mainConnection == null && Settings.getRemoteHostname() != null) {
            // this server should connect to a main server but it does not
            // Alpha central server does not ping others
            log.debug("trying to establish a connection with main server");
            // then try to establish a connection using given parameters
            try {
                mainConnection = outgoingConnection(new Socket(Settings.getRemoteHostname(), Settings.getRemotePort()));
                mainConnection.setMainConnection(true);
                // Send authentication to remote host
                JSONObject requestObj = new JSONObject();
                requestObj.put("command", "AUTHENTICATE");
                requestObj.put("secret", Settings.getSecret());
                requestObj.put("hostname", Settings.getLocalHostname());
                requestObj.put("port", Settings.getLocalPort());
                requestObj.put("type", "main");
                mainConnection.writeMsg(requestObj.toString());
            } catch (IOException e) {
                mainConnection = null;
                log.error("failed to setup main server, retry in 5 seconds");
            }
        }
        if (backupConnection == null && backupHostname != null) {
            // this server should connect to a backup server but it does not
            log.debug("trying to establish a connection with backup server");
            // then try to establish a connection using given parameters
            try {
                backupConnection = outgoingConnection(new Socket(backupHostname, backupPort));
                backupConnection.setMainConnection(false);
                // Send authentication to remote host
                JSONObject requestObj = new JSONObject();
                requestObj.put("command", "AUTHENTICATE");
                requestObj.put("secret", Settings.getSecret());
                requestObj.put("hostname", Settings.getLocalHostname());
                requestObj.put("port", Settings.getLocalPort());
                requestObj.put("type", "backup");
                mainConnection.writeMsg(requestObj.toString());
            } catch (IOException e) {
                mainConnection = null;
                log.error("failed to setup backup server, retry in 5 seconds");
            }
        }
	    if (mainConnection != null) {
	        mainConnection.writeMsg(outObj.toString());
        }
	    if (serverType == 2 && backupConnection != null) {
	        backupConnection.writeMsg(outObj.toString());
        }
        // central servers announce to sub-servers that they are still alive
        // used to pass timeout check
        if (serverType == 0 || serverType == 1) {
            outObj.clear();
            outObj.put("command", "STILL_ALIVE");
            for (Connection c : connections) {
                if (c.getType() == 1) {
                    c.writeMsg(outObj.toString());
                }
            }
        }
		return false;
	}
	
	public final void setTerm(boolean t) {
		term = t;
	}
	
	public final ArrayList<Connection> getConnections() {
		return connections;
	}
}
