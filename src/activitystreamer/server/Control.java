package activitystreamer.server;

import java.io.IOException;
import java.net.Socket;
import java.net.SocketException;
import java.util.ArrayList;
import java.util.Map;
import java.util.HashMap;

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
    // type of server, -1 undefined, 0 - MAIN server, 1 - BACKUP server, 2 - SUB server
    private int serverType = -1;
    private String backupHostname = null;
    private int backupPort = -1;
    private String centralHostname = null;
    private int centralPort = -1;
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
	// map awaiting lock request connection with requested username
	private static Map<String, Connection> connectionMap;
	
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
        connectionMap = new HashMap<>();
        // build initial connection
        initiateConnection();
		// start a listener
		try {
            // start listener
			listener = new Listener();
		} catch (IOException e1) {
			log.fatal("failed to startup a listening thread: " + e1);
			System.exit(-1);
		}
		// start server announce thread
		start();
	}
	
	public void initiateConnection() {
		// make a connection to another server if remote hostname is supplied
		if (Settings.getRemoteHostname() != null) {
			try {
				mainConnection = outgoingConnection(new Socket(Settings.getRemoteHostname(), Settings.getRemotePort()));
				// Send authentication to remote host
                JSONObject requestObj = new JSONObject();
                requestObj.put("command", "AUTHENTICATE");
                requestObj.put("secret", Settings.getSecret());
                requestObj.put("interval", Settings.getActivityInterval());
                requestObj.put("type", "main");
                mainConnection.writeMsg(requestObj.toString());
			} catch (IOException e) {
				log.error("failed to make connection to " + Settings.getRemoteHostname() + ":" + Settings.getRemotePort() + " :" + e);
				System.exit(-1);
			}
		}
		else {
		    serverType = 0;
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
	    // basic format check
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
        // process different commands
        switch (command) {
	        /* Server communication part */
            case "AUTHENTICATE":
                return authenticate(con, requestObj);
            case "AUTHENTICATION_FAIL":
                log.error(String.format("AUTHENTICATION_FAIL, %s", requestObj.get("info")));
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
            case "LOGIN_REQUEST":
                return loginRequest(con, requestObj);
            case "SERVER_QUIT":
                return true;
            /* Client part */
            case "REGISTER":
                return register(con, requestObj);
            case "LOGIN":
                return login(con, requestObj);
            case "LOGOUT":
            	con.setLogin(false);
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
        switch (type) {
            case "backupserver":
                centralHostname = con.getSocket().getInetAddress().getHostAddress();
                centralPort = con.getSocket().getPort();
                Map userInfoDup = (Map) obj.get("userinfo");
                if (userInfoDup != null)
                    userInfo = userInfoDup;
                return false;
            case "subserver":
                try {
                    backupHostname = (String) obj.get("pairedhost");
                    backupPort = ((Number) obj.get("pairedport")).intValue();
                    backupConnection = outgoingConnection(new Socket(backupHostname, backupPort));
                    JSONObject requestObj = new JSONObject();
                    requestObj.put("command", "AUTHENTICATE");
                    requestObj.put("secret", Settings.getSecret());
                    requestObj.put("interval", Settings.getActivityInterval());
                    requestObj.put("type", "backup");
                    backupConnection.writeMsg(requestObj.toString());
                    return false;
                } catch (Exception e) {
                    log.error("failed to start backup connection: " + e);
                    return true;
                }
            default:
                log.error("the message does not contain a valid server type");
                invalidMessage(con, "the message does not contain a valid server type");
                return true;
        }
    }

    private boolean loginRequest(Connection con, JSONObject obj) {
        return false;
    }

    /**
     * Process AUTHENTICATE request. Modified in project 2
     * @param con source connection,
     * @param obj JSON object of message.
     * @return true if connection should be closed.
     */
	private boolean authenticate(Connection con, JSONObject obj) {
	    // Only connection type 0 (new connection) should send this message
        if (con.getType() == 2) {
            log.error("received AUTHENTICATION from a client");
            invalidMessage(con, "Client should not send authentication request");
        }
        if (con.getType() == 1) {
            log.error("AUTHENTICATION is not the first message from this server");
            invalidMessage(con, "Authentication should be the first message");
        }
        if (serverType != 0 && serverType != 1) {
            log.error("Authenticate to a non-central server");
            invalidMessage(con, "Authenticate to a non-central server");
        }
        JSONObject responseObj = new JSONObject();
        String secret = (String) obj.get("secret");
        if (secret == null || !secret.equals(Settings.getSecret())) {
            log.error("the supplied secret is incorrect");
            responseObj.put("command", "AUTHENTICATION_FAIL");
            responseObj.put("info", String.format("the supplied secret is incorrect: %s", secret == null ? "" : secret));
            con.writeMsg(responseObj.toString());
            return true;
        }
        else {
            con.setType(1);
            serverload++;
            String type = (String) obj.get("type");
            if (type.equals("main")) {
                responseObj.put("command", "AUTHENTICATE_SUCCESS");
                if (serverType == 0 && centralHostname == null) {
                    centralHostname = con.getSocket().getInetAddress().getHostAddress();
                    centralPort = con.getSocket().getPort();
                    log.info(String.format("Backup server hostname: %s, port: %d", centralHostname, centralPort));
                    connections.remove(con);
                    mainConnection = con;
                    responseObj.put("type", "backupserver");
                    JSONObject userInfoDup = new JSONObject();
                    userInfoDup.putAll(userInfo);
                    responseObj.put("userinfo", userInfoDup);
                } else {
                    Socket s = con.getSocket();
                    responseObj.put("type", "subserver");
                    responseObj.put("pairedhost", s.getInetAddress().getHostAddress());
                    responseObj.put("pairedport", s.getPort());
                }
                con.writeMsg(responseObj.toString());
            }
            try {
                int interval = ((Number) obj.get("interval")).intValue();
                con.getSocket().setSoTimeout(interval * 2);
            } catch (SocketException e) {
                log.error("failed to set socket timeout" + e);
            }
            return false;
        }
    }

    /**
     * Process SERVER_ANNOUNCE request.
     * @param con source connection,
     * @param obj JSON object of message.
     * @return true if connection should be closed.
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
        // update values in serverInfo map
        ServerInfo si = serverInfo.getOrDefault(id, new ServerInfo(id, hostname, port.intValue(), serverLoad.intValue(), clientLoad.intValue()));
        if (!si.hostname.equals(hostname) || !(si.port == port.intValue())) {
            log.error("new information does not match with old one");
            invalidMessage(con, "Server hostname/port is changed");
            return true;
        }
        si.serverLoad = serverLoad.intValue();
        si.clientLoad = clientLoad.intValue();
        serverInfo.put(id, si);
        return false;
    }

    /**
     * Process ACTIVITY_BROADCAST request.
     * @param con source connection,
     * @param obj JSON object of message.
     * @return true if connection should be closed.
     */
    private boolean activityBroadcast(Connection con, JSONObject obj) {
        if (con.getType() != 1) {
            log.error("received ACTIVITY_BROADCAST from a non-server party");
            invalidMessage(con, "received SERVER_ANNOUNCE from an unauthenticated server");
            return true;
        }
        // broadcast to all connection, including servers and clients except source, if the message is correct
        for (Connection c : connections) {
            if (c.equals(con)) continue;
            c.writeMsg(obj.toString());
        }
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
            log.error("received message does not contain a username");
            return 1;
        }
        if (username.equals("anonymous")) return 0;
        if (secret == null) {
            log.error("received message does not contain a secret");
            return 2;
        }
        if (!userInfo.containsKey(username)) return 3;
        if (!userInfo.get(username).equals(secret)) return 4;
        return 0;
    }

    /**
     * Process LOCK_REQUEST request.
     * @param con source connection,
     * @param obj JSON object of message.
     * @return true if connection should be closed.
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
        // Store user's information regardless the result of lock request.
        userInfo.put(username, secret);
	    // if this request is from a central server, simply response, otherwise lock request to another central server
        if (con.equals(mainConnection)) {
            responseObj.put("command", "LOCK_ALLOWED");
            responseObj.put("username", username);
            responseObj.put("secret", secret);
            con.writeMsg(responseObj.toString());
        }
        else {
            // Send lock request to main server
            JSONObject requestObj = new JSONObject();
            requestObj.put("command", "LOCK_REQUEST");
            requestObj.put("username", username);
            requestObj.put("secret", secret);
            mainConnection.writeMsg(requestObj.toString());
            connectionMap.put(username, con);
        }
	    return false;
    }

    /**
     * Process LOCK_ALLOWED request.
     * @param con source connection,
     * @param obj JSON object of message.
     * @return true if connection should be closed.
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
        Connection c = connectionMap.remove(username);
        // Send lock allowed to server, and register success to client.
        if (c.getType() == 1) {
            responseObj.put("command", "LOCK_ALLOWED");
            responseObj.put("username", username);
            responseObj.put("secret", secret);
        }
        else {
            responseObj.put("command", "REGISTER_SUCCESS");
            responseObj.put("info", String.format("register success for %s", username));
        }
        c.writeMsg(responseObj.toString());
	    return false;
    }

    /**
     * Process LOCK_DENIED request.
     * @param con source connection,
     * @param obj JSON object of message.
     * @return true if connection should be closed.
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
        Connection c = connectionMap.remove(username);
        // Send lock denied to server, and register failed to client.
        if (c.getType() == 1) {
            responseObj.put("command", "LOCK_DENIED");
            responseObj.put("username", username);
            responseObj.put("secret", secret);
        }
        else {
            responseObj.put("command", "REGISTER_FAILED");
            responseObj.put("info", String.format("%s is already registered with the system", username));
        }
        if (c.getType() == 2) c.closeCon();
	    return false;
    }

    /**
     * Process REGISTER request. Modified in project 2.
     * @param con source connection,
     * @param obj JSON object of message.
     * @return true if connection should be closed.
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
        if (serverType != 2) {
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
            // Store user's information regardless the result of lock request.
            userInfo.put(username, secret);
        }
        // Send lock request to main server
        if (mainConnection != null) {
            JSONObject requestObj = new JSONObject();
            requestObj.put("command", "LOCK_REQUEST");
            requestObj.put("username", username);
            requestObj.put("secret", secret);
            mainConnection.writeMsg(requestObj.toString());
            connectionMap.put(username, con);
        }
        else {
            responseObj.put("command", "REGISTER_SUCCESS");
            responseObj.put("info", String.format("register success for %s", username));
            con.writeMsg(responseObj.toString());
        }
        return false;
    }

    /**
     * Process LOGIN request.
     * @param con source connection,
     * @param obj JSON object of message.
     * @return true if connection should be closed.
     */
    private boolean login(Connection con, JSONObject obj) {
		if (con.getType() == 1) {
			log.error("received LOGIN from a server");
			invalidMessage(con, "Server should not send LOGIN request");
			return true;
		}
		if (con.getType() == 0) con.setType(2);
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
        responseObj.put("command", "LOGIN_SUCCESS");
        responseObj.put("info", String.format("logged in as user %s", username));
        con.writeMsg(responseObj.toString());
        // check other servers' load and redirect
        for (ServerInfo si : serverInfo.values()) {
            int clientLoad = si.clientLoad;
            if (clientLoad <= connections.size() - 2) {
                responseObj.clear();
                responseObj.put("command", "REDIRECT");
                responseObj.put("hostname", si.hostname);
                responseObj.put("port", si.port);
                con.writeMsg(responseObj.toString());
                return true;
            }
        }
        // set login flag
        con.setLogin(true);
        return false;
	}

    /**
     * Process ACTIVITY_MESSAGE request.
     * @param con source connection,
     * @param obj JSON object of message.
     * @return true if connection should be closed.
     */
	private boolean activityMessage(Connection con, JSONObject obj) {
        JSONObject responseObj = new JSONObject();
	    if (con.getType() != 2) {
	        log.error("received ACTIVITY_MESSAGE from a non-client party");
	        invalidMessage(con, "Non-client should not send ACTIVITY_MESSAGE");
	        return true;
        }
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
        if (!con.getLogin()) {
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
        for (Connection c : connections) {
            c.writeMsg(responseObj.toString());
        }
	    return false;
    }

	/*
	 * The connection has been closed by the other party.
	 */
	public synchronized void connectionClosed(Connection con) {
		if (term) return;
		if (con.equals(mainConnection)) {
            mainConnection = null;
		    if (serverType == 1) serverType = 0;
		    else if (serverType == 2) {
		        if (backupConnection == null) {
		            // no central server is available, this sub-server is useless
                    log.fatal("no central server is available, entire system is unrecoverable");
                    Control.getInstance().setTerm(true);
                }
                else {
                    mainConnection = backupConnection;
                    backupConnection = null;
                }
            }
        }
        else if (con.equals(backupConnection)) {
            backupConnection = null;
        }
        else {
            connections.remove(con);
            if (con.getType() == 2) clientload--;
            else if (con.getType() == 1) serverload--;
        }
	}
	
	/*
	 * A new incoming connection has been established, and a reference is returned to it
	 */
	public synchronized Connection incomingConnection(Socket s) throws IOException {
		log.debug("incoming connection: " + Settings.socketAddress(s));
		Connection c = new Connection(s);
		connections.add(c);
		return c;
	}
	
	/*
	 * A new outgoing connection has been established, and a reference is returned to it
	 */
	public synchronized Connection outgoingConnection(Socket s) throws IOException{
		log.debug("outgoing connection: " + Settings.socketAddress(s));
		Connection c = new Connection(s);
		c.setType(1);
		return c;
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
				log.debug("doing activity");
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
	    if (mainConnection != null)
	        mainConnection.writeMsg(outObj.toString());
	    if (serverType == 2 && backupConnection != null)
            backupConnection.writeMsg(outObj.toString());
		return false;
	}
	
	public final void setTerm(boolean t) {
		term = t;
	}
	
	public final ArrayList<Connection> getConnections() {
		return connections;
	}
}
