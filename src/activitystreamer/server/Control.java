package activitystreamer.server;

import java.io.IOException;
import java.net.Socket;
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
    private static final String id = Settings.nextSecret();
	private static final Logger log = LogManager.getLogger();
	private static ArrayList<Connection> connections;
	private static boolean term = false;
	private static Listener listener;
    private JSONParser parser = new JSONParser();
	
	protected static Control control = null;

	// local database that store the username and secret
	private Map<String, String> userInfo = new HashMap<>();
	// server info class that store the content of server announce
	class ServerInfo {
	    String id;
	    String hostname;
	    long port;
	    long load;
	    ServerInfo(String id, String hostname, long port, long load) {
	        this.id = id;
	        this.hostname = hostname;
	        this.port = port;
	        this.load = load;
        }
    }
    // map server info with server id
    private Map<String, ServerInfo> serverInfo = new HashMap<>();
	// map awaiting lock requests count with requested username
	private Map<String, Integer> lockMap = new HashMap<>();
	// map awaiting lock request connection with requested username
	private Map<String, Connection> connectionMap = new HashMap<>();
	
	public static Control getInstance() {
		if (control == null) {
			control = new Control();
		} 
		return control;
	}
	
	public Control() {
		// initialize the connections array
		connections = new ArrayList<>();
		// start a listener
		try {
			listener = new Listener();
			// build initial connection
			initiateConnection();
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
				Connection con = outgoingConnection(new Socket(Settings.getRemoteHostname(), Settings.getRemotePort()));
				// Send authentication to remote host
                JSONObject requestObj = new JSONObject();
                requestObj.put("command", "AUTHENTICATE");
                requestObj.put("secret", Settings.getSecret());
                con.writeMsg(requestObj.toString());
                // server connection type
                con.setType(1);
			} catch (IOException e) {
				log.error("failed to make connection to " + Settings.getRemoteHostname() + ":" + Settings.getRemotePort() + " :" + e);
				System.exit(-1);
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
	        // Server communication part
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
            // Client part
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

    /**
     * Process AUTHENTICATE request.
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
        String secret = (String) obj.get("secret");
        if (secret == null || !secret.equals(Settings.getSecret())) {
            log.error("the supplied secret is incorrect");
            invalidMessage(con, String.format("the supplied secret is incorrect: %s", secret == null ? "" : secret));
        }
        else {
            con.setType(1);
            return false;
        }
        return true;
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
        String id = (String) obj.get("id");
        String hostname = (String) obj.get("hostname");
        Long port = (Long) obj.get("port");
        Long load = (Long) obj.get("load");
        if (id == null || hostname == null || port == null || load == null) {
            log.error("some fields are missing");
            invalidMessage(con, "some fields are missing");
        }
        // update values in serverInfo map
        ServerInfo si = serverInfo.getOrDefault(id, new ServerInfo(id, hostname, port.longValue(), load.longValue()));
        if (!si.hostname.equals(hostname) || !(si.port == port.longValue())) {
            log.error("new information does not match with old one");
            invalidMessage(con, "Server hostname/port is changed");
            return true;
        }
        si.load = load.longValue();
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
        // Send lock request to all server connections
        JSONObject requestObj = new JSONObject();
        requestObj.put("command", "LOCK_REQUEST");
        requestObj.put("username", username);
        requestObj.put("secret", secret);
        int requestCount = 0;
        for (Connection c : connections) {
            if (c.getType() == 1 && !c.equals(con)) {
                c.writeMsg(requestObj.toString());
                requestCount++;
            }
        }
        // If no lock request awaiting, lock allowed. Otherwise, store request count and connection map.
        if (requestCount == 0) {
            responseObj.put("command", "LOCK_ALLOWED");
            responseObj.put("username", username);
            responseObj.put("secret", secret);
            con.writeMsg(responseObj.toString());
        }
        else {
            lockMap.put(username, requestCount);
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
        // Return if a previous LOCK_DENIED is received
        if (!lockMap.containsKey(username)) return false;
        // Calculate the rest amount of awaiting request.
        int requestCount = lockMap.get(username) - 1;
        // If no more request awaiting, send lock allowed or register success. Other wise wait for others' reply.
        if (requestCount == 0) {
            lockMap.remove(username);
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
        }
        else {
            lockMap.put(username, requestCount);
        }
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
        // Remove items from lock map and connection map.
        lockMap.remove(username);
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
        c.writeMsg(responseObj.toString());
        // If this is a client connection, close it.
        if (c.getType() == 2) c.closeCon();
	    return false;
    }

    /**
     * Process REGISTER request.
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
        if (con.getType() == 0) con.setType(2);
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
        // Store user's information regardless the result of lock request.
        userInfo.put(username, secret);
        // Send lock request to all server connections
        JSONObject requestObj = new JSONObject();
        requestObj.put("command", "LOCK_REQUEST");
        requestObj.put("username", username);
        requestObj.put("secret", secret);
        int requestCount = 0;
        for (Connection c : connections) {
            if (c.getType() == 1) {
                c.writeMsg(requestObj.toString());
                requestCount++;
            }
        }
        // If no lock request awaiting, register success. Otherwise, store request count and connection map.
        if (requestCount == 0) {
            responseObj.put("command", "REGISTER_SUCCESS");
            responseObj.put("info", String.format("register success for %s", username));
            con.writeMsg(responseObj.toString());
        }
        else {
            lockMap.put(username, requestCount);
            connectionMap.put(username, con);
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
            int load = (int) si.load;
            if (load <= connections.size() - 2) {
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
		if (!term) connections.remove(con);
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
		connections.add(c);
		return c;
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
		log.info("closing " + connections.size() + " connections");
		// clean up
		for(Connection connection : connections){
			connection.closeCon();
		}
		listener.setTerm(true);
	}
	
	public boolean doActivity() {
	    // wrap up current server info and send to server connections
	    JSONObject outObj = new JSONObject();
	    outObj.put("command", "SERVER_ANNOUNCE");
	    outObj.put("id", id);
	    outObj.put("load", connections.size());
	    outObj.put("hostname", Settings.getLocalHostname());
	    outObj.put("port", Settings.getLocalPort());
	    for (Connection c : connections) {
	        if (c.getType() == 1) {
	            c.writeMsg(outObj.toString());
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
