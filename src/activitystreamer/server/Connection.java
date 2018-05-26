package activitystreamer.server;


import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.util.ArrayList;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import activitystreamer.util.Settings;
import org.json.simple.JSONObject;


public class Connection extends Thread {
	private static final Logger log = LogManager.getLogger();
	private DataInputStream in;
	private DataOutputStream out;
	private BufferedReader inreader;
	private PrintWriter outwriter;
	private boolean open = false;
	private Socket socket;
	private boolean term = false;

	private boolean mainConnection;
	private Sender instantSender;
    private Sender verifySender;

	// Type of connection, 0 - undefined, 1 - with a server, 2 - with a client
	private int type = 0;
	// Whether this connection is authenticated
	private boolean authenticated;
	
	Connection(Socket socket) throws IOException {
		in = new DataInputStream(socket.getInputStream());
	    out = new DataOutputStream(socket.getOutputStream());
	    inreader = new BufferedReader( new InputStreamReader(in));
	    outwriter = new PrintWriter(out, true);
	    this.socket = socket;
	    this.socket.setSoTimeout(15 * 1000);
	    open = true;
	    mainConnection = false;
        authenticated = false;
        verifySender = new Sender(this, 10 * 1000);
        instantSender = new Sender(this, 0);
        start();
	}
	
	/*
	 * returns true if the message was written, otherwise false
	 */
	public synchronized boolean writeMsg(String msg) {
		if (open) {
			outwriter.println(msg);
			outwriter.flush();
			return true;
		}
		return false;
	}
	
	public void closeCon() {
		if (open) {
			log.info("closing connection " + Settings.socketAddress(socket));
			try {
				term = true;
                instantSender.setTerm(true);
                instantSender.interrupt();
                verifySender.setTerm(true);
                verifySender.interrupt();
				inreader.close();
				out.close();
			} catch (IOException e) {
				// already closed?
				log.error("received exception closing the connection " + Settings.socketAddress(socket) + ": " + e);
			}
		}
	}
	
	
	public void run() {
		try {
			String data;
			while (!term && (data = inreader.readLine()) != null) {
				term = Control.getInstance().process(this, data);
			}
			// other party crash or quit
			log.debug("connection closed to " + Settings.socketAddress(socket));
			Control.getInstance().connectionClosed(this, false);
			in.close();
		} catch (IOException e) {
		    if (e instanceof  SocketTimeoutException) {
		        // network partition situation
                log.error("received timeout from connection " + Settings.socketAddress(socket));
                Control.getInstance().connectionClosed(this, true);
            }
            else {
                log.error("connection " + Settings.socketAddress(socket) + " closed with exception: " + e);
                Control.getInstance().connectionClosed(this, false);
            }
        }
		open = false;
	}
	
	public Socket getSocket() {
		return socket;
	}
	
	public boolean isOpen() {
		return open;
	}

	public void setTerm(boolean t) {
	    term = t;
    }

	public int getType() {
	    return type;
    }

    public boolean setType(int type) {
	    if (this.type != 0) return false;
	    this.type = type;
	    try {
            if (type == 2) socket.setSoTimeout(60 * 1000);
        } catch (SocketException e) {
	        log.error("failed to set socket timeout:" + e);
	        return false;
        }
        return true;
    }

    public boolean isAuthenticated() {
		return authenticated;
	}

	public void setAuthenticated(boolean authenticated) {
		this.authenticated = authenticated;
	}

    public boolean isMainConnection() {
        return mainConnection;
    }

	public void setMainConnection(boolean m) {
	    mainConnection = m;
    }

    public String getSocketId() {
	    return Settings.socketAddress(socket);
    }
}

class Sender extends Thread {
    private static final Logger log = LogManager.getLogger();
    private Connection con;
    private String socketId;
    private boolean term;
    private int interval;

    Sender(Connection con, int interval) {
        this.con = con;
        socketId = con.getSocketId();
        term = false;
        this.interval = interval;
        start();
    }

    public void run() {
        log.debug("starting " + (interval == 0 ? "instant" : "verify") + " sender process");
        while (!term) {
            // do not use queue system for client
            if (con.getType() != 1 || !con.isAuthenticated()) continue;
            String key = con.isMainConnection() ? "main_connection" : socketId;
            if (interval == 0) { // this is an instant sender
                term = instantSend(key);
            }
            else { // this is a verify sender
                term = verifySend(key);
            }
        }
        log.debug("sender process terminating");
    }

    private boolean instantSend(String key) {
        JSONObject msgInfo = Control.getInstance().getInstantMessage(key);
        if (msgInfo == null) return false;
        // skip this message if the target party has a different type with this connection
        String type = (String) msgInfo.get("type");
        if (type.equals("ACTIVITY_BROADCAST")) {
            Control.getInstance().addVerifyMsg(key, msgInfo);
        }
        // if writeMsg returns false then the connection is closed
        if (!con.writeMsg(msgInfo.get("message").toString())) return true;
        return false;
    }

    private boolean verifySend(String key) {
        JSONObject msgInfo;
        ArrayList<JSONObject> list = Control.getInstance().getVerifyMsgList(key);
        if (list == null || list.size() == 0) return false;
        log.debug("resending activity messages...");
        for (int i = 0; i < list.size(); i++) {
            msgInfo = list.get(i);
            if (!con.writeMsg(msgInfo.get("message").toString())) return true;
        }
        try {
            Thread.sleep(interval);
        } catch (InterruptedException e) {
            log.info("received an interrupt during sleep");
            return true;
        }
        return false;
    }

    public void setTerm(boolean t) {
        term = t;
    }
}
