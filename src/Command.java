
public enum Command {

	GET("takes a group as an argument and retrieves all messages posted to that group, and a timestamp of when the"
			+ " message was posted (UTC), and by which user"), 
	POST("takes a group and a message as an argument, posts a message to some group under the username; if the group"
			+ " doesn't exist, creates it"), 
	END("ends the session with the server, doesn't exit the client and should allow the user to log back in"), 
	
	AUTH("with username and password"),
	
	EXIT("exits the user");
	
	private String DESCRIPTION;
	
	private Command(String DESCRIPTION) {
		this.DESCRIPTION = DESCRIPTION;
	}

	public String getDESCRIPTION() {
		return DESCRIPTION;
	}
}
