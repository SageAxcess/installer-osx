@load base/frameworks/notice
@load base/utils/addrs
@load base/utils/directions-and-hosts

module SMTP;

export {
	redef enum Log::ID += { LOG, Z_LOG };

	type Info: record {
		## Time when the message was first seen.
		ts:                time            &log;
		## Unique ID for the connection.
		uid:               string          &log;
		## The connection's 4-tuple of endpoint addresses/ports.
		id:                conn_id         &log;
		## Contents of the From header.
		from:              string          &log &default="<unknown>";
		## Contents of the To header.
		to:                set[string]     &log &optional;
		## Contents of the Subject header.
		subject:           string          &log &optional;
                ## Size of request, plus attachments
                reqSize:           count           &log &default=0;
		## Indicates that the connection has switched to using TLS.
		tls:               bool            &log &default=F;

		local_user:        string          &log &default="";
		process:        string          &log &default="";
	};

	type State: record {
		helo:                     string    &optional;
		## Count the number of individual messages transmitted during
		## this SMTP session.  Note, this is not the number of
		## recipients, but the number of message bodies transferred.
		messages_transferred:     count     &default=0;
		has_client_activity:      bool      &default=F;

		pending_messages:         set[Info] &optional;
	};

	## Direction to capture the full "Received from" path.
	##    REMOTE_HOSTS - only capture the path until an internal host is found.
	##    LOCAL_HOSTS - only capture the path until the external host is discovered.
	##    ALL_HOSTS - always capture the entire path.
	##    NO_HOSTS - never capture the path.
	const mail_path_capture = ALL_HOSTS &redef;

	## Create an extremely shortened representation of a log line.
	global describe: function(rec: Info): string;

	global log_smtp: event(rec: Info);
}

redef record connection += {
	smtp:       Info  &optional;
	smtp_state: State &optional;
};

const ports = { 25/tcp, 587/tcp };
redef likely_server_ports += { ports };

redef record LogZMQ::Info += {
	smtp: Info &log &optional;
};

function write_log(info: Info)
	{
        Log::write(SMTP::LOG, info);

#	when ( local src_host = lookup_addr(info$id$orig_h) )
#		{
		local s: LogZMQ::Info = [$ptype="smtp", $is_proto=T, $uid=info$uid, $ts=info$ts, $username=info$local_user, $process=info$process];

		s$smtp = info;

		Log::write(SMTP::Z_LOG, s);
#		}
	}

event bro_init() &priority=5
	{
	Log::create_stream(SMTP::LOG, [$columns=Info, $ev=log_smtp, $path="smtp"]);

	Log::create_stream(SMTP::Z_LOG, [$columns=LogZMQ::Info]);
        Log::remove_default_filter(SMTP::Z_LOG);
	local filter: Log::Filter = [$name="smtp", $writer=Log::WRITER_ZMQ];
	Log::add_filter(SMTP::Z_LOG, filter);

	Analyzer::register_for_ports(Analyzer::ANALYZER_SMTP, ports);
	}

function find_address_in_smtp_header(header: string): string
{
	local ips = extract_ip_addresses(header);
	# If there are more than one IP address found, return the second.
	if ( |ips| > 1 )
		return ips[1];
	# Otherwise, return the first.
	else if ( |ips| > 0 )
		return ips[0];
	# Otherwise, there wasn't an IP address found.
	else
		return "";
}

function new_smtp_log(c: connection): Info
	{
	local l: Info;
	l$ts=network_time();
	l$uid=c$uid;
	l$id=c$id;

	return l;
	}

function set_smtp_session(c: connection)
	{
	
        if( !c?$conn ) {
            local x: Conn::Info;
       	    c$conn = x;
        }
	c$conn$service="smtp";

	if ( ! c?$smtp_state )
		c$smtp_state = [];

	if ( ! c?$smtp )
		c$smtp = new_smtp_log(c);

		c$smtp$local_user=c?$local_user ? c$local_user : "";
		c$smtp$process=c?$process ? c$process : "";
	}

function smtp_message(c: connection)
	{
	if ( c$smtp_state$has_client_activity )
		{
		write_log(c$smtp);
		c$smtp = new_smtp_log(c);
		}
	}

event smtp_request(c: connection, is_orig: bool, command: string, arg: string) &priority=5
	{
	set_smtp_session(c);
	local upper_command = to_upper(command);

	if ( upper_command == "RCPT" && /^[tT][oO]:/ in arg )
		{
		c$smtp_state$has_client_activity = T;
		}

	else if ( upper_command == "MAIL" && /^[fF][rR][oO][mM]:/ in arg )
		{
		# Flush last message in case we didn't see the server's acknowledgement.
		smtp_message(c);
		c$smtp_state$has_client_activity = T;
		}
	}

event smtp_reply(c: connection, is_orig: bool, code: count, cmd: string,
                 msg: string, cont_resp: bool) &priority=5
	{
	set_smtp_session(c);
	}

event smtp_reply(c: connection, is_orig: bool, code: count, cmd: string,
                 msg: string, cont_resp: bool) &priority=-5
	{
	if ( cmd == "." )
		{
		# Track the number of messages seen in this session.
		++c$smtp_state$messages_transferred;
		smtp_message(c);
		c$smtp = new_smtp_log(c);
		}
	}

event smtp_data(c: connection, is_orig: bool, data: string) 
	{
		if(c?$smtp)
			c$smtp$reqSize += |data|;
	}

event mime_one_header(c: connection, h: mime_header_rec) &priority=5
	{
	if ( ! c?$smtp ) return;

	if ( h$name == "SUBJECT" )
		c$smtp$subject = h$value;

	else if ( h$name == "FROM" )
		c$smtp$from = h$value;


	}

# This event handler builds the "Received From" path by reading the
# headers in the mail
event mime_one_header(c: connection, h: mime_header_rec) &priority=3
	{
	}

event connection_state_remove(c: connection) &priority=-5
	{
	if ( c?$smtp )
		smtp_message(c);
	}

event smtp_starttls(c: connection) &priority=5
	{
	if ( c?$smtp )
		{
		c$smtp$tls = T;
		c$smtp_state$has_client_activity = T;
		}
	}

