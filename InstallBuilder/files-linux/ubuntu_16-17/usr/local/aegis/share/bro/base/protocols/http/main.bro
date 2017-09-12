##! Implements base functionality for HTTP analysis.  The logging model is
##! to log request/response pairs and all relevant metadata together in
##! a single record.

@load base/utils/numbers
@load base/utils/files
@load base/frameworks/tunnels

module HTTP;

export {
	redef enum Log::ID += { LOG, Z_LOG };

	## Indicate a type of attack or compromise in the record to be logged.
	type Tags: enum {
		## Placeholder.
		EMPTY
	};

	type Info: record {
		## Timestamp for when the request happened.
		ts:                      time      &log;
		## Unique ID for the connection.
		uid:                     string    &log;
		## The connection's 4-tuple of endpoint addresses/ports.
		id:                      conn_id   &log;
		## Verb used in the HTTP request (GET, POST, HEAD, etc.).
		method:                  string    &log &optional;
		## Value of the HOST header.
		host:                    string    &log &optional;
		## URI used in the request.
		uri:                     string    &log &optional;
                ## Authenticated user (basic auth)
                user:			string	   &log &default="<unknown>";
		## Actual uncompressed content size of the data transferred from
		## the client.
		request_body_len:        count     &log &default=0;
		## Actual uncompressed content size of the data transferred from
		## the server.
		response_body_len:       count     &log &default=0;
		## Status code returned by the server.
		status_code:             count     &log &default=0;
		## Status message returned by the server.
		status_msg:              string    &log &optional;

		## Additional process information
                local_user:		string	   &log &default="<unknown>";
                process:		string	   &log &default="";
	};

	## Structure to maintain state for an HTTP connection with multiple
	## requests and responses.
	type State: record {
		## Pending requests.
		pending:          table[count] of Info;
		## Current request in the pending queue.
		current_request:  count                &default=0;
		## Current response in the pending queue.
		current_response: count                &default=0;
		## Track the current deepest transaction.
		## This is meant to cope with missing requests
		## and responses.
		trans_depth:      count                &default=0;
	};

	## A list of HTTP headers typically used to indicate proxied requests.
	const proxy_headers: set[string] = {
		"FORWARDED",
		"X-FORWARDED-FOR",
		"X-FORWARDED-FROM",
		"CLIENT-IP",
		"VIA",
		"XROXY-CONNECTION",
		"PROXY-CONNECTION",
	} &redef;

	## A list of HTTP methods. Other methods will generate a weird. Note
	## that the HTTP analyzer will only accept methods consisting solely
	## of letters ``[A-Za-z]``.
	const http_methods: set[string] = {
		"GET", "POST", "HEAD", "OPTIONS",
		"PUT", "DELETE", "TRACE", "CONNECT",
		# HTTP methods for distributed authoring:
		"PROPFIND", "PROPPATCH", "MKCOL",
		"COPY", "MOVE", "LOCK", "UNLOCK",
		"POLL", "REPORT", "SUBSCRIBE", "BMOVE",
		"SEARCH"
	} &redef;

	## Event that can be handled to access the HTTP record as it is sent on
	## to the logging framework.
	global log_http: event(rec: Info);
}

# Add the http state tracking fields to the connection record.
redef record connection += {
	http:        Info  &optional;
	http_state:  State &optional;
};

const ports = {
	80/tcp, 81/tcp, 631/tcp, 1080/tcp, 3128/tcp,
	8000/tcp, 8080/tcp, 8888/tcp,
};
redef likely_server_ports += { ports };

redef record LogZMQ::Info += {
	http: Info &log &optional;
};

function write_log(info: Info)
	{
        Log::write(HTTP::LOG, info);

#	when ( local src_host = lookup_addr(info$id$orig_h) )
#		{
		local s: LogZMQ::Info = [$ptype="http", $is_proto=T, $ts=info$ts, $uid=info$uid, $username=info$local_user, $process=info$process];
		
		s$http = info;
		     
		Log::write(HTTP::Z_LOG, s);
#		}
	}

# Initialize the HTTP logging stream and ports.
event bro_init() &priority=5
	{
	Log::create_stream(HTTP::LOG, [$columns=Info, $ev=log_http, $path="http"]);

	Log::create_stream(HTTP::Z_LOG, [$columns=LogZMQ::Info]);
        Log::remove_default_filter(HTTP::Z_LOG);
	local filter: Log::Filter = [$name="zmq", $writer=Log::WRITER_ZMQ];
	Log::add_filter(HTTP::Z_LOG, filter);

	Analyzer::register_for_ports(Analyzer::ANALYZER_HTTP, ports);
	}

function code_in_range(c: count, min: count, max: count) : bool
	{
	return c >= min && c <= max;
	}

function new_http_session(c: connection): Info
	{
        if( !c?$conn ) {
            local x: Conn::Info;
            c$conn = x;
        }
	c$conn$service="http";

	local tmp: Info;
	tmp$ts=network_time();
	tmp$uid=c$uid;
	tmp$id=c$id;
	return tmp;
	}

function set_state(c: connection, is_orig: bool)
	{
	if ( ! c?$http_state )
		{
		local s: State;
		c$http_state = s;
		}

	# These deal with new requests and responses.
	if ( is_orig )
		{
		if ( c$http_state$current_request !in c$http_state$pending )
			c$http_state$pending[c$http_state$current_request] = new_http_session(c);

		c$http = c$http_state$pending[c$http_state$current_request];
		}
	else
		{
		if ( c$http_state$current_response !in c$http_state$pending )
			c$http_state$pending[c$http_state$current_response] = new_http_session(c);

		c$http = c$http_state$pending[c$http_state$current_response];
		}
	}

event http_request(c: connection, method: string, original_URI: string,
                   unescaped_URI: string, version: string) &priority=5
	{
	if ( ! c?$http_state )
		{
		local s: State;
		c$http_state = s;
		}

	++c$http_state$current_request;
	set_state(c, T);

        c$http$local_user = c?$local_user ? c$local_user : "";
        c$http$process = c?$process ? c$process : "";
	c$http$method = method;
	c$http$uri = unescaped_URI;

	if ( method !in http_methods )
		event conn_weird("unknown_HTTP_method", c, method);
	}

event http_reply(c: connection, version: string, code: count, reason: string) &priority=5
	{
	if ( ! c?$http_state )
		{
		local s: State;
		c$http_state = s;
		}

	# If the last response was an informational 1xx, we're still expecting
	# the real response to the request, so don't create a new Info record yet.
	if ( c$http_state$current_response !in c$http_state$pending ||
	     (c$http_state$pending[c$http_state$current_response]?$status_code &&
	       ! code_in_range(c$http_state$pending[c$http_state$current_response]$status_code, 100, 199)) )
		{
		++c$http_state$current_response;
		}
	set_state(c, F);

	c$http$status_code = code;
	c$http$status_msg = reason;

	if ( c$http?$method && c$http$method == "CONNECT" && code == 200 )
		{
		# Copy this conn_id and set the orig_p to zero because in the case of CONNECT
		# proxies there will be potentially many source ports since a new proxy connection
		# is established for each proxied connection.  We treat this as a singular
		# "tunnel".
		local tid = copy(c$id);
		tid$orig_p = 0/tcp;
		Tunnel::register([$cid=tid, $tunnel_type=Tunnel::HTTP]);
		}
	}

event http_header(c: connection, is_orig: bool, name: string, value: string) &priority=5
	{
	set_state(c, is_orig);

	if ( is_orig ) # client headers
		{
		if ( name == "HOST" )
			# The split is done to remove the occasional port value that shows up here.
			c$http$host = split_string1(value, /:/)[0];
		else if ( name == "AUTHORIZATION" || name == "PROXY-AUTHORIZATION" )
			{
			if ( /^[bB][aA][sS][iI][cC] / in value )
				{
				local userpass = decode_base64_conn(c$id, sub(value, /[bB][aA][sS][iI][cC][[:blank:]]/, ""));
				local up = split_string(userpass, /:/);
				if ( |up| >= 2 )
					{
					c$http$user = up[0];
					}
				else
					{
					c$http$user = fmt("<problem-decoding> (%s)", value);
					}
				}
			}
		}
#todo: parse basic authentication here
	}

event http_message_done(c: connection, is_orig: bool, stat: http_message_stat) &priority = 5
	{
	set_state(c, is_orig);

	if ( is_orig )
		c$http$request_body_len = stat$body_length;
	else
		c$http$response_body_len = stat$body_length;
	}

event http_message_done(c: connection, is_orig: bool, stat: http_message_stat) &priority = -5
	{
	# The reply body is done so we're ready to log.
	if ( ! is_orig )
		{
		# If the response was an informational 1xx, we're still expecting
		# the real response later, so we'll continue using the same record.
		if ( ! (c$http?$status_code && code_in_range(c$http$status_code, 100, 199)) )
			{
			write_log(c$http);
			delete c$http_state$pending[c$http_state$current_response];
			}
		}
	}

event connection_state_remove(c: connection) &priority=-5
	{
	# Flush all pending but incomplete request/response pairs.
	if ( c?$http_state )
		{
		for ( r in c$http_state$pending )
			{
			# We don't use pending elements at index 0.
			if ( r == 0 ) next;
			write_log(c$http_state$pending[r]);
			}
		}
	}

