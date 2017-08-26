@load ./consts

module DceRpc;

export {
	redef enum Log::ID += { LOG, Z_LOG };

	type Info: record {
		## Timestamp for when the event happened.
		ts:     time    &log;
		## Unique ID for the connection.
		uid:    string  &log;
		## The connection's 4-tuple of endpoint addresses/ports.
		id:     conn_id &log;
                 
		context_uuid: string &default="";

		request_type:	string &log &default="";
		interface_uuid:	string &log &default="";
		interface_name:	string &log &default="";
		opnum:		count &log &default=0;
		method:		string &log &default="";
		arguments:	string &log &default="";
		raw_args:	string &log &default="";

		local_user:	string &log &default="";
		process:	string &log &default="";
	};

	global log_dcerpc: event(rec: Info);
}

const ports = { 9072/tcp, 135/tcp, 49154/tcp };

redef record connection += {
	dce: DceRpc::Info &optional;
};

redef record LogZMQ::Info += {
	dce: Info &log &optional;
};

function write_log(info: Info)
	{
        Log::write(DceRpc::LOG, info);

#	when ( local src_host = lookup_addr(info$id$orig_h) )
#		{
		local s: LogZMQ::Info = [$ptype="dce-rpc", $is_proto=T, $ts=info$ts, $uid=info$uid, $username=info$local_user, $process=info$process];

		s$dce = info;

		Log::write(DceRpc::Z_LOG, s);
#		}
	}

event bro_init() &priority=5
	{
	Log::create_stream(DceRpc::LOG, [$columns=Info, $ev=log_dcerpc, $path="dce-rpc"]);

	Log::create_stream(DceRpc::Z_LOG, [$columns=LogZMQ::Info, $path="z-dce-rpc"]);
        Log::remove_default_filter(DceRpc::Z_LOG);
	local filter: Log::Filter = [$name="zmq", $writer=Log::WRITER_ZMQ];
	Log::add_filter(DceRpc::Z_LOG, filter);

	Analyzer::register_for_ports(Analyzer::ANALYZER_DCE_RPC, ports);
	}

event dce_rpc_message(c: connection, is_orig: bool, ptype: dce_rpc_ptype, msg: string)
	{
	}

event dce_rpc_bind(c: connection, uuid: string)
	{
		if ( ! c?$dce )
		{
		        if( !c?$conn ) {
		            local x: Conn::Info;
	        	    c$conn = x;
		        }
			c$conn$service="dce-rpc";

			local s: Info;
			c$dce = s;

			c$dce$local_user=c?$local_user ? c$local_user : "";
			c$dce$process=c?$process ? c$process : "";
		}

		c$dce$ts  = network_time();
		c$dce$uid = c$uid;
		c$dce$id  = c$id;

		c$dce$request_type = "bind";
		c$dce$interface_uuid = uuid;
		c$dce$interface_name = interfaces[uuid];
		c$dce$opnum = 0;
		c$dce$method = "";
		c$dce$raw_args = "";
		c$dce$arguments = "";

		c$dce$context_uuid = uuid;

		write_log(c$dce);
	}

event dce_rpc_alter_context(c: connection, uuid: string)
	{
		if ( ! c?$dce )
		{
		        if( !c?$conn ) {
		            local x: Conn::Info;
	        	    c$conn = x;
		        }
			c$conn$service="dce-rpc";

			local s: Info;
			c$dce = s;

			c$dce$local_user=c?$local_user ? c$local_user : "";
			c$dce$process=c?$process ? c$process : "";
		}

		c$dce$ts  = network_time();
		c$dce$uid = c$uid;
		c$dce$id  = c$id;
		c$dce$request_type = "alter_context";
		c$dce$interface_uuid = uuid;
		c$dce$interface_name = interfaces[uuid];
		c$dce$opnum = 0;
		c$dce$method = "";
		c$dce$raw_args = "";
		c$dce$arguments = "";
                c$dce$context_uuid = uuid;

		write_log(c$dce);
	}

event dce_rpc_request(c: connection, opnum: count, arguments: string, stub: string)
	{
		if ( ! c?$dce )
		{
		        if( !c?$conn ) {
		            local x: Conn::Info;
	        	    c$conn = x;
		        }
			c$conn$service="dce-rpc";

			local s: Info;
			c$dce = s;

			c$dce$local_user=c?$local_user ? c$local_user : "";
			c$dce$process=c?$process ? c$process : "";
		}

		if(|c$dce$context_uuid|>0)
		{
			c$dce$ts  = network_time();
			c$dce$uid = c$uid;
			c$dce$id  = c$id;
			c$dce$request_type = "request";
			c$dce$interface_uuid = c$dce$context_uuid;
			c$dce$interface_name = interfaces[c$dce$context_uuid];
			c$dce$opnum = opnum;
			c$dce$method = methods[fmt("%s_%d", c$dce$context_uuid, opnum)];
			c$dce$arguments = arguments;
			c$dce$raw_args = |stub| > 0 ? string_to_ascii_hex(stub) : "";

			write_log(c$dce);
		} else 
		{
			event conn_weird("dce-rpc_request_no_uuid_set", c, "");
		}
	}

event dce_rpc_response(c: connection, opnum: count, stub: string)
	{
		if ( ! c?$dce )
		{
		        if( !c?$conn ) {
		            local x: Conn::Info;
	        	    c$conn = x;
		        }
			c$conn$service="dce-rpc";

			local s: Info;
			c$dce = s;

			c$dce$local_user=c?$local_user ? c$local_user : "";
			c$dce$process=c?$process ? c$process : "";
		}

		c$dce$ts  = network_time();
		c$dce$uid = c$uid;
		c$dce$id  = c$id;
		c$dce$request_type = "response";
		c$dce$raw_args = string_to_ascii_hex(stub);
		c$dce$arguments = "";

#		write_log(c$dce);
	}

event epm_map_response(c: connection, uuid: string, p: port, h: addr)
	{
#todo debug log
	Analyzer::register_for_port(Analyzer::ANALYZER_DCE_RPC, p);
	}


