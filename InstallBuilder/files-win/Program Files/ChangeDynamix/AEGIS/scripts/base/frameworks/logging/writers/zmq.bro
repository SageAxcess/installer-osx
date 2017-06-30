##! Interface for the ZMQ log writer. Redefinable options are available

module LogZMQ;

export {
	## Path to server
	const zmq_primary_server = "tcp://54.210.224.248:5555" &redef;
	const zmq_secondary_server = "" &redef;
	const zmq_public_key = "5A5832576F434D2D57367D667148464865326E3C4B74586B733C574C7A624E6355642D5239282E72" &redef;
	const zmq_agent_id = "" &redef;

	## Separator between set elements.
	const set_separator = Log::set_separator &redef;

	## String to use for an unset &optional field.
	const unset_field = Log::unset_field &redef;

	## String to use for empty fields. This should be different from
	## *unset_field* to make the output unambiguous.
	const empty_field = Log::empty_field &redef;

	# Record structure for ZMQ logger
	type Info: record {
#                version:        string &log &default="v1.0";
		## Timestamp (timezone is added automatically)
		ts:		time   &log;
		## Unique ID for the connection.
		uid:    string  &log;
		## Protocol name
                ptype:	string &log;
		## Detected local user name
                username:	string &log &default="<unknown>";
		## Detected local user name
                process:	string &log &default="<unknown>";
		## This is protocol (True) or connection (F) details
		is_proto:	bool            &log &default=T;

		## Connection-specific details
		## See protocols/conn/main.bro for definitions
		id:           conn_id         &log &optional;
		proto:        transport_proto &log &optional;
		service:      string          &log &optional;
		duration:     interval        &log &optional;
		orig_bytes:   count           &log &default=0;
		resp_bytes:   count           &log &default=0;
		conn_state:   string          &log &optional;
		local_orig:   bool            &log &default=F;
		local_resp:   bool            &log &default=F;
		missed_bytes: count           &log &default=0;
		orig_pkts:     count      &log &default=0;
		orig_ip_bytes: count      &log &default=0;
		resp_pkts:     count      &log &default=0;
		resp_ip_bytes: count      &log &default=0;

		## Protocol-specific details
		extra_fields:	vector of string &log &default=vector();
		extra_vals:	vector of string &log &default=vector();
	};
}

event settings_updated()
	{
	}
