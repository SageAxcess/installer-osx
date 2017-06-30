##! Implements username detection for each new connection 
##! Adds local_user field to connection object

# Author: Mikhail Burilov

@load base/frameworks/packet-filter/utils
# TODO: This is for linux version, use base/bif/zmq.bif.bro for windows!
@load base/bif/zmq.bif.bro

module LocalUser;

export {
	global detect_user: function(c: connection) : string;
}

redef record connection += {
	local_user: string &optional;
	process: string &optional;
};

event new_connection(c: connection) &priority=5
	{
        local v: string_vec;
	v=LogZMQ::__detect_user(c);
        if(|v|==2) {
	        c$process=v[0];
	        c$local_user=v[1];
        }

#	print fmt("New connection: %s, detected user=%s, process=%s", c$id$orig_h, c?$local_user ? c$local_user : "<unknown>", c?$process ? c$process : "<unknown>");

	}
