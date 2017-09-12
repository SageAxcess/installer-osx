@load policy/frameworks/packet-filter/shunt.bro

module FilterConn;

global ignore_hosts: vector of string = vector();
global ignore_host: addr = 0.0.0.0;
global ignore_port: port = count_to_port(0, tcp);
global shunt_added: bool = T;

#TODO: shunt on new_connection
event new_connection(c: connection) &priority=5
	{
	if(shunt_added == F) 
		{
			if(c$id$orig_p == ignore_port && c$id$orig_h==ignore_host || c$id$resp_p == ignore_port && c$id$resp_h==ignore_host) {
                                print fmt("connection to aggregator detected, adding to filter");
				PacketFilter::shunt_host_pair(c$id);
				shunt_added = T;
			}
		}
	}

event bro_init()
	{
	shunt_added = T;

	local u: URI;
	u = decompose_uri(LogZMQ::zmq_primary_server);

	print fmt(" initialize packet filter, data receiver addr = %s:%d", u$netlocation, u$portnum);

	ignore_port = count_to_port(u$portnum == 0 ? 80 : u$portnum, tcp);
        ignore_host = to_addr(u$netlocation);
        shunt_added = F;

        PacketFilter::exclude("aggregator_dns", fmt("host %s and port 53", u$netlocation));

        if(|ignore_hosts|>0) {
           for(i in ignore_hosts) {
             PacketFilter::exclude(fmt("aggregator_dns_%d", i), fmt("host %s and port 53", ignore_hosts[i]));
           }
        }

#	when ( local host = lookup_addr(to_addr(u$netlocation)) ) 
#		{
#			print fmt("host lookup finished, host=%s", host);
#			ignore_host=to_addr(host);
#			shunt_added = F;
#		}
	}
