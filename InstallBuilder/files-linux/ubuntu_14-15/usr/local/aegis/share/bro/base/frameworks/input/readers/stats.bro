type system_stats: record {
	cpu_usage:	double &log;
	priority:	int &log;
	ph_mem_total:	count &log;
	ph_mem_used:	count &log;
	virt_mem_total:	count &log;
	virt_mem_used:	count &log;
	hdd_volume:	double &log;
	hdd_used:	double &log;
	hdd_avail:	double &log;
	os_version:	string &log;
	aegis_version:	string &log;
	pcap_version:	string &log;
	current_user:	string &log;
};

@load base/bif/zmq.bif.bro

module InputStats;

export {
	redef enum Log::ID += { Z_LOG };
}

event do_send_stats()
	{
	print "reading statistics...";
	local s: system_stats;
	s = LogZMQ::__get_system_stats();

	print "sending statistics...";
	Log::write(InputStats::Z_LOG, s);

	schedule 30sec { do_send_stats() };
	}

event bro_init() &priority=5
	{
	schedule 10sec { do_send_stats() };

	Log::create_stream(InputStats::Z_LOG, [$columns=system_stats, $path="z-stats"]);
        Log::remove_default_filter(InputStats::Z_LOG);
	local filter: Log::Filter = [$name="zmq", $writer=Log::WRITER_ZMQ];
	Log::add_filter(InputStats::Z_LOG, filter);
	}
