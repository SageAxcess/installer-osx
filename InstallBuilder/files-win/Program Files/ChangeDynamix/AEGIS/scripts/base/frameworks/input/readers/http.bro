module InputHttp;

export {
	const listen_port = 8111 &redef;
	const listen_port_ssl = 8112 &redef;

	redef enum Log::ID += { Z_LOG, LOG };

	type HttpInLog: record {
		ts:  time &log;
		url: string &log;
		verb: string &log;
		username: string &log;
	};

	global log_extensions: event(rec: HttpInLog);
}

type HttpInEvent: record {
	url: string;
	verb: string;
	username: string;
};

#TODO: get local ip!
event InputHttp::read_msg_line(desc: Input::EventDescription, tpe: Input::Event, url: string, verb: string, username: string)
	{
		print fmt("[InputHttp] (%s) %s %s", username, verb, url);

		local s: LogZMQ::Info = [
                        $ptype="http-in", $is_proto=T, $ts=network_time(), $uid="000000000000000000",
                        $username="-"
                ];

                s$extra_fields = vector();
                s$extra_vals = vector();

                s$extra_fields[|s$extra_fields|]="verb";
                s$extra_vals[|s$extra_vals|]=verb;
                s$extra_fields[|s$extra_fields|]="url";
                s$extra_vals[|s$extra_vals|]=url;
                s$extra_fields[|s$extra_fields|]="user";
                s$extra_vals[|s$extra_vals|]=username;

		Log::write(InputHttp::Z_LOG, s);
      
		local l: HttpInLog = [
                        $ts=network_time(), 
                        $url=url, 
                        $verb=verb,
                        $username=username
                ];

		Log::write(InputHttp::LOG, l);
	}

event bro_init() &priority=5
	{
		Input::add_event([$source="http",
		                     $reader=Input::READER_HTTP,
		                     $mode=Input::STREAM,
		                     $name="reader-http",
				     $fields=InputHttp::HttpInEvent,
 		                     $want_record=F,
				     $ev=InputHttp::read_msg_line
				]);

		Log::create_stream(InputHttp::Z_LOG, [$columns=LogZMQ::Info, $path="z-tds"]);
	        Log::remove_default_filter(InputHttp::Z_LOG);
		local filter: Log::Filter = [$name="zmq", $writer=Log::WRITER_ZMQ];
		Log::add_filter(InputHttp::Z_LOG, filter);

		Log::create_stream(InputHttp::LOG, [$columns=InputHttp::HttpInLog, $ev=log_extensions, $path="extensions"]);
	}
