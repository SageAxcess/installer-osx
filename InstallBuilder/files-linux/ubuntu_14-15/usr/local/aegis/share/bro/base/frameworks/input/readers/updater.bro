@load base/bif/plugins/SageAxcess_Updater.events.bif.bro

module Updater;

export {
	const enabled = F &redef;
	const remote_control = T &redef;
	const check_interval = 60 &redef;
	const url = "http://build.sageaxcess.com/" &redef;

	type UpdaterEvent: record {
		name: string;
		old_version: string;
		new_version: string;
	};
}

event Updater::read_msg_line(desc: Input::EventDescription, tpe: Input::Event, name:string, old_ver: string, new_ver:string)
	{
	}

event bro_init() &priority=5
	{
		Input::add_event([$source="updater",
		                     $reader=Input::READER_UPDATER,
		                     $mode=Input::STREAM,
		                     $name="reader-updater",
				     $fields=Updater::UpdaterEvent,
 		                     $want_record=F,
				     $ev=Updater::read_msg_line                                     
				]);
	}

event remote_command(command: string) &priority=5
	{
		Reporter::info(fmt("Received command from remote: %s", command));
		if(command=="reload_settings")
		{
			save_settings();
		}
	}

event remote_update_setting(name: string, value: string) &priority=5
	{
		Reporter::info(fmt("remote plugin update setting %s=%s", name, value));
		update_setting(name, value);
	}
