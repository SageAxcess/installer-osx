##! Analysis and logging for MIME entities found in SMTP sessions.

@load base/utils/strings
@load base/utils/files
@load ./main

module SMTP;

export {
	redef record State += {
		## Track the number of MIME encoded files transferred
		## during a session.
		mime_depth: count &default=0;
	};
}

event mime_begin_entity(c: connection) &priority=10
	{
	if ( c?$smtp_state )
		++c$smtp_state$mime_depth;
	}

event file_over_new_connection(f: fa_file, c: connection, is_orig: bool) &priority=5
	{
#	if ( f$source == "SMTP" && c?$smtp )
#		{
#			c$smtp$reqSize += f$total_bytes;
#		}
	}

event mime_one_header(c: connection, h: mime_header_rec) &priority=5
	{
	if ( ! c?$smtp )
		return;

	}
event mime_end_entity(c: connection) &priority=5
	{
	}
