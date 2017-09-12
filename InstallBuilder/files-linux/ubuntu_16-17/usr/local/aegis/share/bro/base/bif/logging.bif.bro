# This file was automatically generated by bifcl from logging.bif (alternative mode).

##! Internal functions and types used by the logging framework.

export {
module Log;








global Log::__create_stream: function(id: Log::ID , stream: Log::Stream ) : bool ;


global Log::__remove_stream: function(id: Log::ID ) : bool ;


global Log::__enable_stream: function(id: Log::ID ) : bool ;


global Log::__disable_stream: function(id: Log::ID ) : bool ;


global Log::__add_filter: function(id: Log::ID , filter: Log::Filter ) : bool ;


global Log::__remove_filter: function(id: Log::ID , name: string ) : bool ;


global Log::__write: function(id: Log::ID , columns: any ) : bool ;


global Log::__set_buf: function(id: Log::ID , buffered: bool ): bool ;


global Log::__flush: function(id: Log::ID ): bool ;

} # end of export section
module GLOBAL;
