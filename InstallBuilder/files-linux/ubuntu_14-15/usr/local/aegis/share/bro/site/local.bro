##! Local site policy. Customize as appropriate.
##!
##! This file will not be overwritten when upgrading or reinstalling!

# This script logs which scripts were loaded during each run.
@load misc/loaded-scripts

# Apply the default tuning scripts for common tuning settings.
@load tuning/defaults

# Load the scan detection script.
@load misc/scan

# Scripts that do asset tracking.
@load protocols/conn/known-hosts
@load protocols/conn/known-services

# disable smb builtin
#@load policy/protocols/smb/smb_default

@load policy/protocols/smb/smb_v1
@load policy/protocols/tds/tds
@load policy/protocols/ldap/ldap

@load policy/misc/filter-conn