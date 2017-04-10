signature dpd_smb1_tcp {
	ip-proto == tcp	
        payload /^ ?(\xFF)SMB /
	enable "smb1"
}

signature dpd_smb1_udp {
	ip-proto == udp
        payload /^ ?(\xFF)SMB /
	enable "smb1"
}

signature dpd_smb2_tcp {
	ip-proto == tcp	
        payload /^ ?(\xFE)SMB /
	enable "smb1"
}

signature dpd_smb2_udp {
	ip-proto == udp	
        payload /^ ?(\xFE)SMB /
	enable "smb1"
}
