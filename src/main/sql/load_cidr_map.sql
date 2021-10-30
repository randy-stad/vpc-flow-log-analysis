truncate cidr_map;
copy cidr_map(cidr_range, port, inbound, outbound, netname, organization, inbound_ip, outbound_ip) 
from 'output.csv' 
delimiter ',' 
csv header;