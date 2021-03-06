create table cidr_map (
    id serial primary key,
    cidr_range text[],
    port int,
    protocol text,
    inbound boolean,
    outbound boolean,
    netname text,
    organization text,
    inbound_ip text[],
    outbound_ip text[]
);
