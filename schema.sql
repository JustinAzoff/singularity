create table blocklog (
    block_id bigserial primary key,
    block_when timestamp not null,
    block_ipaddress inet not null,
    block_reverse VARCHAR(256),
    block_who VARCHAR(32) not null,
    block_why VARCHAR(256) not null,
    block_notified boolean DEFAULT false
);

create index idx_blocklog_ipaddress on blocklog(block_ipaddress);
create index idx_blocklog_notified on blocklog(block_notified);

create table unblocklog (
    unblock_id bigint primary key references blocklog(block_id),
    unblock_when timestamp not null,
    unblock_who VARCHAR(32) not null,
    unblock_why VARCHAR(256) not null,
    unblock_notified boolean DEFAULT false
);
create index idx_unblocklog_notified on unblocklog(unblock_notified);


create table blocklist (
    blocklist_id bigint primary key references blocklog(block_id),
    blocklist_until timestamp not null
);

ALTER TABLE public.blocklist OWNER TO blackhole;
ALTER TABLE public.blocklog OWNER TO blackhole;
ALTER TABLE public.blocklog_block_id_seq OWNER TO blackhole;
ALTER TABLE public.unblocklog OWNER TO blackhole;
