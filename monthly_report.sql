\echo OSSEC Blocks by month
select month, count(distinct(ip)) as unique, count(1) as total from (select date_trunc('month', block_when) as month, block_ipaddress as ip from blocklog where block_who='secops') as foo group by
                month order by month asc;

\echo Bro Blocks by month and notice type
select month, reason, count(distinct(ip)) as unique, count(1) as total from (select date_trunc('month', block_when) as month, (string_to_array(block_why, ' '))[1] as reason, block_ipaddress as ip
                from blocklog where block_who='bro') as foo group by month, reason order by month,reason;

