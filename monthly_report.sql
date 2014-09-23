\echo OSSEC Blocks by month
select month, count(1) from (select date_trunc('month', block_when) as month from blocklog where block_who='secops') as foo group by
                month order by month asc;

\echo Bro Blocks by month and notice type
select month, reason, count(1) from (select date_trunc('month', block_when) as month, (string_to_array(block_why, ' '))[1] as reason
                from blocklog where block_who='bro') as foo group by month, reason order by month,reason;

