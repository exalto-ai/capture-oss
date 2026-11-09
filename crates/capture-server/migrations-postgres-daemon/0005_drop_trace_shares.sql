-- No capture service shares Traces, so nothing reads or writes share records.
-- Dropping the table also drops its keys, checks and foreign key; no other
-- table references it.
DROP TABLE captured.trace_shares;
