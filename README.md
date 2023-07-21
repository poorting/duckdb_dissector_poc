# duckdb_dissector_poc
Proof of concept for using duckdb for creating large file fingerprints

# Proof of Concept - do not use!

It (very very very) roughly does what [ddos_dissector](https://github.com/ddos-clearing-house/ddos_dissector) from the [DDoS Clearing House](https://github.com/ddos-clearing-house) does: create fingerprints from a packet capture of a DDoS attack.

The point is to investigate whether converting a pcap file to parquet format first, then using [duckdb](https://duckdb.org/) to do the heavy analytical lifting is useful (faster, bigger, etc).

It tries to be faithful in its calculations, but in a crudely/ugly coded way. The goal is to be a good approximation of the analysis done by the original ddos_dissector in order to be able to compare the two approaches.

## Approach

Roughly the difference in approach is this:

Steps in ddos_dissector:
1. convert pcap to csv
2. load in a panda dataframe in memory
3. do analysis 
   - determine attack vectors etc.
4. write fingerprint

Steps in duckdb_dissector:
1. convert pcap to csv
2. convert csv to parquet
3. use duckdb to analyse parquet file 
   - load results in dataframe in memory
   - determine attack vectors etc.
4. write fingerprint

### More detailed
Extensive use is made of 'views', a way of putting a filter on a database, table or other view; usually intended to create a subset of the parent view. 

The key here is that creating a view **does not load anything in memory** (like a table would). It is filled with data on the fly whenever an SQL statement operates on a view.

For example: the first use of a view is to create a, well, view on the parquet file to be analysed:
```
CREATE VIEW raw AS SELECT * FROM '{parquet_file}'
```

Another view is then created to combine fields into one (e.g. coalescing udp_srcport and tcp_srcport) and other stuff.
```
create view pcap as select * exclude (col_protocol, tcp_srcport, tcp_dstport, udp_srcport, udp_dstport, ip_src, ip_dst, col_source, col_destination, frame_time, ip_frag_offset, ntp_priv_reqcode, ip_ttl, frame_len), 
coalesce(ip_src, col_source) as source_address, 
coalesce(ip_dst, col_destination) as destination_address, 
coalesce(tcp_srcport, udp_srcport, 0) as source_port, 
coalesce(tcp_dstport, udp_dstport, 0) as destination_port, 
coalesce(ip_frag_offset, 0) as fragmentation_offset, 
coalesce(ntp_priv_reqcode, 0) as ntp_requestcode, 
coalesce(ip_ttl, 0) as ttl, 
col_protocol as service, 
frame_time as time_start, frame_time as time_end, 
frame_len as nr_bytes, 1 as nr_packets, from raw
```

At this point, nothing is loaded into memory yet.
This only happens at the point where the first call is made to determine the attack target(s), which translates to this query:
```
df = db.execute("select destination_address, sum(nr_packets)/(select sum(nr_packets) from pcap) as frac "
           "from pcap group by all order by frac desc").fetchdf()
```
This query determines the fraction of total traffic (in number of packets) received by each distinct destination (IP) address present in the pcap, in descending order (biggest receiver first).

The `.fetchdf()` appended to the execute statement loads the results of the query directly into a dataframe, which can then be used for further processing.

Note that only loading the distinct set of destination addresses and the number of packets they received into memory, rather than descriptions of all packets (i.e. the entire file), is already a much smaller number by many orders of magnitude.

This approach is used throughout:
Create new views based on queries on previous views, then query those and only load results for further processing and tweaking.

As opposed to loading the entire pcap into a dataframe in memory and working with that, this approach enables working with much bigger packet captures much faster.

## Bigger, faster

Pcaps around 10 to 20 MB size are fairly comparable in speed (after all: conversion needs to happen in both cases and these sizes are easily loaded in memory). Still: processing by duckdb is faster than Panda dataframes for the types of operations performed (2 to 4 times as fast on average).

For bigger files the differences get more dramatic:

* A 300MB file, processed by ddos_dissector in nearly two minutes, can be processed by this approach in under half a minute (24 seconds: 23 for conversion, 1 for analysis).

* A 16GB file can be loaded by ddos_dissector on a machine with 16GB of memory, but crashes after the first one or two calculations (after six minutes). This approach processes the file in just under three minutes (2 minutes 50 seconds, although that is mostly the conversion process to parquet: analysis just takes 5 seconds).

* A 50GB file is processed in 30 minutes. Again mostly conversion, the actual analysis takes 20 seconds of those 30 minutes.




