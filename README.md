# duckdb_dissector_poc
Proof of concept for using duckdb for creating fingerprints based on large pcap or flow files

## Proof of Concept goal

It does what [ddos_dissector](https://github.com/ddos-clearing-house/ddos_dissector) from the [DDoS Clearing House](https://github.com/ddos-clearing-house) does: create fingerprints from a packet capture (pcap/flow) of a DDoS attack.

The point is to investigate whether converting a pcap file to parquet format first, then using [duckdb](https://duckdb.org/) to do the heavy analytical lifting is useful (faster, bigger, etc) compared to the original approach of loading the entire capture in a dataframe in memory for analysis.

It tries to be faithful to the original in its calculations, but because of the difference in approach this may not always entirely be the case. The goal is to be a good approximation of the analysis done by the original ddos_dissector, in order to be able to compare the two approaches.

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
   - determine attack vectors etc.
   - load results in dataframe in memory
4. write fingerprint

### More detailed
Extensive use is made of 'views', a way of putting a filter on a database, table or other view; usually intended to create a subset of the parent view. 

The key here is that creating a view **does not load anything in memory** (like a table would). It is filled with data on the fly whenever an SQL statement operates on a view.

For example: the first use of a view is to create a, well, view on the parquet file(s) to be analysed:
```
CREATE VIEW raw AS SELECT * FROM read_parquet({pqt_files})
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

Pcaps around 10 to 20 MB size are fairly comparable in speed, taking only seconds to process. 
This is not surprising, as conversion needs to happen in both cases and the conversions are the biggest time consumers.
Even so, the time spent on analysis is an order of magnitude smaller: duckdb is about 2 to 5 times faster than Panda dataframes when it comes to the actual analysis (even though the net effect is only a few hundred milliseconds to a few seconds for small files). 

For bigger files the differences get more dramatic. The samples below were run on a machine with 16GB of memory, a 2TB nvme drive, and an AMD Ryzen 5 2600 Six-Core Processor.

* A [300MB file](http://traces.simpleweb.org/booter-attacks-im2015/anon-Booter5.pcap.gz) processed by ddos_dissector in nearly two minutes, can be processed by this approach in under half a minute (24 seconds: 23 for conversion, 1 for analysis).

* A [7GB file](http://traces.simpleweb.org/booter-attacks-im2015/anon-Booter8.pcap.gz) processed by ddos_dissector in 15 minutes, can be processed by this approach in over a minute (74 seconds: 72 for conversion, 2 for analysis).

* A [16GB file](http://traces.simpleweb.org/booter-attacks-im2015/anon-Booter9.pcap.gz) can be loaded by ddos_dissector, but the process crashes (is killed by the system) after the first one or two calculations (after six minutes). The duckdb approach processes the file in just under three minutes (2 minutes 50 seconds. Again that is mostly the conversion process to parquet, analysis just takes 5 seconds.

* A [50GB file](http://traces.simpleweb.org/booter-attacks-im2015/anon-Booter4.pcap.gz) is processed in 30 minutes. Yet again mostly conversion, the actual analysis only takes 20 seconds of those 30 minutes.


## How to use the Dissector

This dissector can be used in the same way as the original, so [refer to those instructions](https://github.com/ddos-clearing-house/ddos_dissector#how-to-use-the-dissector).

You can build a local docker image named ddosclearinghouse/dissector (as used in the ['Option 1: in Docker'](https://github.com/ddos-clearing-house/ddos_dissector#option-1-in-docker)) by issuing the following command in the base directory:
```commandline
docker build . -t ddosclearinghouse/dissector
```
