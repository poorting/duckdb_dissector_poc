#! /usr/bin/env python3

import os
import io
import sys
import hashlib
import shutil
import socket
import logging
import argparse
import textwrap
import tempfile
from pathlib import Path
import subprocess
import multiprocessing
import json
import random
import string
import uuid
from typing import Union, Any
import duckdb
from duckdb import DuckDBPyConnection
import pandas as pd
import pprint
import time
import pytz
from datetime import datetime
import pyarrow as pa
import pyarrow.parquet as pq
import pyarrow.csv
import datetime


program_name = os.path.basename(__file__)
VERSION = 0.1
logger = logging.getLogger(__name__)

IPPROTO_TABLE: dict[int, str] = {
    num: name[8:]
    for name, num in vars(socket).items()
    if name.startswith('IPPROTO')
}

AMPLIFICATION_SERVICES: dict[int, str] = {  # UDP port -> service name
    17: 'Quote of the Day',
    19: 'Chargen',
    53: 'DNS',
    69: 'TFTP',
    111: 'TPC',
    123: 'NTP',
    137: 'NetBios',
    161: 'SNMP',
    177: 'XDMCP',
    389: 'LDAP',
    500: 'ISAKMP',
    520: 'RIPv1',
    623: 'IPMI',
    1434: 'MS SQL',
    1900: 'SSDP',
    3283: 'Apple Remote Desktop',
    3389: 'Windows Remote Desktop',
    3702: 'WS-Discovery',
    5093: 'Sentinel',
    5351: 'NAT-PMP',
    5353: 'mDNS',
    5683: 'CoAP',
    10074: 'Mitel MiColab',  # CVE-2022-26143
    11211: 'MEMCACHED',
    27015: 'Steam',
    32414: 'Plex Media',
    33848: 'Jenkins',
    37810: 'DHDiscover'
}

ETHERNET_TYPES: dict[int, str] = {
    0x0800: 'IPv4',
    0x0806: 'ARP',
    0x0842: 'Wake-on-LAN',
    0x22F0: 'Audio Video Transport Protocol (AVTP)',
    0x22F3: 'IETF TRILL Protocol',
    0x22EA: 'Stream Reservation Protocol',
    0x6002: 'DEC MOP RC',
    0x6003: 'DECnet Phase IV, DNA Routing',
    0x6004: 'DEC LAT',
    0x8035: 'Reverse Address Resolution Protocol (RARP)',
    0x809B: 'AppleTalk (Ethertalk)',
    0x80F3: 'AppleTalk Address Resolution Protocol (AARP)',
    0x8100: 'VLAN-tagged frame (IEEE 802.1Q) and Shortest Path Bridging IEEE 802.1aq with NNI compatibility',
    0x8102: 'Simple Loop Prevention Protocol (SLPP)',
    0x8103: 'Virtual Link Aggregation Control Protocol (VLACP)',
    0x8137: 'IPX',
    0x8204: 'QNX Qnet',
    0x86DD: 'IPv6',
    0x8808: 'Ethernet flow control',
    0x8809: 'Ethernet Slow Protocols[11] such as the Link Aggregation Control Protocol (LACP)',
    0x8819: 'CobraNet',
    0x8847: 'MPLS unicast',
    0x8848: 'MPLS multicast',
    0x8863: 'PPPoE Discovery Stage',
    0x8864: 'PPPoE Session Stage',
    0x887B: 'HomePlug 1.0 MME',
    0x888E: 'EAP over LAN (IEEE 802.1X)',
    0x8892: 'PROFINET Protocol',
    0x889A: 'HyperSCSI (SCSI over Ethernet)',
    0x88A2: 'ATA over Ethernet',
    0x88A4: 'EtherCAT Protocol',
    0x88A8: 'Service VLAN tag identifier (S-Tag) on Q-in-Q tunnel.',
    0x88AB: 'Ethernet Powerlink[citation needed]',
    0x88B8: 'GOOSE (Generic Object Oriented Substation event)',
    0x88B9: 'GSE (Generic Substation Events) Management Services',
    0x88BA: 'SV (Sampled Value Transmission)',
    0x88BF: 'MikroTik RoMON (unofficial)',
    0x88CC: 'Link Layer Discovery Protocol (LLDP)',
    0x88CD: 'SERCOS III',
    0x88E1: 'HomePlug Green PHY',
    0x88E3: 'Media Redundancy Protocol (IEC62439-2)',
    0x88E5: 'IEEE 802.1AE MAC security (MACsec)',
    0x88E7: 'Provider Backbone Bridges (PBB) (IEEE 802.1ah)',
    0x88F7: 'Precision Time Protocol (PTP) over IEEE 802.3 Ethernet',
    0x88F8: 'NC-SI',
    0x88FB: 'Parallel Redundancy Protocol (PRP)',
    0x8902: 'IEEE 802.1ag Connectivity Fault Management (CFM) Protocol / ITU-T Recommendation Y.1731 (OAM)',
    0x8906: 'Fibre Channel over Ethernet (FCoE)',
    0x8914: 'FCoE Initialization Protocol',
    0x8915: 'RDMA over Converged Ethernet (RoCE)',
    0x891D: 'TTEthernet Protocol Control Frame (TTE)',
    0x893a: '1905.1 IEEE Protocol',
    0x892F: 'High-availability Seamless Redundancy (HSR)',
    0x9000: 'Ethernet Configuration Testing Protocol',
    0xF1C1: 'Redundancy Tag (IEEE 802.1CB Frame Replication and Elimination for Reliability)'
}

ICMP_TYPES: dict[int, str] = {
    0: 'Echo Reply',
    3: 'Destination Unreachable',
    5: 'Redirect',
    8: 'Echo',
    9: 'Router Advertisement',
    10: 'Router Solicitation',
    11: 'Time Exceeded',
    12: 'Parameter Problem',
    13: 'Timestamp',
    14: 'Timestamp Reply',
    40: 'Photuris',
    42: 'Extended Echo Request',
    43: 'Extended Echo Reply',
}

DNS_QUERY_TYPES: dict[int, str] = {
    1: 'A',
    28: 'AAAA',
    18: 'AFSDB',
    255: 'ANY',
    42: 'APL',
    257: 'CAA',
    60: 'CDNSKEY',
    59: 'CDS',
    37: 'CERT',
    5: 'CNAME',
    62: 'CSYNC',
    49: 'DHCID',
    32769: 'DLV',
    39: 'DNAME',
    48: 'DNSKEY',
    43: 'DS',
    108: 'EUI48',
    109: 'EUI64',
    13: 'HINFO',
    55: 'HIP',
    65: 'HTTPS',
    45: 'IPSECKEY',
    25: 'KEY',
    36: 'KX',
    29: 'LOC',
    15: 'MX',
    35: 'NAPTR',
    2: 'NS',
    47: 'NSEC',
    50: 'NSEC3',
    51: 'NSEC3PARAM',
    61: 'OPENPGPKEY',
    12: 'PTR',
    46: 'RRSIG',
    17: 'RP',
    24: 'SIG',
    53: 'SMIMEA',
    6: 'SOA',
    33: 'SRV',
    44: 'SSHFP',
    64: 'SVCB',
    32768: 'TA',
    249: 'TKEY',
    52: 'TLSA',
    250: 'TSIG',
    16: 'TXT',
    256: 'URI',
    63: 'ZONEMD'
}


###############################################################################
# taken from https://stackoverflow.com/questions/69156181/pyarrow-find-bad-lines-in-csv-to-parquet-conversion
# Since some pcap->csv may have UTF-8 errors
class UnicodeErrorIgnorerIO(io.IOBase):
    """Simple wrapper for a BytesIO that removes non-UTF8 input.

    If a file contains non-UTF8 input, it causes problems in pyarrow and other libraries
    that try to decode the input to unicode strings. This just removes the offending bytes.

    >>> io = io.BytesIO(b"INT\xbfL LICENSING INDUSTRY MERCH ASSOC")
    >>> io = UnicodeErrorIgnorerIO(io)
    >>> io.read()
    'INTL LICENSING INDUSTRY MERCH ASSOC'
    """

    def __init__(self, file: io.BytesIO) -> None:
        self.file = file

    def read(self, n=-1):
        return self.file.read(n).decode("utf-8", "ignore").encode("utf-8")

    def readline(self, n=-1):
        return self.file.readline(n).decode("utf-8", "ignore").encode("utf-8")

    def readable(self):
        return True


###############################################################################

class Pcap2Parquet:
    PCAP_COLUMN_NAMES: dict[str, dict] = {
        '_ws.col.Time': {'frame_time': pa.timestamp('us')},
        'ip.src': {'ip_src': pa.string()},
        'ip.dst': {'ip_dst': pa.string()},
        'ip.proto': {'ip_proto': pa.uint8()},
        'tcp.flags.str': {'tcp_flags': pa.string()},
        '_ws.col.Source': {'col_source': pa.string()},
        '_ws.col.Destination': {'col_destination': pa.string()},
        '_ws.col.Protocol': {'col_protocol': pa.string()},
        'dns.qry.name': {'dns_qry_name': pa.string()},
        'dns.qry.type': {'dns_qry_type': pa.string()},
        'eth.type': {'eth_type': pa.uint16()},
        'frame.len': {'frame_len': pa.uint16()},
        'udp.length': {'udp_length': pa.uint16()},
        'http.request.uri': {'http_request_uri': pa.string()},
        'http.host': {'http_host': pa.string()},
        'http.request.method': {'http_request_method': pa.string()},
        'http.user_agent': {'http_user_agent': pa.string()},
        'http.file_data': {'http_file_data': pa.string()},
        'icmp.type': {'icmp_type': pa.uint8()},
        'ip.frag_offset': {'ip_frag_offset': pa.uint16()},
        'ip.ttl': {'ip_ttl': pa.uint8()},
        'ntp.priv.reqcode': {'ntp_priv_reqcode': pa.string()},
        'tcp.dstport': {'tcp_dstport': pa.uint16()},
        'tcp.srcport': {'tcp_srcport': pa.uint16()},
        'udp.dstport': {'udp_dstport': pa.uint16()},
        'udp.srcport': {'udp_srcport': pa.uint16()},
        '_ws.col.Info': {'col_info': pa.string()},
    }

    # Max size of chunk to read at a time
    block_size = 512 * 1024 * 1024

    # Max size of pcap to read in one go (in MB)
    max_pcap_chunk = 50

    chunks = None
    chunks_csv = None

    # ------------------------------------------------------------------------------
    def __init__(self, source_file: str, destination_dir: str, log_parse_errors=False, nr_procs=2):
        """Initialises Nfdump2Parquet instance.

        Provide nfdump_fields parameter **only** if defaults don't work
        Defaults for parquet_fields: ts, te, td, sa, da, sp, dp, pr, flg, ipkt, ibyt, opkt, obyt

        :param source_file: name of the nfcapd file to convert
        :param destination_dir: directory for storing resulting parquet file
        :param parquet_fields: the fields from ncapd file to translate to parquet
        :param nfdump_fields: the fields (and order) in the nfcapd file
        """
        if not os.path.isfile(source_file):
            raise FileNotFoundError(source_file)
        self.src_file = source_file
        self.basename = os.path.basename(source_file)
        self.dst_dir = destination_dir
        if not self.dst_dir.endswith('/'):
            self.dst_dir = f"{self.dst_dir}/"
        self.parse_errors = 0
        self.log_parse_errors = log_parse_errors
        self.nr_procs = int(nr_procs)

        letters = string.ascii_lowercase
        self.random = ''.join(random.choice(letters) for i in range(10))

        # Determine splitsize bases on filesize, max pcap size and nr of cores to use.
        # Split files even if smaller than max pcap size to make maximum use of parallel
        # processing. If filesize > nr_procs*maxpcapchunk then just use that.
        filesize = round(os.path.getsize(self.src_file)/(1024*1024))
        logger.debug(f"Filesize is approximately {filesize}MB")
        logger.debug(f"nr_of_cores x chunk_size = {nr_procs*self.max_pcap_chunk}MB")

        self.splitsize = self.max_pcap_chunk
        if (nr_procs * self.max_pcap_chunk) > filesize:
            self.splitsize = int(filesize/nr_procs)+2
            logger.debug(f"Split size set to {self.splitsize}MB")

    # ------------------------------------------------------------------------------
    def __prepare_file(self):

        # Chop up a file into multiple chunks if it is bigger than a certain size
        # Returns either a list of chunk files or the same single file

        use_tmp = False
        filename = Path(self.src_file)
        if filename.stat().st_size < (self.splitsize * 1000 * 1000):  # PCAP is smaller than 100MB
            self.chunks = [self.src_file]
        else:
            # Now check if the file ends in .pcap
            # If not: tcpdump on Ubuntu variants will return permission denied
            # when splitting into multiple chunks
            # Solution: copy to tmp folder with extension .pcap...
            if not self.src_file.endswith('.pcap'):
                logger.debug(f'Copy/rename file since it does not end in .pcap')
                shutil.copyfile(self.src_file, f'/tmp/{self.random}.pcap')
                filename = Path(f'/tmp/{self.random}.pcap')
                use_tmp = True
            logger.debug(f'Splitting PCAP file {filename} into chunks of {self.splitsize}MB.')
            process = subprocess.run(
                ['tcpdump', '-r', filename, '-w', f'/tmp/pcap2parquet_{self.random}_chunk', '-C', f'{self.splitsize}'],
                stderr=subprocess.PIPE)
            output = process.stderr
            if process.returncode != 0:
                err = output.decode('utf-8').strip()
                logger.error(f'splitting file failed: {err}')
            else:
                self.chunks = [Path(rootdir) / file for rootdir, _, files in os.walk('/tmp')
                               for file in files if file.startswith(f'pcap2parquet_{self.random}_chunk')]
                logger.debug(f"Split into {len(self.chunks)} chunks")

            if use_tmp:
                os.remove(filename)

    # ------------------------------------------------------------------------------
    def __cleanup(self):
        if self.chunks:
            if len(self.chunks) > 1:
                for chunk in self.chunks:
                    os.remove(chunk)
            self.chunks = None

        if self.chunks_csv:
            if len(self.chunks_csv) > 1:
                for chunk in self.chunks_csv:
                    os.remove(chunk)
            self.chunks_csv = None

    # ------------------------------------------------------------------------------
    def __parse_error(self, row):
        # logger.debug(row.text)
        self.parse_errors += 1
        if self.log_parse_errors:
            # Append to file
            with open(self.basename + '-parse-errors.txt', 'a', encoding='utf-8') as f:
                f.write(row.text + '\n')
        return 'skip'

    # ------------------------------------------------------------------------------
    def convert_chunk_to_csv(self, pcap_chunk):
        # Create the list of columns tshark has to export to CSV
        col_extract = list(self.PCAP_COLUMN_NAMES.keys())

        new_env = dict(os.environ)
        new_env['LC_ALL'] = 'C.utf8'
        new_env['LC_TIME'] = 'POSIX'
        new_env['LC_NUMERIC'] = 'C.utf8'

        tmp_file, tmp_filename = tempfile.mkstemp()
        # tshark_error = False
        # Create command
        csv_file = None
        command = ['tshark', '-r', str(pcap_chunk), '-t', 'ud', '-T', 'fields']
        for field in col_extract:
            command.extend(['-e', field])
        for option in ['header=n', 'separator=/t', 'quote=n', 'occurrence=f']:
            command.extend(['-E', option])

        logger.debug(" ".join(command))
        try:
            process = subprocess.run(command, stdout=tmp_file, stderr=subprocess.PIPE, env=new_env)
            output = process.stderr
            if process.returncode != 0:
                err = output.decode('utf-8')
                logger.error(f'tshark command failed:{err}')
                os.close(tmp_file)
                os.remove(tmp_filename)
            else:
                if len(output) > 0:
                    err = output.decode('utf-8')
                    for errline in err.split('\n'):
                        if len(errline) > 0:
                            logger.warning(errline)
                os.close(tmp_file)
                csv_file = tmp_filename
        except Exception as e:
            logger.error(f'Error reading {str(pcap_chunk)} : {e}')
            pp.pprint(e)
            os.close(tmp_file)
            os.remove(tmp_filename)

        return csv_file

    # ------------------------------------------------------------------------------
    def convert(self):

        pp = pprint.PrettyPrinter(indent=4)

        # Create the list of columns tshark has to export to CSV
        col_extract = list(self.PCAP_COLUMN_NAMES.keys())

        # Create the list of names pyarrow gives to the columns in the CSV
        col_names = []
        for extr_name in col_extract:
            col_names.append(next(iter(self.PCAP_COLUMN_NAMES[extr_name])))

        # Dict mapping column names to the pyarrow types
        col_type = {}
        [col_type.update(valtyp) for valtyp in self.PCAP_COLUMN_NAMES.values()]

        start = time.time()

        # Split source pcap into chunks if need be
        self.__prepare_file()
        if not self.chunks:
            logger.error("conversion aborted")
            return None

        # Convert chunks to csv individually and in parallel
        pool = multiprocessing.Pool(self.nr_procs)
        results = pool.map(self.convert_chunk_to_csv, self.chunks)  # Convert the PCAP chunks concurrently
        pool.close()
        pool.join()

        self.chunks_csv = []
        for result in results:
            if result:
                self.chunks_csv.append(result)

        duration = time.time() - start
        sf = os.path.basename(self.src_file)
        logger.debug(f"{sf} to CSV in {duration:.2f}s")
        start = time.time()

        pqwriter = None

        # Now read the produced CSVs and convert them to parquet one by one
        output_file = f'{self.dst_dir}{self.basename}.parquet'
        for chunknr, chunkcsv in enumerate(self.chunks_csv):
            logger.debug(f"Writing to parquet: {chunknr + 1}/{len(self.chunks_csv)}")
            try:
                with open(chunkcsv, "rb") as f:
                    f = UnicodeErrorIgnorerIO(f)
                    with pyarrow.csv.open_csv(
                            input_file=f,
                            # input_file='tmp.csv',
                            read_options=pyarrow.csv.ReadOptions(
                                block_size=self.block_size,
                                column_names=col_names,
                                encoding='utf-8',
                            ),
                            parse_options=pyarrow.csv.ParseOptions(
                                delimiter='\t',
                                # quote_char="'",
                                invalid_row_handler=self.__parse_error
                            ),
                            convert_options=pyarrow.csv.ConvertOptions(
                                timestamp_parsers=[pyarrow.csv.ISO8601],
                                column_types=col_type,
                            ),
                    ) as reader:
                        for next_chunk in reader:
                            if next_chunk is None:
                                break
                            table = pa.Table.from_batches([next_chunk])
                            # Add a column with the basename of the source file
                            # This will allow detailed investigation of the proper
                            # original pcap file with tshark if needed
                            table = table.append_column('pcap_file',
                                                        pa.array([self.basename] * len(table), pa.string()))

                            if not pqwriter:
                                pqwriter = pq.ParquetWriter(output_file, table.schema)

                            pqwriter.write_table(table)

            except pyarrow.lib.ArrowInvalid as e:
                logger.error(e)

        if pqwriter:
            pqwriter.close()
            duration = time.time() - start
            logger.debug(f"CSV to Parquet in {duration:.2f}s")

        self.__cleanup()
        return output_file


###############################################################################
class ArgumentParser(argparse.ArgumentParser):

    def error(self, message):
        print('\n\033[1;33mError: {}\x1b[0m\n'.format(message))
        self.print_help(sys.stderr)
        # self.exit(2, '%s: error: %s\n' % (self.prog, message))
        self.exit(2)


###############################################################################
class CustomConsoleFormatter(logging.Formatter):
    """
        Log facility format
    """

    def format(self, record):
        # info = '\033[0;32m'
        info = ''
        warning = '\033[0;33m'
        error = '\033[1;33m'
        debug = '\033[1;34m'
        reset = "\x1b[0m"

        formatter = "%(levelname)s - %(message)s"
        if record.levelno == logging.INFO:
            log_fmt = info + formatter + reset
            self._style._fmt = log_fmt
        elif record.levelno == logging.WARNING:
            log_fmt = warning + formatter + reset
            self._style._fmt = log_fmt
        elif record.levelno == logging.ERROR:
            log_fmt = error + formatter + reset
            self._style._fmt = log_fmt
        elif record.levelno == logging.DEBUG:
            # formatter = '%(asctime)s %(levelname)s [%(filename)s.py:%(lineno)s/%(funcName)s] %(message)s'
            formatter = '%(levelname)s [%(filename)s:%(lineno)s/%(funcName)s] %(message)s'
            log_fmt = debug + formatter + reset
            self._style._fmt = log_fmt
        else:
            self._style._fmt = formatter

        return super().format(record)


###############################################################################
class AttackVector:
    def __init__(self, db: DuckDBPyConnection, view: str, source_port: int, protocol: int):

        pp = pprint.PrettyPrinter(indent=4)

        # self.data = data
        self.db = db
        self.source_port = source_port
        self.protocol = IPPROTO_TABLE[protocol]

        self.view = f"'{self.protocol}-{str(uuid.uuid4())}'"
        start = time.time()
        if source_port == -1:
            self.view = view
            self.source_port = dataframe_to_dict(get_outliers(db, self.view, 'source_port', 0.1)['df'])
        else:
            db.execute(
                f"create view {self.view} as select * from {view} where ip_proto={protocol} and source_port={source_port}")

        results = db.execute(
            f"select sum(nr_packets) as nr_packets, sum(nr_bytes) as nr_bytes, "
            "min(time_start) as time_start, max(time_end) as time_end "
            f" from {self.view}").fetchdf()
        print()
        pp.pprint(results)
        self.packets = int(results['nr_packets'][0])
        self.bytes = int(results['nr_bytes'][0])
        self.time_start: datetime = pytz.utc.localize(results['time_start'][0])
        self.time_end: datetime = pytz.utc.localize(results['time_end'][0])
        self.duration = (self.time_end - self.time_start).seconds

        results = db.execute(f"select distinct(source_address) from {self.view}").fetchdf()
        self.source_ips = list(results['source_address'])
        # print(self.source_ips)
        print(f"{len(self.source_ips)} IP Addresses")
        duration = time.time() - start
        print(f"That took {duration:.2f} seconds")

        self.destination_ports = dataframe_to_dict(get_outliers(db, self.view, 'destination_port', 0.1)['df'])
        pp.pprint(self.destination_ports)
        self.fraction_of_attack = 0

        try:
            if self.protocol == 'UDP' and source_port != -1:
                self.service = (AMPLIFICATION_SERVICES.get(self.source_port, None) or
                                socket.getservbyport(source_port, self.protocol.lower()).upper())
            elif self.protocol == 'TCP' and source_port != -1:
                self.service = socket.getservbyport(source_port, self.protocol.lower()).upper()
            else:
                self.service = None
        except OSError:  # service not found by socket.getservbyport
            if self.source_port == 0 and len(self.destination_ports) == 1 and list(self.destination_ports)[0] == 0:
                self.service = 'Fragmented IP packets'
            else:
                self.service = None
        except OverflowError:  # Random source port (-1), no specific service
            self.service = None
        print(f"\nservice: {self.service}")

        if self.protocol == 'TCP':
            self.tcp_flags = None
        #     self.tcp_flags = dict(get_outliers(self.data, 'tcp_flags', 0.2, return_others=True)) or None
        #     if self.filetype == FileType.PCAP:  # Transform the numeric TCP flag representation to identifiable letters
        #         flag_letters = {}
        #         for key, value in self.tcp_flags.items():
        #             flag_letters[key.replace('·', '.')] = value
        #         self.tcp_flags = flag_letters
        #
        else:
            self.tcp_flags = None

        res = get_outliers(db, self.view, 'eth_type', 0.05, return_others=True)
        self.eth_type = dataframe_to_dict(res['df'], translate=ETHERNET_TYPES, others=res['others'])
        print(f"eth_type: {self.eth_type}\n")

        res = get_outliers(db, self.view, 'nr_bytes', 0.05, return_others=True)
        # set nr_bytes to str

        self.frame_len = dataframe_to_dict(res['df'].astype({'nr_bytes': str}), others=res['others'])
        print(f"frame_len: {self.frame_len}\n")

        if isinstance(self.eth_type, dict) and ('IPv4' in self.eth_type or 'IPv6' in self.eth_type):
            # IP packets
            res = get_outliers(db, self.view, 'fragmentation_offset', 0.1, return_others=True)
            self.frag_offset = dataframe_to_dict(res['df'].astype({'fragmentation_offset': str}), others=res['others'])
            print(f"frag_offset: {self.frag_offset}\n")

            res = get_outliers(db, self.view, 'ttl', 0.069, return_others=True)
            # res = get_outliers(db, self.view, 'ttl', 0.1, return_others=True)
            self.ttl = dataframe_to_dict(res['df'].astype({'ttl': str}), others=res['others'])
            print(f"ttl: {self.ttl}\n")

        if self.service == 'DNS':
            res = get_outliers(db, self.view, 'dns_qry_name', 0.1, return_others=True)
            self.dns_query_name = dataframe_to_dict(res['df'], others=res['others'])
            print(f"dns_query_name: {self.dns_query_name}\n")

            res = get_outliers(db, self.view, 'dns_qry_type', 0.1, return_others=True)
            self.dns_query_type = dataframe_to_dict(res['df'].astype({'dns_qry_type': int}),
                                                    translate=DNS_QUERY_TYPES, others=res['others'])
            print(f"dns_query_type: {self.dns_query_type}\n")
        elif self.protocol == 'ICMP':
            res = get_outliers(db, self.view, 'icmp_type', 0.1, return_others=True)
            self.icmp_type = dataframe_to_dict(res['df'], translate=ICMP_TYPES, others=res['others'])
            print(f"icmp_type: {self.icmp_type}\n")
        # if self.filetype == FileType.PCAP:
        #     elif self.service in ['HTTP', 'HTTPS']:
        #         self.http_uri = dict(get_outliers(self.data, 'http_uri', fraction_for_outlier=0.05,
        #                                           return_others=True)) or 'random'
        #         self.http_method = dict(get_outliers(self.data, 'http_method', fraction_for_outlier=0.1,
        #                                              return_others=True)) or 'random'
        #         self.http_user_agent = dict(get_outliers(self.data, 'http_user_agent', fraction_for_outlier=0.05,
        #                                                  return_others=True)) or 'random'
        #     elif self.service == 'NTP':
        #         self.ntp_requestcode = dict(get_outliers(self.data, 'ntp_requestcode', fraction_for_outlier=0.1,
        #                                                  return_others=True)) or 'random'
        #     elif self.protocol == 'ICMP':
        #         self.icmp_type = dict(get_outliers(self.data, 'icmp_type', fraction_for_outlier=0.1,
        #                                            return_others=True)) or 'random'

    def __str__(self):
        return f'[AttackVector ({round(self.fraction_of_attack * 100, 1)}% of traffic) {self.protocol}, service: {self.service}]'

    def __repr__(self):
        return self.__str__()

    def __len__(self):
        return len(self.data)

    def __lt__(self, other):
        if type(other) != AttackVector:
            return NotImplemented
        return self.bytes < other.bytes and self.service != 'Fragmented IP packets'

    def as_dict(self, summarized: bool = False) -> dict:
        fields = {
            'service': self.service,
            'protocol': self.protocol,
            # 'fraction_of_attack': self.fraction_of_attack if self.service != 'Fragmented IP packets' else None,
            'fraction_of_attack': self.fraction_of_attack,
            'source_port': self.source_port if self.source_port != -1 else 'random',
            'destination_ports': self.destination_ports,
            'tcp_flags': self.tcp_flags,
            # f'nr_{"flows" if self.filetype == FileType.FLOW else "packets"}': len(self),
            'nr_packets': int(self.packets),
            'nr_megabytes': int(self.bytes) // 1_000_000,
            'time_start': self.time_start.isoformat(),
            'duration_seconds': self.duration,
            'source_ips': f'{len(self.source_ips)} IP addresses ommitted' if summarized
            else [str(i) for i in self.source_ips],
        }
        # if self.filetype == FileType.PCAP:
        fields.update({'ethernet_type': self.eth_type,
                       'frame_len': self.frame_len})
        if 'IPv4' in self.eth_type.keys() or 'IPv6' in self.eth_type.keys():  # IP packets
            fields.update({'fragmentation_offset': self.frag_offset,
                           'ttl': self.ttl})
        if self.service == 'DNS':
            fields.update({'dns_query_name': self.dns_query_name,
                           'dns_query_type': self.dns_query_type})
        elif self.service in ['HTTP', 'HTTPS']:
            fields.update({'http_uri': self.http_uri,
                           'http_method': self.http_method,
                           'http_user_agent': self.http_user_agent})
        elif self.service == 'NTP':
            fields.update({'ntp_requestcode': self.ntp_requestcode})
        elif self.protocol == 'ICMP':
            fields.update({'icmp_type': self.icmp_type})
        return fields


###############################################################################
# Subroutines

# ------------------------------------------------------------------------------
def get_outliers(db: DuckDBPyConnection,
                 view: str,
                 column: Union[str, list[str]],
                 fraction_for_outlier: float,
                 return_others: bool = False) -> pd.DataFrame | None:

    pp = pprint.PrettyPrinter(indent=4)
    start = time.time()
    cols = column
    if isinstance(column, list):
        cols = ','.join(column)

    df_all = db.execute(
        f"select {cols}, sum(nr_packets)/(select sum(nr_packets) from {view}) as frac from {view}"
        f" group by all order by frac desc").fetchdf()

    df_frac = df_all[df_all['frac'] > fraction_for_outlier].copy()

    others = None
    if return_others:
        others = round(df_all[df_all['frac'] <= fraction_for_outlier]['frac'].sum(), 3)
        if others < 0.002:
            others = None

    df_frac['frac'] = df_frac['frac'].map(lambda frac: round(frac, 3))

    duration = time.time() - start
    print(df_all.head())
    print(f"That took {duration:.2f} seconds")

    return {'df': df_frac, 'others': others}


# ------------------------------------------------------------------------------
def dataframe_to_dict(df: pd.DataFrame, default: str = 'random', translate: dict = None, others = None):
    if len(df.columns) != 2:
        return default

    if df.empty:
        return default

    ret = dict()
    for index, row in df.iterrows():
        if translate:
            if isinstance(row[0], str):
                ret[row[0]] = row[1]
            else:
                ret[translate[int(row[0])]] = row[1]
        else:
            if isinstance(row[0], str):
                ret[row[0]] = row[1]
            else:
                ret[int(row[0])] = row[1]

    if others:
        ret['others'] = others

    return ret


# ------------------------------------------------------------------------------
def get_logger(debug=False):
    logger = logging.getLogger(__name__)

    # Create handlers
    console_handler = logging.StreamHandler()
    #    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    formatter = CustomConsoleFormatter()
    console_handler.setFormatter(formatter)

    logger.setLevel(logging.INFO)

    if debug:
        logger.setLevel(logging.DEBUG)

    # add handlers to the logger
    logger.addHandler(console_handler)

    return logger


# ------------------------------------------------------------------------------
def parser_add_arguments():
    """
        Parse command line parameters
    """
    parser = ArgumentParser(
        prog=program_name,
        description=textwrap.dedent('''\
                        Vewwy vewwy wudimentary duckdb powered dissector
                        '''),
        formatter_class=argparse.RawTextHelpFormatter, )

    parser.add_argument("source",
                        help=textwrap.dedent('''\
                        Source pcap file
                        '''),
                        action="store",
                        )

    parser.add_argument("--debug",
                        help="show debug output",
                        action="store_true")

    parser.add_argument("-V", "--version",
                        help="print version and exit",
                        action="version",
                        version='%(prog)s (version {})'.format(VERSION))

    return parser


#############################################################################
def main():

    pp = pprint.PrettyPrinter(indent=4)
    parser = parser_add_arguments()
    args = parser.parse_args()
    logger = get_logger(args.debug)

    filename = args.source
    if not os.path.isfile(filename):
        logger.error(f"{filename} is not a file")
        exit(1)

    startall = time.time()

    if filename.endswith('.parquet'):
        parquet_file = filename
    else:
        logger.info(f"Converting {filename} to parquet")
        start = time.time()

        # Store converted parquet file in *this* directory (where this file resides)
        dir_path = os.path.dirname(os.path.realpath(__file__))
        pcap2pqt = Pcap2Parquet(filename, dir_path, False, os.cpu_count())
        parquet_file = pcap2pqt.convert()
        duration = time.time() - start
        if parquet_file:
            logger.info(f"conversion took {duration:.2f} seconds")
        else:
            logger.error("Conversion failed")
            exit(2)

        if pcap2pqt.parse_errors > 0:
            logger.info(f'{pcap2pqt.parse_errors} parse errors during conversion. Error lines were skipped')

    db = duckdb.connect()

    # Create view on parquet file
    db.execute(f"CREATE VIEW raw AS SELECT * FROM '{parquet_file}'")

    # Create a view from that, flattening udp/tcp ports onto one src/dst port (and replacing NaN with 0 as well)
    # Do similar for source/destination address
    sql = "create view pcap as select * exclude "\
          "(col_protocol, tcp_srcport, tcp_dstport, udp_srcport, udp_dstport, "\
          "ip_src, ip_dst, col_source, col_destination, frame_time, "\
          "ip_frag_offset, ntp_priv_reqcode, ip_ttl, frame_len), "\
          "coalesce(ip_src, col_source) as source_address, "\
          "coalesce(ip_dst, col_destination) as destination_address, "\
          "coalesce(tcp_srcport, udp_srcport, 0) as source_port, "\
          "coalesce(tcp_dstport, udp_dstport, 0) as destination_port, "\
          "coalesce(ip_frag_offset, 0) as fragmentation_offset, "\
          "coalesce(ntp_priv_reqcode, 0) as ntp_requestcode, "\
          "coalesce(ip_ttl, 0) as ttl, "\
          "col_protocol as service, "\
          "frame_time as time_start, "\
          "frame_time as time_end, "\
          "frame_len as nr_bytes, "\
          "1 as nr_packets, "\
          "from raw"

    # print(sql)
    db.execute(sql)

    # # See if we can find attack victim
    df = get_outliers(db, 'pcap', 'destination_address', 0.5)['df']

    # Keep it simple for now
    if len(df) == 0:
        print("No attack found")
        exit(0)

    # Create new view that only contains attack traffic
    for index, row in df.iterrows():
        print("Attack target(s) found:")
        print(f"{row['destination_address']} ({row['frac']})\n")

    # enclose target IPs in ' --> so we can make sql as: where destination_address in ('ip1', 'ip2')
    targets_str = [f"'{t}'" for t in list(df['destination_address'])]
    targets = list(df['destination_address'])
    if len(targets) == 1:
        targets = targets[0]

    # Create 'attack' view based on target(s)
    db.execute(f"create view attack as select * from pcap where destination_address in ({','.join(targets_str)})")

    # Create 'attack' view without fragmentation based on target(s)
    db.execute(f"create view attack_nofrag as select * from attack where source_port>0")

    # Get outliers with fragmentation
    df_attacks1 = get_outliers(db, 'attack', ['ip_proto', 'source_port'], 0.05, return_others=True)
    pp.pprint(df_attacks1['df'])
    print(f"others: {df_attacks1['others']}\n")
    df_attacks_frag = df_attacks1['df']

    # Get outliers without fragmentation
    df_attacks_nofrag = get_outliers(db, 'attack_nofrag', ['ip_proto', 'source_port'], 0.05)['df']
    pp.pprint(df_attacks_nofrag)
    print()

    # Leave fragmented for now
    attack_vectors: list[AttackVector] = []
    filter = []
    if len(df_attacks_nofrag)>0:
        for index, row in df_attacks_nofrag.iterrows():
            # pp.pprint(row)
            source_port = int(row['source_port'])
            ip_proto = int(row['ip_proto'])
            filter.append(f"(ip_proto={ip_proto} and source_port={source_port})")
            av = AttackVector(db, 'attack_nofrag', source_port, ip_proto)
            av.fraction_of_attack = row['frac']
            attack_vectors.append(av)
    else:
        # find the different ip_proto's and use that
        df_protos = get_outliers(db, 'attack_nofrag', 'ip_proto', 0.05)['df']
        print(f"ip_protos: {df_protos}\n")
        for index, row in df_protos.iterrows():
            ip_proto = row['ip_proto']
            db.execute(f"create view attack_{index} as select * from attack_nofrag where ip_proto={ip_proto}")
            filter.append(f"ip_proto={ip_proto}")
            av = AttackVector(db, f'attack_{index}', -1, ip_proto)
            av.fraction_of_attack = row['frac']
            attack_vectors.append(av)

    # Now get back to the fragmented bits
    for index, row in df_attacks_frag.iterrows():
        if row['source_port'] == 0:
            print("Looking into fragmented bits")
            # db.execute(f"create view attack_frag_{index} as select * from attack where ip_proto={row['ip_proto']} and source_port=0")
            av = AttackVector(db, 'attack', 0, row['ip_proto'])
            av.fraction_of_attack = row['frac']
            attack_vectors.append(av)

    # See if rest of traffic is worth exploring
    frac = 0.0
    for av in attack_vectors:
        frac += av.fraction_of_attack

    if frac < 0.99:
        # See if there is any other attack data outside the already established attack vectors
        # This needs some serious SQL query wrangling...
        # Get a view that contains all data *except* the attack vector outliers
        filter_combi = " or ".join(filter)
        print(f" not ({filter_combi})")
        # Create remainder view without fragmentation
        if len(filter) > 0:
            db.execute(f"create view remainder as select * from attack_nofrag where not ({filter_combi})")
        else:
            db.execute(f"create view remainder as select * from attack_nofrag")

        df_prot_dest = get_outliers(db, 'remainder', ['ip_proto', 'destination_port'], 0.1)['df']
        pp.pprint(df_prot_dest)
        for index, row in df_prot_dest.iterrows():
            ip_proto = row['ip_proto']
            destination_port = row['destination_port']
            db.execute(f"create view remainder_{index} as select * from remainder where ip_proto={ip_proto} and "
                       f"destination_port={destination_port}")
            av = AttackVector(db, f'remainder_{index}', -1, ip_proto)
            attack_vectors.append(av)

    # Update traffic percentages & create summary
    total_pkts = 0
    total_bytes = 0
    times: list(datetime) = []
    for av in attack_vectors:
        total_pkts += av.packets
        total_bytes += av.bytes
        times.append(av.time_start)
        times.append(av.time_end)

    fp = {}
    fp['target'] = targets
    fp['time_start'] = min(times)
    fp['time_end'] = max(times)
    fp['duration'] = (max(times)-min(times)).seconds
    fp['total_packets'] = total_pkts
    fp['total_megabytes'] = total_bytes // 1_000_000
    fp['attack_vectors'] = []

    print("\n-------------------------------------------------")
    for av in attack_vectors:
        av.fraction_of_attack = round(av.packets/total_pkts, 3)
        fp['attack_vectors'].append(av.as_dict(summarized=True))
        # print(av)
        # # return json.dumps(self.as_dict(summarized=True), indent=4)
        # print(json.dumps(av.as_dict(summarized=True), indent=4))

    strmd5 = (str(attack_vectors)+str(fp['total_packets'])+'/'+str(fp['total_megabytes'])).encode()
    fp['key'] = hashlib.md5(strmd5).hexdigest()

    print(json.dumps(fp, indent=4, default=str))

    fp['attack_vectors'] = []
    for av in attack_vectors:
        fp['attack_vectors'].append(av.as_dict(summarized=False))

    with open(f"{fp['key']}.json", 'w') as f:
        f.write(json.dumps(fp, indent=4, default=str))

    # df = db.execute("show tables").fetchdf()
    # pp.pprint(df)
    db.close()

    duration = time.time()-startall
    print(f"\nOverall took {duration:.2f} seconds")


if __name__ == '__main__':
    # Run the main process
    main()
