import sys
import time
import pandas as pd
# from netaddr import IPAddress, IPNetwork
from typing import Any
from collections import defaultdict
from datetime import datetime
import pytz

from logger import LOGGER
from attack import Attack, AttackVector
from util import get_outliers, FileType

__all__ = ["infer_target", "extract_attack_vectors", "compute_summary"]


def infer_target(attack: Attack) -> str:
    """
    Infer the target IP address of this attack.
    :param attack: Attack object of which to determine the target IP address or network
    :return: Target IP address as a string, or None if nothing found
    """
    LOGGER.debug("Inferring attack target.")
    df = get_outliers(attack.db, attack.view, 'destination_address', 0.5)['df']
    target = None
    if not df.empty:
        target = df['destination_address'][0]
    return target


def extract_attack_vectors(attack: Attack) -> list[AttackVector]:
    """
    Extract the attack vector(s) that make up this attack, from the Attack object. e.g. DNS amplfication vector
    :param attack: Attack object from which extract vectors
    :return: List of AttackVectors
    """
    LOGGER.info('Extracting attack vectors.')
    # Get outliers with fragmentation
    df_attacks_frag = get_outliers(attack.db, attack.view, ['protocol', 'source_port'], 0.05, return_others=True)
    LOGGER.debug(df_attacks_frag['df'])
    LOGGER.debug(f"others: {df_attacks_frag['others']}\n")
    df_attacks_frag = df_attacks_frag['df']
    fragmentation_protocols = set()  # protocols for which a significant fraction of traffic is fragmented packets
    for index, row in df_attacks_frag.iterrows():
        source_port = int(row['source_port'])
        protocol = str(row['protocol'])
        if source_port == 0 and protocol in ['UDP', 'TCP']:
            fragmentation_protocols.add(protocol)

    LOGGER.debug(f"fragmentation protocols: {fragmentation_protocols}")

    # Create 'attack' view without fragmentation based on target(s)
    attack.db.execute(f"create view attack_nofrag as select * from '{attack.view}' where source_port>0")
    df_attacks_nofrag = get_outliers(attack.db, 'attack_nofrag', ['protocol', 'source_port'], 0.05, return_others=True)
    LOGGER.debug(df_attacks_nofrag['df'])
    LOGGER.debug(f"others: {df_attacks_nofrag['others']}\n")
    df_attacks_nofrag = df_attacks_nofrag['df']

    LOGGER.debug(f'Extracting attack vectors from source_port / protocol pair outliers ')
    # Leave fragmented for now
    attack_vectors: list[AttackVector] = []
    filter = []
    for index, row in df_attacks_nofrag.iterrows():
        LOGGER.debug(f"\n{row}")
        source_port = int(row['source_port'])
        protocol = str(row['protocol'])
        filter.append(f"(protocol='{protocol}' and source_port={source_port})")
        av = AttackVector(attack.db, attack.view, source_port, protocol, attack.filetype)
        av.fraction_of_attack = row['frac']
        attack_vectors.append(av)

    # See if rest of traffic is worth exploring
    frac = 0.0
    for av in attack_vectors:
        frac += av.fraction_of_attack

    if frac < 0.90:
        # See if there is any other attack data outside the already established attack vectors
        # This needs some serious SQL query wrangling...
        # Get a view that contains all data *except* the attack vector outliers
        # Create remainder view without fragmentation
        if len(filter) > 0:
            filter_combi = " or ".join(filter)
            LOGGER.debug(f" not ({filter_combi})")
            attack.db.execute(f"create view remainder as select * from attack_nofrag where not ({filter_combi})")
        else:
            attack.db.execute(f"create view remainder as select * from attack_nofrag")

        df_prot_dest = get_outliers(attack.db, 'remainder', ['protocol', 'destination_port'], 0.1)['df']
        LOGGER.debug(df_prot_dest)
        # If combine outliers of the same protocol
        protos = list(set(list(df_prot_dest['protocol'])))
        for proto in protos:
            av = AttackVector(attack.db, 'remainder', -1, proto, attack.filetype)
            attack_vectors.append(av)

    # Handle the fragmentation bits now
    # But only needed if other attack vectors already found
    if len(attack_vectors) > 0:
        LOGGER.debug("Checking fragmented bits now")
        for protocol in fragmentation_protocols:
            av = AttackVector(attack.db, attack.view, 0, protocol, attack.filetype)
            attack_vectors.append(av)

    return sorted(attack_vectors)


def compute_summary(attack_vectors: list[AttackVector]) -> dict[str, Any]:
    """
    Compute the summary statistics of the attack given its attack vectors
    :param attack_vectors: List of attack vectors that make up the attack
    :return: Dictionary with summary statistics
    """

    if len(attack_vectors) == 0:
        return None

    filetype = attack_vectors[0].filetype
    # Update traffic percentages & create summary
    total_entries = 0
    total_pkts = 0
    total_pkts_nofrag = 0
    total_bytes = 0
    ip_addresses = set()
    times: list(datetime) = []

    for av in attack_vectors:
        total_entries += av.entries
        total_pkts += av.packets
        total_pkts_nofrag += av.summ_nr_pkts()
        total_bytes += av.bytes
        times.append(av.time_start)
        times.append(av.time_end)
        ip_addresses.update(av.source_ips)

    for av in attack_vectors:
        if total_pkts_nofrag>0:
            av.fraction_of_attack = round(av.packets/total_pkts_nofrag, 3)
        else:
            av.fraction_of_attack = 0

    time_start: datetime = min(times).replace(tzinfo=None)
    time_end: datetime = max(times).replace(tzinfo=None)
    duration = (time_end - time_start).seconds
    nr_bytes = total_bytes
    nr_packets = total_pkts
    return {
        'time_start': time_start.isoformat(),
        'time_end': time_end.isoformat(),
        'duration_seconds': duration,
        f'total_{"flows" if filetype == FileType.FLOW else "packets"}': total_entries,
        'total_megabytes': nr_bytes // 1_000_000,
        'total_packets': nr_packets,
        'total_ips': len(ip_addresses),
        'avg_bps': (nr_bytes << 3) // duration if duration > 0 else 0,  # octets to bits
        'avg_pps': nr_packets // duration if duration > 0 else 0,
        'avg_Bpp': nr_bytes // nr_packets
    }
