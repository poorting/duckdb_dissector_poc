from typing import Any
from collections import defaultdict
from datetime import datetime
import pytz

from logger import LOGGER
from attack import Attack, AttackVector
from util import get_outliers_single, get_outliers_mult, FileType

__all__ = ["infer_target", "extract_attack_vectors", "compute_summary"]


def infer_target(attack: Attack) -> str:
    """
    Infer the target IP address of this attack.
    :param attack: Attack object of which to determine the target IP address or network
    :return: Target IP address as a string, or None if nothing found
    """
    LOGGER.debug("Inferring attack target.")
    targets = get_outliers_single(attack.db, attack.view, 'destination_address', 0.5)

    target = None
    if not len(targets) == 0:
        target, _ = targets[0]
    return target


def extract_attack_vectors(attack: Attack) -> list[AttackVector]:
    """
    Extract the attack vector(s) that make up this attack, from the Attack object. e.g. DNS amplfication vector
    :param attack: Attack object from which extract vectors
    :return: List of AttackVectors
    """
    LOGGER.info('Extracting attack vectors.')
    # Get outliers with fragmentation
    df_attacks_frag = get_outliers_mult(attack.db, attack.view, ['protocol', 'source_port'], 0.05)
    LOGGER.debug(df_attacks_frag)
    fragmentation_protocols = set()  # protocols for which a significant fraction of traffic is fragmented packets

    attack_list: list[(str, int)] = []
    for index, row in df_attacks_frag.iterrows():
        source_port = int(row['source_port'])
        protocol = str(row['protocol'])
        if source_port == 0 and protocol in ['UDP', 'TCP']:
            fragmentation_protocols.add(protocol)
        else:
            attack_list.append((protocol, source_port))

    LOGGER.debug(f"fragmentation protocols: {fragmentation_protocols}")

    # Create 'attack' view without fragmentation based on target(s)
    attack.db.execute(f"create view '{attack.view}_nofrag' as select * from '{attack.view}' "
                      "where source_port>0 and protocol not in ('TCP','UDP')")
    df_attacks_nofrag = get_outliers_mult(attack.db, f'{attack.view}_nofrag', ['protocol', 'source_port'], 0.05)

    LOGGER.debug(df_attacks_nofrag)
    for index, row in df_attacks_nofrag.iterrows():
        source_port = int(row['source_port'])
        protocol = str(row['protocol'])
        attack_list.append((protocol, source_port))

    attack_list = list(set(attack_list))
    LOGGER.debug(f"All outliers with and without fragmentation:\n{attack_list}")

    LOGGER.debug(f'Extracting attack vectors from these source_port / protocol pair outliers ')
    # Leave fragmented for now
    attack_vectors: list[AttackVector] = []
    filter = []
    for protocol, source_port in attack_list:
        filter.append(f"(protocol='{protocol}' and source_port={source_port})")
        av = AttackVector(attack.db, attack.view, source_port, protocol, attack.filetype)
        if av.entries > 0:
            attack_vectors.append(av)

    # See if there is any other attack data outside the already established attack vectors
    # This needs some serious SQL query wrangling...
    # Get a view that contains all data *except* the attack vector outliers
    # Create remainder view without fragmentation
    viewname=attack.view if len(fragmentation_protocols) == 0 else f'{attack.view}_nofrag'
    if len(filter) > 0:
        filter_combi = " or ".join(filter)
        LOGGER.debug(f" not ({filter_combi})")
        attack.db.execute(f"create view '{viewname}_remainder' as select * from '{viewname}' where not ({filter_combi})")
    else:
        attack.db.execute(f"create view '{viewname}_remainder' as select * from '{viewname}'")

    df_prot_dest = get_outliers_mult(attack.db, f'{viewname}_remainder', ['protocol', 'destination_port'], 0.1)
    LOGGER.debug(df_prot_dest)
    # If combine outliers of the same protocol
    protos = list(set(list(df_prot_dest['protocol'])))
    for proto in protos:
        av = AttackVector(attack.db, f'{viewname}_remainder', -1, proto, attack.filetype)
        attack_vectors.append(av)

    # Combine attack vectors with the same service and protocol. First create a dictionary grouping them:
    # {(service, protocol): [attack_vectors]}
    vectors_by_service_protocol: dict[tuple[str, str], list[AttackVector]] = defaultdict(list)
    for vector in attack_vectors:
        vectors_by_service_protocol[(vector.service, vector.protocol)].append(vector)

    # Combine attack vectors in the same group.
    reduced_vectors: list[AttackVector] = []
    for (service, protocol), vectors in vectors_by_service_protocol.items():
        if len(vectors) > 1:
            viewname = f"{attack.view}_combined_{protocol}"
            ports = []
            for v in vectors:
                if v.input_source_port != -1:
                    if isinstance(v.input_source_port, int):
                        ports.append(str(v.input_source_port))
            if ports:
                attack.db.execute(f"create view '{viewname}' as select * from '{attack.view}' "
                                  f"where protocol='{protocol}' and source_port in ({','.join(ports)})")
                av = AttackVector(attack.db, viewname, -1, protocol, attack.filetype)
                reduced_vectors.append(av)
        else:
            reduced_vectors.append(vectors[0])
    attack_vectors = reduced_vectors

    LOGGER.debug('Computing the fraction of traffic each attack vector contributes.')
    while True:
        total_bytes = sum([v.bytes for v in attack_vectors])
        for vector in attack_vectors:
            vector.fraction_of_attack = round(vector.bytes / total_bytes, 3)
            if vector.fraction_of_attack < 0.05:
                break
        else:
            break
        LOGGER.debug(f'removing {vector} ({vector.fraction_of_attack * 100:.1f}% of traffic)')
        attack_vectors.remove(vector)

    # Handle the fragmentation vectors now
    # But only needed if other attack vectors already found
    if len(attack_vectors) > 0:
        LOGGER.debug("Checking fragmented vectors now")
        for protocol in fragmentation_protocols:
            # for every protocol, use only source ips that appear in other attack vectors (of the same protocol).
            srcips = []
            for av in attack_vectors:
                if av.protocol == protocol and isinstance(av.source_port, int) and av.source_port > 0:
                    srcips.extend(av.source_ips)

            srcips = list(set(srcips))
            if len(srcips) == 0:
                continue
            # Create a specific view that contains that protocol and IP addresses
            # LOGGER.debug(srcips)
            sql_ips = "','".join(srcips)
            sql = f"create view '{attack.view}_frag_{protocol}' as select * from '{attack.view}' where source_port=0 and " \
                  f"protocol='{protocol}' and source_address in ('{sql_ips}')"
            # LOGGER.debug(sql)
            attack.db.execute(sql)
            av = AttackVector(attack.db, f"{attack.view}_frag_{protocol}", 0, protocol, filetype=attack.filetype)
            if av.entries > 0:
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
    total_bytes_nofrag = 0
    ip_addresses = set()
    times: list(datetime) = []

    for av in attack_vectors:
        total_entries += av.entries
        total_pkts += av.packets
        total_pkts_nofrag += av.summ_nr_pkts()
        total_bytes += av.bytes
        total_bytes_nofrag += av.summ_nr_bytes()
        times.append(av.time_start)
        times.append(av.time_end)
        ip_addresses.update(av.source_ips)

    for av in attack_vectors:
        if total_bytes_nofrag > 0:
            av.fraction_of_attack = round(av.bytes/total_bytes_nofrag, 3)
        else:
            av.fraction_of_attack = 0

    time_start: datetime = pytz.utc.localize(min(times).replace(tzinfo=None))
    time_end: datetime = pytz.utc.localize(max(times).replace(tzinfo=None))
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
