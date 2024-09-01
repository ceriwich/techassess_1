from datetime import datetime
import random
import time
import argparse as ap
import os

# global
keywords = {"6":"tcp","1":"icmp","17":"udp"}

### functions to randomly generate input file and lookup table file ###

def generate_random_flow_log_entry() -> dict:
    """
    Generate one VPC flow log (version 2) entry
    :return:
    """
    return {
        "Version": "2",
        "AccountId": str(random.randint(100000000000, 999999999999)),
        "InterfaceId": f"eni-{''.join(random.choices('abcdef0123456789', k=16))}",
        "SrcAddr": f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}",
        "DstAddr": f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}",
        "SrcPort": str(random.randint(1024, 65535)),
        "DstPort": str(random.randint(1, 65535)),
        "Protocol": str(random.choice([1, 6, 17])),  # icmp, tcp, udp
        "Packets": str(random.randint(1, 1000)),
        "Bytes": str(random.randint(50, 5000)),
        "Start": str(int(time.time() - random.randint(10000, 50000))),
        "End": str(int(time.time() - random.randint(1000, 10000))),
        "Action": random.choice(["ACCEPT", "REJECT"]),
        "LogStatus": "OK" 
    }

def generate_random_tag_mapping() -> dict:
    """
    Generate one dstport/protocol to tag mapping
    :return:
    """
    return {
        "DstPort": str(random.randint(1, 65535)),
        "Protocol": str(random.choice(["icmp", "tcp", "udp","ICMP", "TCP", "UDP"])),
        "Tag": random.choice(["email", "sv_P" + str(random.randint(1, 5))])
    }

def generate_lookup_table(filename: str, num_entries: int):
    """
    Write specified number of randomly generated mappings to a file
    :param filename: file name of the lookup table
    :param num_entries: number of entries to generate AKA how many lines of a file
    """
    with open(filename, 'w') as f:
        f.write("dstport,protocol,tag\n")
        for _ in range(num_entries):
            mapping = generate_random_tag_mapping()
            val_list = list(mapping.values())
            log = ",".join(val_list) + "\n"
            f.write(log)

def generate_vpc_flow_logs(filename: str, num_entries: int):
    """
    Write specified number of randomly generated VPC flow log entries to a file
    :param filename: file name of flow log data file
    :param num_entries: number of entries to generate AKA how many lines of a file
    """
    with open(filename, 'w') as f:
        for _ in range(num_entries):
            log_entry = generate_random_flow_log_entry()
            val_list = list(log_entry.values())
            log = " ".join(val_list) + "\n"
            f.write(log)

### functions to parse data ###

def find_mapping(dstport: str, protocol: str, lookup_table: str) -> str:
    """
    Find tag by iterating through lookup table for dstport/protocol combination
    :param dstport: destination port
    :param protocol: protocol keyword
    :param lookup_table: filename for tag mappings
    :return:
    """
    with open(lookup_table, 'r') as tagfile:
        next(tagfile)
        for line in tagfile:
            row = line.split(",")
            if dstport == row[0] and protocol.lower() == row[1].lower():
                return row[2].strip()
    return None
        
def output_to_file(tag_counts: dict, port_prot_combos: dict):
    """
    Write frequency information to output file according to given format
    :param tag_counts: tag frequencies
    :param port_prot_combos: port/protocol combination frequencies
    """

    with open("output.txt", 'w') as outfile:
        outfile.write("Tag Counts:\nTag,Count\n")
        for key in tag_counts.keys():
            outfile.write(f"{key.rstrip()},{tag_counts[key]}\n")
        
        outfile.write("\nPort/Protocol Combination Counts:\nPort,Protocol,Count\n")
        for key in port_prot_combos.keys():
            outfile.write(f"{key.rstrip()},{port_prot_combos[key]}\n")

def parse_flow_logs(flow_log: str, lookup_table: str):
    """
    Parse given flow log file, map port/protocol combinations to a lookup table, and track tag frequency and combination frequency
    :param flow_log: file name of flow log data
    :param lookup_table: file name of lookup table
    """

    tag_counts = {}
    port_prot_combos = {}

    with open(flow_log, 'r+') as infile:
        start = datetime.now()
        for line in infile:
            fields = (line.strip()).split(" ")
            # if not version 2 or if not default format
            if fields[0] != "2":
                print("ERROR: Wrong Version - flow log data is NOT in the default format")
                return
            elif len(fields) != 14: #including new line character
                print("ERROR: Incorrect Number of Fields - flow log data is NOT in the default format")
                return
            
            dstport = fields[6]
            protocol_key = keywords[fields[7]]

            combo = dstport + "," + protocol_key
            try:
                    port_prot_combos[combo] += 1
            except:
                    port_prot_combos[combo] = 1

            tag = find_mapping(dstport, protocol_key, lookup_table) 
            if(tag != None):
                try:
                    tag_counts[tag] += 1
                except:
                    tag_counts[tag] = 1
            else:
                try:
                    tag_counts["Untagged"] += 1
                except:
                    tag_counts["Untagged"] = 1
                
    output_to_file(tag_counts, port_prot_combos)
    end = datetime.now()
    print("\telapsed time:", round(end.timestamp() - start.timestamp(), 4), " seconds")

menu = ap.ArgumentParser(description='Parse VPC flow log data either via files with given data or ones with randomly generated data.\nBoth FLOW_LOG_ENTRIES and LOOKUP_ENTRIES must be defined to retrieve the randomly generated data')

# positional arguments
menu.add_argument("flow_log_fn", help = "REQUIRED: File name for flow log data. Plain text (.txt) only", type = str)
menu.add_argument("lookup_table_fn", help = "REQUIRED:  File name for lookup table. Plain text (.txt) only", type = str)
menu.add_argument("-fle","--flow_log_entries", help = "Number of randomly generated flow log entries", type = int)
menu.add_argument("-le","--lookup_entries", help = "Number of randomly generated lookup table entries", type = int)

print("\n--- VPC Flow Log Analysis ---\n")
args = menu.parse_args()
gen_rand = args.flow_log_entries and args.lookup_entries
if args.flow_log_fn:
    if args.flow_log_fn[-4:] != ".txt":
        raise menu.error('Filename must be plain text (.txt)')
    if not os.path.isfile(args.flow_log_fn) and not gen_rand:
        raise menu.error('File not found in directory')

if args.lookup_table_fn:
    if args.flow_log_fn[-4:] != ".txt":
        raise menu.error('Filename must be plain text (.txt)')
    if not os.path.isfile(args.lookup_table_fn) and not gen_rand:
        raise menu.error('File not found in directory')
    
if args.flow_log_entries and args.lookup_entries:
    generate_lookup_table(args.lookup_table_fn, args.lookup_entries)
    generate_vpc_flow_logs(args.flow_log_fn, args.flow_log_entries)
    parse_flow_logs(args.flow_log_fn,args.lookup_table_fn)

elif args.flow_log_fn and args.lookup_table_fn:
    parse_flow_logs(args.flow_log_fn, args.lookup_table_fn)

