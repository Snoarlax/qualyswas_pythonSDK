#!/usr/bin/env python3
import sys
import xml.etree.ElementTree as ET
from .QualysApi import QualysClient, create_client

def parse_qualys_xml(file_path):
    """Parses a Qualys XML file and returns a set of vulnerabilities based on QID."""
    tree = ET.parse(file_path)
    root = tree.getroot()

    qid_set = set()
    for vuln in root.findall(".//VULNERABILITY"):
        qid = vuln.find("QID")
        if qid is not None and qid.text:
            qid_set.add(qid.text.strip())
    for vuln in root.findall(".//INFORMATION_GATHERED"):
        qid = vuln.find("QID")
        if qid is not None and qid.text:
            qid_set.add(qid.text.strip())
    return qid_set

def compare_vulns(old_vulns, new_vulns):
    added = new_vulns - old_vulns
    removed = old_vulns - new_vulns
    unchanged = old_vulns & new_vulns
    return added, removed, unchanged

def get_diff_qids(old_file, new_file):
    old_vulns = parse_qualys_xml(old_file)
    new_vulns = parse_qualys_xml(new_file)
    return compare_vulns(old_vulns, new_vulns)

def get_diff(client, old_file, new_file):
    added_qids, removed_qids, unchanged_qids = get_diff_qids(old_file, new_file)
    new_vulns, removed_vulns = set(),set()
    for added_qid in added_qids:
        qid_details = client.get_qid_details(added_qid)[0]
        new_vulns.add(qid_details["name"])
    for removed_qid in removed_qids:
        qid_details = client.get_qid_details(removed_qid)[0]
        removed_vulns.add(qid_details["name"])

    return new_vulns, removed_vulns, unchanged_qids

def print_diff(added, removed, unchanged):
    print(f"Added ({len(added)}): {sorted(added)}")
    print(f"Removed ({len(removed)}): {sorted(removed)}")
    print(f"Unchanged ({len(unchanged)}): {len(unchanged)} items")

def main():
    old_file = sys.argv[1]
    new_file = sys.argv[2]
    client = create_client()
    added, removed, unchanged = get_diff(client, old_file, new_file)
    print_diff(added, removed, unchanged)


if __name__ == "__main__":
    main()

