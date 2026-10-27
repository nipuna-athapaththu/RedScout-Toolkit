"""Maps plugin techniques to MITRE ATT&CK tactics/techniques."""

MAPPING = {
    "port_scan": {"tactic": "Discovery", "technique_id": "T1046", "technique": "Network Service Discovery"},
    "service_enum": {"tactic": "Discovery", "technique_id": "T1046", "technique": "Network Service Discovery"},
    "web_vuln_scan": {"tactic": "Initial Access", "technique_id": "T1190", "technique": "Exploit Public-Facing Application"},
    "credential_bruteforce": {"tactic": "Credential Access", "technique_id": "T1110", "technique": "Brute Force"},
    "subdomain_enum": {"tactic": "Reconnaissance", "technique_id": "T1590.001", "technique": "Gather Victim Network Information: Domain Properties"},
    "dns_enum": {"tactic": "Reconnaissance", "technique_id": "T1590.002", "technique": "Gather Victim Network Information: DNS"},
    "whois_lookup": {"tactic": "Reconnaissance", "technique_id": "T1596.002", "technique": "Search Open Technical Databases: WHOIS"},
    "web_fuzzing": {"tactic": "Discovery", "technique_id": "T1083", "technique": "File and Directory Discovery"},
        "sqli": {"tactic": "Initial Access", "technique_id": "T1190", "technique": "Exploit Public-Facing Application"},
    "xss": {"tactic": "Execution", "technique_id": "T1059.007", "technique": "JavaScript/JScript"},
}

def map_technique(technique: str) -> dict:
    return MAPPING.get(technique, {"tactic": "Unknown", "technique_id": "N/A", "technique": technique})