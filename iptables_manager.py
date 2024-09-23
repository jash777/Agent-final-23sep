import logging
import ipaddress
import psutil
import pwd
import grp
import os
import spwd
import shutil
from pathlib import Path
import crypt
from functools import lru_cache
import re
import subprocess
import json
from concurrent.futures import ThreadPoolExecutor
from typing import List, Dict, Any, Tuple, Optional
import iptc
import socket
from datetime import datetime

from logger_config import setup_logger
logger = setup_logger('application_manager', 'logs/application_manager.log')

class IPTablesManager:
    @staticmethod
    def _add_rule(
        protocol: str,
        action: str,
        chain: str,
        port: Optional[int] = None,
        ip: Optional[str] = None,
        table: str = "filter",
        extra: Optional[str] = None
    ) -> bool:
        try:
            rule = iptc.Rule()
            if protocol.lower() != 'all':
                rule.protocol = protocol.lower()
            iptc_table = iptc.Table(table)
            iptc_chain = iptc.Chain(iptc_table, chain)

            rule.create_target(action.upper())

            if protocol.lower() in ['tcp', 'udp'] and port is not None:
                match = rule.create_match(protocol.lower())
                match.dport = str(port)

            if ip:
                ipaddress.ip_network(ip)  
                if chain == "INPUT":
                    rule.src = ip
                elif chain == "OUTPUT":
                    rule.dst = ip
            else:
                if chain == "INPUT":
                    rule.src = "0.0.0.0/0"
                elif chain == "OUTPUT":
                    rule.dst = "0.0.0.0/0"

            if extra:
                extra_parts = extra.split()
                if len(extra_parts) >= 2:
                    match_name, match_args = extra_parts[0], extra_parts[1:]
                    match = rule.create_match(match_name)
                    for arg in match_args:
                        key, value = arg.split('=')
                        setattr(match, key, value)

            iptc_chain.insert_rule(rule)
            logger.info(f"Iptables rule added successfully: {table} {chain} {protocol} {port if port else 'all'} {action}")
            return True
        except (iptc.IPTCError, ValueError) as e:
            logger.error(f"Error adding iptables rule: {e}")
            return False

    @staticmethod
    def inbound_rule(rule_data: Dict[str, Any]) -> bool:
        return IPTablesManager._add_rule(
            protocol=rule_data['protocol'],
            port=rule_data.get('port'),
            action=rule_data.get('action', 'ACCEPT'),
            chain="INPUT",
            ip=rule_data.get('source_ip'),
            table=rule_data.get('table', 'filter'),
            extra=rule_data.get('extra')
        )

    @staticmethod
    def outbound_rule(rule_data: Dict[str, Any]) -> bool:
        return IPTablesManager._add_rule(
            protocol=rule_data['protocol'],
            port=rule_data.get('port'),
            action=rule_data.get('action', 'DROP'),
            chain="OUTPUT",
            ip=rule_data.get('destination_ip'),
            table=rule_data.get('table', 'filter'),
            extra=rule_data.get('extra')
        )

    @staticmethod
    def get_rules() -> Dict[str, Any]:
        tables = ['filter', 'nat', 'mangle', 'raw']
        all_rules = {}

        for table_name in tables:
            try:
                table = iptc.Table(table_name)
                table_rules = {}

                for chain in table.chains:
                    chain_rules = []
                    for rule in chain.rules:
                        rule_dict = {
                            'protocol': rule.protocol,
                            'src': rule.src,
                            'dst': rule.dst,
                            'in_interface': rule.in_interface,
                            'out_interface': rule.out_interface,
                            'target': rule.target.name if rule.target else None,
                            'matches': [
                                {
                                    'name': match.name,
                                    'dport': match.dport if hasattr(match, 'dport') else None,
                                    'sport': match.sport if hasattr(match, 'sport') else None
                                }
                                for match in rule.matches
                            ]
                        }
                        chain_rules.append(rule_dict)

                    table_rules[chain.name] = {
                        'policy': chain.policy if hasattr(chain, 'policy') else None,
                        'rules': chain_rules
                    }

                all_rules[table_name] = table_rules
            except iptc.ip4tc.IPTCError as e:
                logger.error(f"Error accessing {table_name} table: {e}")
                all_rules[table_name] = {"error": str(e)}

        return all_rules