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



class NetworkManager:
    @staticmethod
    def get_network_interfaces() -> List[Dict[str, Any]]:
        interfaces = []
        try:
            for interface, addrs in psutil.net_if_addrs().items():
                interface_info = {'name': interface, 'addresses': []}
                for addr in addrs:
                    if addr.family == socket.AF_INET:
                        interface_info['addresses'].append({
                            'ip': addr.address,
                            'netmask': addr.netmask,
                            'broadcast': addr.broadcast
                        })
                interfaces.append(interface_info)
        except Exception as e:
            logger.error(f"Error getting network interfaces: {e}")
        return interfaces

    @staticmethod
    def get_network_usage() -> Dict[str, Dict[str, int]]:
        try:
            return psutil.net_io_counters(pernic=True)
        except Exception as e:
            logger.error(f"Error getting network usage: {e}")
            return {}

    @staticmethod
    def get_open_ports() -> List[Dict[str, Any]]:
        open_ports = []
        try:
            for conn in psutil.net_connections():
                if conn.status == 'LISTEN':
                    open_ports.append({
                        'port': conn.laddr.port,
                        'ip': conn.laddr.ip,
                        'pid': conn.pid,
                        'program': psutil.Process(conn.pid).name() if conn.pid else None
                    })
        except Exception as e:
            logger.error(f"Error getting open ports: {e}")
        return open_ports

