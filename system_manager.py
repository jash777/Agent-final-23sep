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

class SystemManager:
    @staticmethod
    def get_running_processes() -> List[Dict[str, Any]]:
        try:
            return [
                {
                    'pid': proc.info['pid'],
                    'name': proc.info['name'],
                    'username': proc.info['username'],
                    'cpu_percent': proc.cpu_percent(),
                    'memory_percent': proc.memory_percent(),
                    'status': proc.status(),
                    'create_time': datetime.fromtimestamp(proc.create_time()).isoformat()
                }
                for proc in psutil.process_iter(['pid', 'name', 'username'])
            ]
        except Exception as e:
            logger.error(f"Error getting running processes: {e}")
            return []

    @staticmethod
    def add_user(username: str, password: str, groups: Optional[List[str]] = None) -> Tuple[bool, str]:
        if not re.match(r'^[a-z_][a-z0-9_-]*[$]?$', username):
            return False, "Invalid username format"

        if len(password) < 8:
            return False, "Password must be at least 8 characters long"

        try:
            pwd.getpwnam(username)
            return False, f"User {username} already exists"
        except KeyError:
            pass

        try:
            salt = os.urandom(6).hex()
            hashed_password = crypt.crypt(password, f'$6${salt}$')

            uids = [u.pw_uid for u in pwd.getpwall()]
            next_uid = max(uids) + 1 if uids else 1000

            subprocess.run(['useradd', '-m', '-s', '/bin/bash', '-u', str(next_uid), username], check=True)
            subprocess.run(['chpasswd'], input=f"{username}:{password}", universal_newlines=True, check=True)

            if groups:
                for group in groups:
                    if not re.match(r'^[a-z_][a-z0-9_-]*[$]?$', group):
                        logger.warning(f"Invalid group name format: {group}")
                        continue
                    try:
                        subprocess.run(['usermod', '-aG', group, username], check=True)
                    except subprocess.CalledProcessError as e:
                        logger.error(f"Error adding user {username} to group {group}: {e}")

            logger.info(f"User {username} added successfully")
            return True, f"User {username} added successfully"
        except subprocess.CalledProcessError as e:
            logger.error(f"Error adding user {username}: {e}")
            return False, f"Error adding user {username}: {e}"
        except Exception as e:
            logger.error(f"Unexpected error adding user {username}: {e}")
            return False, f"Unexpected error adding user {username}: {e}"

    @staticmethod
    def remove_user(username: str) -> Tuple[bool, str]:
        if not re.match(r'^[a-z_][a-z0-9_-]*[$]?$', username):
            return False, "Invalid username format"

        try:
            pwd.getpwnam(username)
        except KeyError:
            return False, f"User {username} does not exist"

        try:
            subprocess.run(['userdel', '-r', username], check=True)
            logger.info(f"User {username} removed successfully")
            return True, f"User {username} removed successfully"
        except subprocess.CalledProcessError as e:
            logger.error(f"Error removing user {username}: {e}")
            return False, f"Error removing user {username}: {e}"
        except Exception as e:
            logger.error(f"Unexpected error removing user {username}: {e}")
            return False, f"Unexpected error removing user {username}: {e}"

    @staticmethod
    @lru_cache(maxsize=None)
    def get_user_groups(username: str) -> List[str]:
        try:
            groups = [g.gr_name for g in grp.getgrall() if username in g.gr_mem]
            gid = pwd.getpwnam(username).pw_gid
            groups.append(grp.getgrgid(gid).gr_name)
            return list(set(groups))
        except KeyError:
            logger.error(f"User {username} not found")
            return []
        except Exception as e:
            logger.error(f"Error getting groups for user {username}: {e}")
            return []

    @staticmethod
    @lru_cache(maxsize=None)
    def get_user_privileges(username: str) -> List[str]:
        privileges = []
        try:
            if 'sudo' in SystemManager.get_user_groups(username):
                privileges.append('sudo')
            user_info = pwd.getpwnam(username)
            if user_info.pw_shell not in ['/usr/sbin/nologin', '/bin/false']:
                privileges.append('login')
            if os.path.exists('/etc/pam.d/su'):
                with open('/etc/pam.d/su', 'r') as f:
                    if any('pam_wheel.so' in line for line in f) and 'wheel' in SystemManager.get_user_groups(username):
                        privileges.append('su to root')
            return privileges
        except KeyError:
            logger.error(f"User {username} not found")
            return []
        except Exception as e:
            logger.error(f"Error getting privileges for user {username}: {e}")
            return []

    @staticmethod
    def get_non_default_users() -> List[Dict[str, Any]]:
        try:
            non_default_users = []
            for user in pwd.getpwall():
                if 1000 <= user.pw_uid < 65534 and user.pw_shell not in ['/usr/sbin/nologin', '/bin/false']:
                    user_info = {
                        'username': user.pw_name,
                        'uid': user.pw_uid,
                        'gid': user.pw_gid,
                        'home': user.pw_dir,
                        'shell': user.pw_shell,
                        'groups': SystemManager.get_user_groups(user.pw_name),
                        'privileges': SystemManager.get_user_privileges(user.pw_name)
                    }
                    try:
                        sp = spwd.getspnam(user.pw_name)
                        user_info.update({
                            'last_password_change': sp.sp_lstchg,
                            'min_password_age': sp.sp_min,
                            'max_password_age': sp.sp_max
                        })
                    except KeyError:
                        logger.warning(f"Shadow password entry not found for user {user.pw_name}")
                    except PermissionError:
                        logger.warning(f"Permission denied when accessing shadow password for user {user.pw_name}")
                    non_default_users.append(user_info)
            return non_default_users
        except Exception as e:
            logger.error(f"Error getting non-default users: {e}")
            return []