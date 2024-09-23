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

class ApplicationManager:
    @staticmethod
    def get_installed_applications() -> List[str]:
        logger.info("Fetching installed applications")
        applications = set()

        def add_to_applications(app: str) -> None:
            if app and len(app) > 1 and not app.startswith('.'):
                applications.add(app.strip())

        def scan_desktop_files() -> None:
            desktop_dirs = ['/usr/share/applications', '/usr/local/share/applications', 
                            os.path.expanduser('~/.local/share/applications')]
            for desktop_dir in desktop_dirs:
                try:
                    for desktop_file in Path(desktop_dir).glob('*.desktop'):
                        try:
                            with open(desktop_file, 'r', errors='ignore') as f:
                                content = f.read()
                                match = re.search(r'^Name=(.+)$', content, re.MULTILINE)
                                if match:
                                    add_to_applications(match.group(1))
                        except Exception as e:
                            logger.error(f"Error reading desktop file {desktop_file}: {e}")
                except Exception as e:
                    logger.error(f"Error scanning desktop files in {desktop_dir}: {e}")

        def scan_package_manager(command: List[str], start_index: int = 0) -> None:
            try:
                result = subprocess.run(command, capture_output=True, text=True, timeout=60)
                if result.returncode != 0:
                    logger.error(f"Package manager command {command[0]} failed with return code {result.returncode}")
                    return
                for line in result.stdout.split('\n')[start_index:]:
                    parts = line.split()
                    if len(parts) >= 2:
                        add_to_applications(parts[1] if command[0] == 'dpkg' else parts[0])
            except subprocess.TimeoutExpired:
                logger.error(f"Timeout while executing {command[0]}")
            except Exception as e:
                logger.error(f"Error using {command[0]}: {e}")

        def scan_bin_directories() -> None:
            for bin_dir in ['/usr/bin', '/usr/local/bin', '/opt', '/snap/bin']:
                try:
                    for root, _, files in os.walk(bin_dir):
                        for file in files:
                            file_path = os.path.join(root, file)
                            if os.path.isfile(file_path) and os.access(file_path, os.X_OK):
                                add_to_applications(file)
                except Exception as e:
                    logger.error(f"Error scanning {bin_dir}: {e}")

        def list_system_services() -> None:
            try:
                result = subprocess.run(['systemctl', 'list-units', '--type=service', '--all', '--no-pager'], 
                                        capture_output=True, text=True, timeout=60)
                if result.returncode != 0:
                    logger.error(f"systemctl command failed with return code {result.returncode}")
                    return
                for line in result.stdout.split('\n')[1:]:
                    parts = line.split()
                    if len(parts) >= 5:
                        service_name = parts[0].replace('.service', '')
                        add_to_applications(service_name)
            except subprocess.TimeoutExpired:
                logger.error("Timeout while listing system services")
            except Exception as e:
                logger.error(f"Error listing system services: {e}")

        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = [
                executor.submit(scan_desktop_files),
                executor.submit(scan_package_manager, ['dpkg', '-l'], 5),
                executor.submit(scan_package_manager, ['rpm', '-qa']),
                executor.submit(scan_bin_directories),
                executor.submit(list_system_services)
            ]
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    logger.error(f"Error in one of the application scanning tasks: {e}")

        return sorted(list(applications))

    @staticmethod
    def get_application_details(app_name: str) -> Dict[str, Any]:
        logger.info(f"Getting details for application: {app_name}")
        details = {}
        try:
            # Try to get details using 'which' command
            which_result = subprocess.run(['which', app_name], capture_output=True, text=True, timeout=10)
            if which_result.returncode == 0:
                details['path'] = which_result.stdout.strip()

            # Try to get version information
            version_cmds = [
                [app_name, '--version'],
                [app_name, '-V'],
                ['dpkg', '-s', app_name],
                ['rpm', '-q', app_name]
            ]
            for cmd in version_cmds:
                try:
                    version_result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                    if version_result.returncode == 0:
                        version_match = re.search(r'version\s*:?\s*([\d\.]+)', version_result.stdout, re.IGNORECASE)
                        if version_match:
                            details['version'] = version_match.group(1)
                            break
                except subprocess.TimeoutExpired:
                    logger.warning(f"Timeout while getting version for {app_name} using {cmd}")
                except Exception as e:
                    logger.error(f"Error getting version for {app_name} using {cmd}: {e}")

            # Get process information if the application is running
            for proc in psutil.process_iter(['name', 'pid', 'status', 'create_time', 'cpu_percent', 'memory_percent']):
                if proc.info['name'] == app_name:
                    details.update({
                        'status': proc.info['status'],
                        'pid': proc.info['pid'],
                        'cpu_usage': proc.info['cpu_percent'],
                        'memory_usage': proc.info['memory_percent'],
                        'start_time': datetime.fromtimestamp(proc.info['create_time']).isoformat()
                    })
                    break

            # Check if it's a system service
            service_result = subprocess.run(['systemctl', 'is-active', app_name], capture_output=True, text=True, timeout=10)
            if service_result.returncode == 0:
                details['service_status'] = service_result.stdout.strip()

        except Exception as e:
            logger.error(f"Error getting details for application {app_name}: {e}")

        return details

    @staticmethod
    def start_application(app_name: str) -> Tuple[bool, str]:
        try:
            # First, check if it's a system service
            service_result = subprocess.run(['systemctl', 'is-active', app_name], capture_output=True, text=True, timeout=10)
            if service_result.returncode == 0:
                start_result = subprocess.run(['sudo', 'systemctl', 'start', app_name], capture_output=True, text=True, timeout=30)
                if start_result.returncode == 0:
                    return True, f"Service {app_name} started successfully"
                else:
                    return False, f"Error starting service {app_name}: {start_result.stderr}"

            # If not a service, try to start as a regular application
            process = subprocess.Popen([app_name], start_new_session=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            time.sleep(2)  # Wait for 2 seconds to check if the process is still running
            if process.poll() is None:
                return True, f"Application {app_name} started successfully"
            else:
                _, stderr = process.communicate(timeout=10)
                return False, f"Error starting application {app_name}: {stderr.decode('utf-8')}"
        except subprocess.TimeoutExpired:
            return False, f"Timeout while starting application {app_name}"
        except Exception as e:
            logger.error(f"Error starting application {app_name}: {e}")
            return False, f"Error starting application {app_name}: {str(e)}"

    @staticmethod
    def stop_application(app_name: str) -> Tuple[bool, str]:
        try:
            # First, check if it's a system service
            service_result = subprocess.run(['systemctl', 'is-active', app_name], capture_output=True, text=True, timeout=10)
            if service_result.returncode == 0:
                stop_result = subprocess.run(['sudo', 'systemctl', 'stop', app_name], capture_output=True, text=True, timeout=30)
                if stop_result.returncode == 0:
                    return True, f"Service {app_name} stopped successfully"
                else:
                    return False, f"Error stopping service {app_name}: {stop_result.stderr}"

            # If not a service, try to stop as a regular application
            for proc in psutil.process_iter(['name', 'pid']):
                if proc.info['name'] == app_name:
                    proc.terminate()
                    try:
                        proc.wait(timeout=10)
                        return True, f"Application {app_name} stopped successfully"
                    except psutil.TimeoutExpired:
                        proc.kill()
                        return True, f"Application {app_name} forcefully killed"

            return False, f"Application {app_name} not found running"
        except Exception as e:
            logger.error(f"Error stopping application {app_name}: {e}")
            return False, f"Error stopping application {app_name}: {str(e)}"

    @staticmethod
    def get_application_logs(app_name: str, lines: int = 100) -> Tuple[bool, str]:
        logger.info(f"Fetching logs for application: {app_name}")        
        try:
            log_locations = [
                f"/var/log/{app_name}.log",
                f"/var/log/{app_name}/{app_name}.log",
                f"/var/log/syslog"
            ]
            
            for log_file in log_locations:
                if os.path.exists(log_file):
                    with open(log_file, 'r') as f:
                        logs = f.readlines()[-lines:]
                        return True, ''.join(logs)
            
            # If no log file found, try journalctl
            journalctl_result = subprocess.run(['journalctl', '-u', app_name, '-n', str(lines)], 
                                               capture_output=True, text=True, timeout=30)
            if journalctl_result.returncode == 0:
                return True, journalctl_result.stdout

            return False, f"No logs found for application {app_name}"
        except Exception as e:
            logger.error(f"Error retrieving logs for application {app_name}: {e}")
            return False, f"Error retrieving logs for application {app_name}: {str(e)}"