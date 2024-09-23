from flask import Flask, request, jsonify
from flask_socketio import SocketIO
from functools import wraps
import logging
import os
from dotenv import load_dotenv
from typing import Dict, Any, List
from iptables_manager import IPTablesManager
from system_manager import SystemManager
from application_manager import ApplicationManager
from network_manager import NetworkManager
from system_monitor import SystemMonitor
from log_manager import LogManager
from backup_manager import BackupManager
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.middleware.proxy_fix import ProxyFix


load_dotenv()

app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)
socketio = SocketIO(app, cors_allowed_origins=os.getenv('CORS_ORIGINS', '*').split(','))

# Setup rate limiting
limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

# Configure logging
logging.basicConfig(
    filename=os.getenv('LOG_FILE', 'agent.log'),
    level=logging.getLevelName(os.getenv('LOG_LEVEL', 'INFO')),
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

iptables_manager = IPTablesManager()
system_manager = SystemManager()
app_manager = ApplicationManager()
network_manager = NetworkManager()
system_monitor = SystemMonitor()
log_manager = LogManager()
backup_manager = BackupManager()

def require_api_key(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        api_key = request.headers.get('X-API-Key')
        if api_key != os.getenv('API_KEY'):
            logger.warning(f"Unauthorized access attempt from IP: {request.remote_addr}")
            return jsonify({'error': 'Unauthorized'}), 401
        return f(*args, **kwargs)
    return decorated_function


@app.route('/')
@limiter.exempt
def agent_status():
    return "<h1>Agent is running</h1>"

def validate_rule_data(rule_data: Dict[str, Any], required_fields: list) -> Dict[str, Any]:
    errors = {}
    for field in required_fields:
        if field not in rule_data:
            errors[field] = f"Missing required field: {field}"
        elif field == 'port' and not isinstance(rule_data[field], int):
            errors[field] = "Port must be an integer"
        elif field == 'protocol' and rule_data[field] not in ['tcp', 'udp']:
            errors[field] = "Protocol must be 'tcp' or 'udp'"
    return errors

@app.route('/apply-rules', methods=['POST'])
@require_api_key
def apply_rules():
    rules = request.json.get('rules', [])
    if not rules:
        return jsonify({'error': 'No rules provided'}), 400

    results = []
    for rule in rules:
        errors = validate_rule_data(rule, ['protocol', 'port', 'action'])
        if errors:
            results.append({'rule': rule, 'success': False, 'errors': errors})
        else:
            try:
                success = iptables_manager._add_rule(
                    protocol=rule['protocol'],
                    port=rule['port'],
                    action=rule['action'],
                    chain=rule.get('chain', 'INPUT'),
                    ip=rule.get('source_ip') or rule.get('destination_ip'),
                    table=rule.get('table', 'filter')
                )
                results.append({'rule': rule, 'success': success})
            except Exception as e:
                results.append({'rule': rule, 'success': False, 'error': str(e)})

    return jsonify({'status': 'completed', 'results': results})

@app.route('/inbound_rule', methods=['POST'])
@require_api_key
def inbound_rules():
    inbound_rule_data = request.json.get('inbound_rule')
    if not inbound_rule_data:
        return jsonify({'error': 'No inbound rule data provided'}), 400

    errors = validate_rule_data(inbound_rule_data, ['protocol', 'port'])
    if errors:
        return jsonify({'error': errors}), 400

    try:
        success = iptables_manager.inbound_rule(inbound_rule_data)
        return jsonify({
            'status': 'success' if success else 'failed',
            'message': 'Inbound rule added successfully' if success else 'Failed to add inbound rule'
        })
    except Exception as e:
        logger.error(f"Error in inbound_rules: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/outbound_rule', methods=['POST'])
@require_api_key
def outbound_rules():
    outbound_rule_data = request.json.get('outbound_rule')
    if not outbound_rule_data:
        return jsonify({'error': 'No outbound rule data provided'}), 400

    errors = validate_rule_data(outbound_rule_data, ['protocol', 'port'])
    if errors:
        return jsonify({'error': errors}), 400

    try:
        success = iptables_manager.outbound_rule(outbound_rule_data)
        return jsonify({
            'status': 'success' if success else 'failed',
            'message': 'Outbound rule added successfully' if success else 'Failed to add outbound rule'
        })
    except Exception as e:
        logger.error(f"Error in outbound_rules: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/iptables_rules')
@require_api_key
def get_iptables_rules_route():
    try:
        rules = iptables_manager.get_rules()
        return jsonify({
            'status': 'success',
            'rules': rules
        })
    except Exception as e:
        logger.error(f"Unexpected error in get_iptables_rules route: {e}")
        return jsonify({
            'status': 'error',
            'message': 'An unexpected error occurred while retrieving iptables rules',
            'error': str(e)
        }), 500

@app.route('/processes')
@require_api_key
def get_processes():
    return jsonify(system_manager.get_running_processes())

@app.route('/add_user', methods=['POST'])
@require_api_key
def add_user_route():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    groups = data.get('groups', [])

    if not username or not password:
        return jsonify({'error': 'Username and password are required'}), 400

    success, message = system_manager.add_user(username, password, groups)
    return jsonify({'message': message}), 200 if success else 400

@app.route('/remove_user', methods=['POST'])
@require_api_key
def remove_user_route():
    username = request.json.get('username')
    if not username:
        return jsonify({'error': 'Username is required'}), 400

    success, message = system_manager.remove_user(username)
    return jsonify({'message': message}), 200 if success else 400

@app.route('/users', methods=['GET'])
@require_api_key
def get_users_route():
    return jsonify({'users': system_manager.get_non_default_users()})

@app.route('/applications')
@require_api_key
def get_applications():
    try:
        applications = app_manager.get_installed_applications()
        return jsonify({
            'status': 'success',
            'count': len(applications),
            'applications': applications
        })
    except Exception as e:
        logger.error(f"Error in get_applications route: {e}")
        return jsonify({
            'status': 'error',
            'message': 'An error occurred while retrieving installed applications',
            'error': str(e)
        }), 500

@app.route('/application/<app_name>', methods=['GET'])
@require_api_key
def get_application_details(app_name):
    try:
        details = app_manager.get_application_details(app_name)
        return jsonify({
            'status': 'success',
            'application': app_name,
            'details': details
        })
    except Exception as e:
        logger.error(f"Error in get_application_details route: {e}")
        return jsonify({
            'status': 'error',
            'message': f'An error occurred while retrieving details for {app_name}',
            'error': str(e)
        }), 500

@app.route('/application/<app_name>/start', methods=['POST'])
@require_api_key
def start_application(app_name):
    try:
        success, message = app_manager.start_application(app_name)
        return jsonify({
            'status': 'success' if success else 'failed',
            'message': message
        })
    except Exception as e:
        logger.error(f"Error in start_application route: {e}")
        return jsonify({
            'status': 'error',
            'message': f'An error occurred while starting {app_name}',
            'error': str(e)
        }), 500

@app.route('/application/<app_name>/stop', methods=['POST'])
@require_api_key
def stop_application(app_name):
    try:
        success, message = app_manager.stop_application(app_name)
        return jsonify({
            'status': 'success' if success else 'failed',
            'message': message
        })
    except Exception as e:
        logger.error(f"Error in stop_application route: {e}")
        return jsonify({
            'status': 'error',
            'message': f'An error occurred while stopping {app_name}',
            'error': str(e)
        }), 500


@app.route('/network/usage', methods=['GET'])
@require_api_key
def get_network_usage():
    try:
        usage = network_manager.get_network_usage()
        return jsonify({
            'status': 'success',
            'usage': usage
        })
    except Exception as e:
        logger.error(f"Error in get_network_usage route: {e}")
        return jsonify({
            'status': 'error',
            'message': 'An error occurred while retrieving network usage',
            'error': str(e)
        }), 500

@app.route('/network/open_ports', methods=['GET'])
@require_api_key
def get_open_ports():
    try:
        ports = network_manager.get_open_ports()
        return jsonify({
            'status': 'success',
            'open_ports': ports
        })
    except Exception as e:
        logger.error(f"Error in get_open_ports route: {e}")
        return jsonify({
            'status': 'error',
            'message': 'An error occurred while retrieving open ports',
            'error': str(e)
        }), 500




@app.route('/system/user_groups/<username>', methods=['GET'])
@require_api_key
def get_user_groups(username):
    try:
        groups = system_manager.get_user_groups(username)
        return jsonify({
            'status': 'success',
            'username': username,
            'groups': groups
        })
    except Exception as e:
        logger.error(f"Error in get_user_groups route: {e}")
        return jsonify({
            'status': 'error',
            'message': f'An error occurred while retrieving groups for user {username}',
            'error': str(e)
        }), 500

@app.route('/system/user_privileges/<username>', methods=['GET'])
@require_api_key
def get_user_privileges(username):
    try:
        privileges = system_manager.get_user_privileges(username)
        return jsonify({
            'status': 'success',
            'username': username,
            'privileges': privileges
        })
    except Exception as e:
        logger.error(f"Error in get_user_privileges route: {e}")
        return jsonify({
            'status': 'error',
            'message': f'An error occurred while retrieving privileges for user {username}',
            'error': str(e)
        }), 500



@socketio.on('connect')
def handle_connect():
    socketio.start_background_task(send_system_data)

if __name__ == "__main__":
    socketio.run(
        app,
        host=os.getenv('HOST', '0.0.0.0'),
        port=int(os.getenv('PORT', 5000)),
        debug=os.getenv('DEBUG', 'False').lower() == 'true'
    )
