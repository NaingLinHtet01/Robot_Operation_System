import warnings
warnings.filterwarnings("ignore", category=DeprecationWarning)
warnings.filterwarnings("ignore", category=UserWarning)
warnings.filterwarnings("ignore", category=FutureWarning)

from flask import Flask, request, jsonify
from flask_cors import CORS 
import paramiko
from io import StringIO
import winrm
import re
import os
from werkzeug.utils import secure_filename
import smtplib
import random
import string
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

app = Flask(__name__)
CORS(app)

# Configuration
UPLOAD_FOLDER = './uploads'
ALLOWED_EXTENSIONS = {'xls', 'xlsx'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
verification_codes = {}

# For Mail
SMTP_SERVER = 'smtp.gmail.com'  
SMTP_PORT = smtp_port
SMTP_USERNAME = 'example@gmail.com'  
SMTP_PASSWORD = 'app_password'    
SUPERVISOR_EMAIL = 'supervisor@gmail.com'  

SUDO_COMMAND_PATTERNS = [
    # System management
    r'^apt(-get)?\s+(install|remove|purge|update|upgrade|dist-upgrade)',
    r'^yum\s+(install|remove|update|upgrade)',
    r'^dnf\s+(install|remove|update|upgrade)',
    r'^zypper\s+(install|remove|update)',
    r'^pacman\s+(-S|-R|-U)',
    r'^shutdown',
    r'^reboot',
    r'^halt',
    r'^poweroff',
    r'^init\s+[06]',
    # Service management
    r'^systemctl\s+(start|stop|restart|enable|disable|reload)\s+',
    r'^service\s+\w+\s+(start|stop|restart|reload)',
    # Network configuration
    r'^ifconfig\s+(\w+\s+)?(up|down|add|del)',
    r'^ip\s+(addr|link|route)\s+(add|del|change)',
    r'^route\s+(add|del)',
    r'^iptables',
    r'^ufw\s+',
    # User/group management
    r'^useradd',
    r'^userdel',
    r'^usermod',
    r'^groupadd',
    r'^groupdel',
    r'^groupmod',
    # File permissions and ownership
    r'^chown\s+(\w+:)?\w+\s+[^\-]',
    r'^chgrp\s+\w+\s+[^\-]',
    # Mount operations
    r'^mount\s+',
    r'^umount\s+',
    # Process management (certain operations)
    r'^kill\s+(-9\s+)?\d+',
    # Package and system configuration
    r'^dpkg\s+(-i|--install|-r|--remove)',
    r'^rpm\s+(-i|-U|-e)',
    # File operations in system directories
    r'^(cp|mv|rm)\s+.*(/usr/bin/|/usr/sbin/|/usr/lib/|/etc/|/var/log/|/boot/)',
    r'^dd\s+if=.*\s+of=/dev/',
    # Editing system files
    r'^(vim|vi|nano|emacs)\s+.*(/etc/|/usr/lib/|/var/log/)',
]

SENSITIVE_LINUX_COMMANDS = [
    r'^shutdown',
    r'^reboot',
    r'^halt',
    r'^poweroff',
    r'^init\s+[06]',
    # r'^rm\s+-rf\s+/($|\s)',
    r'^dd\s+if=.*\s+of=/dev/',
]

SENSITIVE_WINDOWS_COMMANDS = [
    r'^shutdown',
    r'^restart-computer',
    r'^stop-computer',
    r'^logoff',
    r'^psshutdown',
    r'^taskkill',
    r'^net\s+stop',
    # r'^Remove-Item\s+-Recurse\s+-Force\s+[A-Z]:\\',
]

def generate_verification_code():
    """Generate a random 6-word code with numbers and letters"""
    words = []
    for _ in range(3):
        # Add random word (3 letters)
        words.append(''.join(random.choices(string.ascii_lowercase, k=3)))
        # Add random number (2 digits)
        words.append(str(random.randint(10, 99)))
    
    # Shuffle and join
    random.shuffle(words)
    return '-'.join(words)

def send_verification_email(target_ip, commands, verification_code):
    """Send verification email to supervisor"""
    try:
        # Create message
        msg = MIMEMultipart()
        msg['From'] = SMTP_USERNAME
        msg['To'] = SUPERVISOR_EMAIL
        msg['Subject'] = f"Sensitive Command Execution Request for {target_ip}"
        
        # Create email body
        body = f"""
        Robot Operation System [Sensitive Command Alert]
        #######################
        Sensitive commands are about to be executed on {target_ip}.
        
        Commands:
        {chr(10).join(['- ' + cmd for cmd in commands])}
        
        Verification Code: {verification_code}
        
        Please provide this code to the user to allow command execution.
        """
        
        msg.attach(MIMEText(body, 'plain'))
        
        # Send email
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(SMTP_USERNAME, SMTP_PASSWORD)
        server.send_message(msg)
        server.quit()
        
        return True
    except Exception as e:
        print(f"Error sending email: {e}")
        return False
    
def is_sensitive_command(command, os_type):
    """Check if a command is sensitive based on OS"""
    patterns = SENSITIVE_LINUX_COMMANDS if os_type == 'Linux' else SENSITIVE_WINDOWS_COMMANDS
    
    for pattern in patterns:
        if re.search(pattern, command, re.IGNORECASE):
            return True
    return False



def is_sudo_command(command):
    """Check if a command typically requires superuser privileges"""
    for pattern in SUDO_COMMAND_PATTERNS:
        if re.search(pattern, command, re.IGNORECASE):
            return True
    return False

def check_user_privileges_ssh(ssh_client):
    """Check if the current SSH user has superuser privileges"""
    try:
        # root?
        stdin, stdout, stderr = ssh_client.exec_command('echo $USER')
        current_user = stdout.read().decode().strip()
        if current_user == 'root':
            return True
        
    
        stdin, stdout, stderr = ssh_client.exec_command('sudo -n true 2>/dev/null && echo "has_sudo" || echo "no_sudo"')
        sudo_check = stdout.read().decode().strip()
        return sudo_check == 'has_sudo'
        
    except Exception:
        return False

def check_user_privileges_windows(session):
    """Check if the current Windows user has administrator privileges"""
    try:
        # Check if user is in Administrators group
        result = session.run_ps(
            '$currentUser = [Security.Principal.WindowsIdentity]::GetCurrent();'
            '$principal = New-Object Security.Principal.WindowsPrincipal($currentUser);'
            '$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)'
        )
        
        if result.status_code == 0:
            is_admin = result.std_out.decode().strip().lower()
            return is_admin == 'true'
        return False
        
    except Exception:
        return False

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def create_ssh_client(ip, username, password):
    """Create SSH client connection"""
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(ip, username=username, password=password)
    return client

def detect_os(ip, username, password):
    """Detect the operating system of the target"""
    try:
        # First try SSH (Linux/Unix)
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(ip, username=username, password=password, timeout=10)
        stdin, stdout, stderr = client.exec_command('uname -s')
        os_type = stdout.read().decode().strip()
        client.close()
        
        if os_type:
            return 'Linux', 'ssh'
        
    except (paramiko.AuthenticationException, paramiko.SSHException, Exception):
        pass
    
    
    winrm_ports = [
        (5985, 'http'),   # Default HTTP port
        (5986, 'https'),  # Default HTTPS port
        (47001, 'http'),  # Sometimes?Maybe?just some common port used in most system 
    ]
    
    for port, protocol in winrm_ports:
        try:
            session = winrm.Session(
                f'{ip}:{port}', 
                auth=(username, password), 
                transport='ntlm',
                server_cert_validation='ignore' 
            )
            result = session.run_cmd('echo %OS%')
            if result.status_code == 0 and 'Windows' in result.std_out.decode():
                return 'Windows', 'winrm'
        except:
            continue
    
    #For trying SSH if OpenSSH is installed
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(ip, port=2222, username=username, password=password, timeout=10)
        stdin, stdout, stderr = client.exec_command('echo %OS%')
        os_output = stdout.read().decode().strip()
        client.close()
        
        if os_output and 'Windows' in os_output:
            return 'Windows', 'ssh'
            
    except Exception:
        pass
    
    return 'Unknown', None

def create_connection(ip, username, password, connection_type):
    # ssh for linux, winrm for windows
    if connection_type == 'ssh':
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(ip, username=username, password=password)
        return client
    elif connection_type == 'winrm':
        try:
            # Trying different authentication methods
            session = winrm.Session(ip, auth=(username, password), transport='ntlm')
            result = session.run_cmd('echo test')
            if result.status_code == 0:
                return session
        except:
            try:
                # Try with basic auth
                session = winrm.Session(ip, auth=(username, password), transport='basic')
                result = session.run_cmd('echo test')
                if result.status_code == 0:
                    return session
            except:
                try:
                    # Try with kerberos
                    session = winrm.Session(ip, auth=(username, password), transport='kerberos')
                    result = session.run_cmd('echo test')
                    if result.status_code == 0:
                        return session
                except:
                    pass
        return None
    return None

def validate_command_windows(session, command, has_admin_privs):
    """Validate command on Windows system with privilege check"""
    try:
        # Check if command requires admin privileges
        if not has_admin_privs and is_sudo_command(command):
            return False, ["This command requires administrator privileges"]
        
        #checking if the command exists in PATH or is a built-in
        result = session.run_cmd(f'where {command.split()[0]}')
        
        if result.status_code == 0:
            return True, []
        else:
            #Check if it's a PowerShell cmdlet
            ps_result = session.run_ps(f'Get-Command {command.split()[0]} -ErrorAction SilentlyContinue')
            if ps_result.status_code == 0:
                return True, []
            
            #For suggestions
            suggestions = get_windows_command_suggestions(session, command)
            return False, suggestions
            
    except Exception as e:
        return False, [f"Validation error: {str(e)}"]

def get_windows_command_suggestions(session, invalid_command):
    """Get similar commands for Windows"""
    try:
        # Get list of available commands
        result = session.run_cmd('where *')
        all_commands = []
        if result.status_code == 0:
            all_commands = result.std_out.decode().split('\r\n')
        
        # Also get PowerShell cmdlets
        ps_result = session.run_ps('Get-Command -CommandType Cmdlet,Function | Select-Object -ExpandProperty Name')
        if ps_result.status_code == 0:
            ps_commands = ps_result.std_out.decode().split('\r\n')
            all_commands.extend(ps_commands)
        
        command_base = invalid_command.split()[0]
        import difflib
        suggestions = difflib.get_close_matches(command_base, all_commands, n=3, cutoff=0.3)
        
        return suggestions if suggestions else ["Command not found in PATH"]
        
    except Exception:
        return ["Command not found"]
    
def execute_command_ssh(ssh_client, command):
    """Execute command on SSH connection"""
    try:
        stdin, stdout, stderr = ssh_client.exec_command(command)
        output = stdout.read().decode().strip()
        error = stderr.read().decode().strip()
        
        if error and not output:
            return error
        return output if output else "Executed successfully"
    except Exception as e:
        return str(e)

def execute_command_windows(session, command):
    """Execute command on Windows via WinRM"""
    try:
        # Try as CMD command
        result = session.run_cmd(command)
        
        if result.status_code == 0:
            return result.std_out.decode().strip() or "Executed successfully"
        else:
            # Try as PowerShell command
            ps_result = session.run_ps(command)
            if ps_result.status_code == 0:
                return ps_result.std_out.decode().strip() or "Executed successfully"
            else:
                return f"Error: {ps_result.std_err.decode().strip()}"
                
    except Exception as e:
        return f"Execution error: {str(e)}"


def get_command_suggestions(ssh_client, invalid_command):
    """Get similar commands for suggestions with better handling of short commands"""
    try:
        command_base = invalid_command.split()[0]
        
        #common commands
        common_commands = [
            'ls', 'cd', 'rm', 'cp', 'mv', 'mkdir', 'touch', 'cat', 'grep',
            'find', 'chmod', 'chown', 'ps', 'kill', 'tar', 'ssh', 'scp',
            'wget', 'curl', 'ping', 'ifconfig', 'netstat', 'df', 'du'
        ]
        
        # Check for exact prefix matches in common commands
        prefix_matches = [cmd for cmd in common_commands if cmd.startswith(command_base)]
        if prefix_matches:
            return prefix_matches[:3]  # Return max 3 prefix matches
        
        stdin, stdout, stderr = ssh_client.exec_command('compgen -c')
        all_commands = stdout.read().decode().split()
        
        if len(command_base) <= 3:
            prefix_matches = [cmd for cmd in all_commands if cmd.startswith(command_base)]
            if prefix_matches:
                return prefix_matches[:3]
        
        
        import difflib
        
        # Adjust cutoff based on command length
        cutoff = 0.5 if len(command_base) <= 3 else 0.3
        
        suggestions = difflib.get_close_matches(
            command_base,
            all_commands,
            n=3,
            cutoff=cutoff
        )
        
        
        if not suggestions and len(command_base) > 3:
            suggestions = difflib.get_close_matches(
                command_base,
                all_commands,
                n=3,
                cutoff=0.2
            )
        
        return suggestions
        
    except Exception as e:
        print(f"Error getting suggestions: {e}")
        return []

def validate_command_with_args(ssh_client, full_command, has_sudo_privs):
    """Validate command including arguments for specific commands with privilege check"""
    command_parts = full_command.split()
    if not command_parts:
        return True, []
    
    command_base = command_parts[0]
    
   
    if not has_sudo_privs and is_sudo_command(full_command):
        return False, ["This command requires superuser privileges. Login as root."]
    
    #validate the base command exists
    stdin, stdout, stderr = ssh_client.exec_command(f'type {command_base} || which {command_base}')
    error = stderr.read().decode().strip()
    
    if error:
        suggestions = get_command_suggestions(ssh_client, full_command)
        return False, suggestions
    
    # Check for potential typos
    typo_suggestions = detect_command_typos(command_base, command_parts)
    
    # Now validate arguments for specific commands
    validation_result = validate_command_arguments(ssh_client, command_base, command_parts)
    
    if not validation_result['valid']:
        
        all_suggestions = validation_result.get('suggestions', [])
        if typo_suggestions:
            all_suggestions.append(f"Possible typo? Did you mean: {', '.join(typo_suggestions)}?")
        return False, all_suggestions
    
    
    if typo_suggestions:
        return True, [f"Note: Command valid, but you might have meant: {', '.join(typo_suggestions)}?"]
    
    return True, []

def validate_command_arguments(ssh_client, command_base, command_parts):
    """Validate arguments for specific commands that need it"""
    result = {'valid': True}
    
    if command_base == 'chmod' and len(command_parts) >= 3:
        mode = command_parts[1]
        file_path = command_parts[2]
        
        
        if any(char in mode for char in ['+', '-', '0', '1', '2', '3', '4', '5', '6', '7']):
            
            if len(command_parts) >= 3:
                actual_file_path = command_parts[2]
                stdin, stdout, stderr = ssh_client.exec_command(f'test -e "{actual_file_path}" && echo "exists" || echo "not exists"')
                exists = stdout.read().decode().strip()
                
                if exists == 'not exists':
                    result['valid'] = False
                    result['suggestions'] = [f"File not found: {actual_file_path}"]
        else:
            
            stdin, stdout, stderr = ssh_client.exec_command(f'test -e "{mode}" && echo "exists" || echo "not exists"')
            exists = stdout.read().decode().strip()
            
            if exists == 'not exists':
                result['valid'] = False
                result['suggestions'] = [f"File not found: {mode}"]
    
    
    elif command_base == 'cd' and len(command_parts) >= 2:
        path = command_parts[1]
        
        
        stdin, stdout, stderr = ssh_client.exec_command(f'test -d "{path}" && echo "directory" || echo "not directory"')
        is_directory = stdout.read().decode().strip()
        
        if is_directory == 'not directory':
            
            stdin, stdout, stderr = ssh_client.exec_command(f'test -e "{path}" && echo "file" || echo "not exists"')
            exists = stdout.read().decode().strip()
            
            if exists == 'file':
                result['valid'] = False
                result['suggestions'] = [f"'{path}' is a file, not a directory. Did you mean 'cp' instead of 'cd'?"]
            else:
                result['valid'] = False
                result['suggestions'] = [f"Directory not found: {path}"]
    
    elif command_base == 'cp' and len(command_parts) >= 3:
        source_file = command_parts[1]
        destination = command_parts[2]
        
        
        stdin, stdout, stderr = ssh_client.exec_command(f'test -e "{source_file}" && echo "exists" || echo "not exists"')
        source_exists = stdout.read().decode().strip()
        
        if source_exists == 'not exists':
            result['valid'] = False
            result['suggestions'] = [f"Source file not found: {source_file}"]
        else:
            
            if len(command_parts) > 3:
                
                destination_dir = command_parts[-1]
                stdin, stdout, stderr = ssh_client.exec_command(rf'systemctl list-unit-files --full --all | grep -E "^{service_name}\.(service|socket|target|timer)"')
                is_dest_directory = stdout.read().decode().strip()
                
                if is_dest_directory == 'not directory':
                    result['valid'] = False
                    result['suggestions'] = [f"Destination is not a directory: {destination_dir}"]
    
    elif command_base == 'systemctl' and len(command_parts) >= 3:
        action = command_parts[1]
        service_name = command_parts[2]
        
        if action in ['status', 'start', 'stop', 'restart', 'enable', 'disable']:
            stdin, stdout, stderr = ssh_client.exec_command(rf'systemctl list-unit-files --full --all | grep -E "^{service_name}\.(service|socket|target|timer)"')
            services = stdout.read().decode().strip()
            
            if not services:
                result['valid'] = False
                result['suggestions'] = get_systemctl_service_suggestions(ssh_client, service_name)
    
    elif command_base == 'docker' and len(command_parts) >= 3:
        action = command_parts[1]
        
        if action in ['start', 'stop', 'restart', 'exec', 'logs', 'rm'] and len(command_parts) >= 3:
            container_name = command_parts[2]
            stdin, stdout, stderr = ssh_client.exec_command(f'docker ps -a --filter "name={container_name}" --format "{{.Names}}"')
            containers = stdout.read().decode().strip()
            
            if not containers:
                result['valid'] = False
                result['suggestions'] = get_docker_container_suggestions(ssh_client, container_name)
    
    elif command_base in ['cat', 'rm', 'mv', 'chown'] and len(command_parts) >= 2:
        file_path = command_parts[1]
        
        if not file_path.startswith('-'):
            stdin, stdout, stderr = ssh_client.exec_command(f'test -e "{file_path}" && echo "exists" || echo "not exists"')
            exists = stdout.read().decode().strip()
            
            if exists == 'not exists':
                result['valid'] = False
                result['suggestions'] = [f"File not found: {file_path}"]

    result = validate_command_usage(ssh_client, command_base, command_parts, result)
    
    return result

def validate_command_usage(ssh_client, command_base, command_parts, result):
    """Validate that commands are used with appropriate arguments"""
    
    # Check for common command misuse patterns
    if command_base == 'cd' and len(command_parts) > 2:
        result['valid'] = False
        result['suggestions'] = ["'cd' command only takes one directory argument"]
    
    elif command_base == 'cp' and len(command_parts) < 3:
        result['valid'] = False
        result['suggestions'] = ["'cp' requires both source and destination arguments"]
    
    elif command_base == 'mv' and len(command_parts) < 3:
        result['valid'] = False
        result['suggestions'] = ["'mv' requires both source and destination arguments"]
    
    elif command_base == 'rm' and len(command_parts) < 2:
        result['valid'] = False
        result['suggestions'] = ["'rm' requires at least one file argument"]
    
    return result

def detect_command_typos(command_base, command_parts):
    """Detect common command typos and suggest corrections"""
    common_typos = {
        'cd': ['cp', 'mv', 'ls'],
        'ls': ['cd', 'cp', 'mv'],
        'cp': ['cd', 'mv', 'rm'],
        'mv': ['cp', 'cd', 'rm'],
        'rm': ['cp', 'mv', 'cd']
    }
    
    suggestions = []
    
    if command_base in common_typos:
        
        if command_base == 'cd' and len(command_parts) >= 2:
            path = command_parts[1]
            if '.' in path and '/' in path and not path.endswith('/'):
                suggestions.extend(common_typos['cd'])
        
        elif command_base == 'cp' and len(command_parts) >= 2:
            path = command_parts[1]
            if path in ['.', '..', '~'] or path.endswith('/'):
                suggestions.extend(['cd', 'ls'])
    
    return suggestions

def get_systemctl_service_suggestions(ssh_client, service_name):
    """Get similar systemctl service names"""
    try:
        stdin, stdout, stderr = ssh_client.exec_command(r'systemctl list-unit-files --full --all --no-legend | cut -d" " -f1 | sed "s/\.service$//"')
        all_services = stdout.read().decode().split()
        
        import difflib
        suggestions = difflib.get_close_matches(service_name, all_services, n=3, cutoff=0.3)
        
        if suggestions:
            return [f"Service not found. Did you mean: {', '.join(suggestions)}?"]
        return ["Service not found"]
    except Exception as e:
        return ["Service not found"]

def get_docker_container_suggestions(ssh_client, container_name):
    """Get similar docker container names"""
    try:
        stdin, stdout, stderr = ssh_client.exec_command('docker ps -a --format "{{.Names}}"')
        all_containers = stdout.read().decode().split()
        
        import difflib
        suggestions = difflib.get_close_matches(container_name, all_containers, n=3, cutoff=0.3)
        
        if suggestions:
            return [f"Container not found. Did you mean: {', '.join(suggestions)}?"]
        return ["Container not found"]
    except Exception as e:
        return ["Container not found"]
    
def validate_command(ssh_client, command, has_sudo_privs):
    """Check if command exists on remote system and validate arguments with privilege check"""
    try:
        command_base = command.split()[0] if command.split() else ""
        
        # Skip validation for empty commands
        if not command_base:
            return True, []
            
        is_valid, suggestions = validate_command_with_args(ssh_client, command, has_sudo_privs)
        return is_valid, suggestions
        
    except Exception as e:
        print(f"Error validating command: {e}")
        return False, []

def execute_command(ssh_client, command):
    """Execute command on remote system and return output"""
    try:
        stdin, stdout, stderr = ssh_client.exec_command(command)
        output = stdout.read().decode().strip()
        error = stderr.read().decode().strip()
        
        silent_commands = ['cp', 'mv', 'rm', 'chmod', 'mkdir', 'touch']
        is_silent = any(command.strip().startswith(cmd) for cmd in silent_commands)
        
        if is_silent and not error:
            return "Executed successfully"
        elif error:
            return f"Error: {error}"
        return output if output else "Executed successfully"
    except Exception as e:
        return f"Error: {str(e)}"

def test_connections(ip, username, password):
    """Test various connection methods and return detailed error information"""
    errors = []
    
    # Test SSH
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(ip, username=username, password=password, timeout=5)
        client.close()
        errors.append("SSH: Success")
    except Exception as e:
        errors.append(f"SSH: {str(e)}")
    
    # Test WinRM on different ports
    winrm_ports = [5985, 5986, 47001]
    for port in winrm_ports:
        try:
            session = winrm.Session(
                f'{ip}:{port}', 
                auth=(username, password), 
                transport='ntlm',
                server_cert_validation='ignore'
            )
            result = session.run_cmd('echo test')
            errors.append(f"WinRM port {port}: Success")
        except Exception as e:
            errors.append(f"WinRM port {port}: {str(e)}")
    
    return "; ".join(errors)

# Modify the validate_commands function
@app.route('/validate_commands', methods=['POST'])
def validate_commands():
    try:
        data = request.json
        ip = data['ip']
        username = data['username']
        password = data['password']
        commands = data['commands']
        
        print(f"Attempting to connect to {ip} with username {username}")
        
        # Detect OS and connection type
        os_type, connection_type = detect_os(ip, username, password)
        
        print(f"Detected OS: {os_type}, Connection type: {connection_type}")
        
        if not connection_type:
            # Test all connection methods to provide detailed error info
            error_details = test_connections(ip, username, password)
            return jsonify({
                'success': False, 
                'error': f'Unable to connect to {ip}. Details: {error_details}'
            })
        
        # Create connection
        connection = create_connection(ip, username, password, connection_type)
        
        # Check user privileges
        has_privileges = False
        if connection_type == 'ssh':
            has_privileges = check_user_privileges_ssh(connection)
        elif connection_type == 'winrm':
            has_privileges = check_user_privileges_windows(connection)
        
        results = []
        all_valid = True
        sensitive_commands = []
        
        # First validate all commands
        for cmd in commands:
            if connection_type == 'ssh':
                is_valid, suggestions = validate_command_with_args(connection, cmd['command'], has_privileges)
            elif connection_type == 'winrm':
                is_valid, suggestions = validate_command_windows(connection, cmd['command'], has_privileges)
            else:
                is_valid, suggestions = False, ["Unsupported connection type"]
            
            results.append({
                'id': cmd['id'],
                'command': cmd['command'],
                'description': cmd['description'],
                'valid': is_valid,
                'suggestions': suggestions,
                'requires_sudo': is_sudo_command(cmd['command']) and not has_privileges,
                'sensitive': False  # Will be updated later
            })
            if not is_valid:
                all_valid = False
        
        # Only check for sensitive commands if all commands are valid
        requires_verification = False
        verification_code = None
        
        if all_valid:
            # Update results with sensitive command information
            for result in results:
                is_sensitive = is_sensitive_command(result['command'], os_type)
                result['sensitive'] = is_sensitive
                if is_sensitive:
                    sensitive_commands.append(result['command'])
            
            # If sensitive commands found, generate verification code and send email
            requires_verification = len(sensitive_commands) > 0
            
            if requires_verification:
                verification_code = generate_verification_code()
                # Store the code with the IP as key
                verification_codes[ip] = verification_code
                
                # Send email to supervisor
                email_sent = send_verification_email(ip, sensitive_commands, verification_code)
                if not email_sent:
                    return jsonify({
                        'success': False, 
                        'error': 'Failed to send verification email to supervisor'
                    })
        
        if connection_type == 'ssh':
            connection.close()
        
        return jsonify({
            'success': True,
            'os_type': os_type,
            'connection_type': connection_type,
            'has_privileges': has_privileges,
            'results': results,
            'all_valid': all_valid,
            'requires_verification': requires_verification,
            'verification_code': verification_code  # For testing purposes only
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/verify_code', methods=['POST'])
def verify_code():
    try:
        data = request.json
        ip = data['ip']
        code = data['code']
        
        # Check if the code matches
        if ip in verification_codes and verification_codes[ip] == code:
            # Code is correct, remove it to prevent reuse
            del verification_codes[ip]
            return jsonify({'success': True, 'verified': True})
        else:
            return jsonify({'success': True, 'verified': False})
            
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@app.route('/execute_commands', methods=['POST'])
def execute_commands():
    try:
        data = request.json
        ip = data['ip']
        username = data['username']
        password = data['password']
        commands = data['commands']
    
        os_type, connection_type = detect_os(ip, username, password)
        
        if not connection_type:
            return jsonify({'success': False, 'error': 'Unable to establish connection'})
        
        connection = create_connection(ip, username, password, connection_type)
        
        has_privileges = False
        if connection_type == 'ssh':
            has_privileges = check_user_privileges_ssh(connection)
        elif connection_type == 'winrm':
            has_privileges = check_user_privileges_windows(connection)
        
        non_sensitive_commands = []
        sensitive_commands = []
        
        for cmd in commands:
            if is_sensitive_command(cmd['command'], os_type):
                sensitive_commands.append(cmd)
            else:
                non_sensitive_commands.append(cmd)
        
        results = []
        
        for cmd in non_sensitive_commands:
            if not has_privileges and is_sudo_command(cmd['command']):
                output = "Error: This command requires superuser/administrator privileges"
            else:
                if connection_type == 'ssh':
                    output = execute_command_ssh(connection, cmd['command'])
                elif connection_type == 'winrm':
                    output = execute_command_windows(connection, cmd['command'])
                else:
                    output = "Unsupported connection type"
            
            results.append({
                'id': cmd['id'],
                'command': cmd['command'],
                'output': output,
                'requires_sudo': is_sudo_command(cmd['command']) and not has_privileges,
                'sensitive': False
            })
        
        for cmd in sensitive_commands:
            if not has_privileges and is_sudo_command(cmd['command']):
                output = "Error: This command requires superuser/administrator privileges"
            else:
                if connection_type == 'ssh':
                    output = execute_command_ssh(connection, cmd['command'])
                elif connection_type == 'winrm':
                    output = execute_command_windows(connection, cmd['command'])
                else:
                    output = "Unsupported connection type"
            
            results.append({
                'id': cmd['id'],
                'command': cmd['command'],
                'output': output,
                'requires_sudo': is_sudo_command(cmd['command']) and not has_privileges,
                'sensitive': True
            })
        
        if connection_type == 'ssh':
            connection.close()
        
        return jsonify({
            'success': True,
            'has_privileges': has_privileges,
            'results': results
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

if __name__ == '__main__':
    if not os.path.exists(UPLOAD_FOLDER):
        os.makedirs(UPLOAD_FOLDER)
    app.run(host='0.0.0.0', port=5000, debug=True)