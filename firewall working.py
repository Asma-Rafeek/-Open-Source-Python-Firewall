#!/usr/bin/env python3
import os
import sys
import json
import time
import getpass
import logging
import threading
import subprocess
from datetime import datetime
import netifaces
from passlib.hash import sha256_crypt
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session
from flask_socketio import SocketIO

# Configure colored logging
class ColorFormatter(logging.Formatter):
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    RESET = '\033[0m'
    
    FORMATS = {
        logging.INFO: GREEN + "%(asctime)s [%(levelname)s] %(message)s" + RESET,
        logging.WARNING: YELLOW + "%(asctime)s [%(levelname)s] %(message)s" + RESET,
        logging.ERROR: RED + "%(asctime)s [%(levelname)s] %(message)s" + RESET,
        logging.CRITICAL: RED + "%(asctime)s [%(levelname)s] %(message)s" + RESET
    }

    def format(self, record):
        log_fmt = self.FORMATS.get(record.levelno)
        formatter = logging.Formatter(log_fmt)
        return formatter.format(record)

# Set up logging
logger = logging.getLogger('Firewall')
logger.setLevel(logging.DEBUG)

# File handler
file_handler = logging.FileHandler('firewall.log')
file_handler.setFormatter(logging.Formatter('%(asctime)s [%(levelname)s] %(message)s'))
logger.addHandler(file_handler)

# Console handler
console_handler = logging.StreamHandler()
console_handler.setFormatter(ColorFormatter())
logger.addHandler(console_handler)

# Flask app
app = Flask(__name__)
app.secret_key = os.urandom(24)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

# Create templates directory if it doesn't exist
if not os.path.exists('templates'):
    os.makedirs('templates')

# Core Firewall Class
class PyFirewall:
    def __init__(self):
        self.users_file = 'users.json'
        self.rules_file = 'rules.json'
        self.current_user = None
        self.network_adapters = []
        self.ids_mode = True  # True=IDS, False=IPS
        self.firewall_running = False
        self.load_initial_config()
        self.web_server_active = False
        self.web_server_thread = None

    def is_service_available(self, service_name):
        """Check if a systemd service is available"""
        try:
            result = subprocess.run(
                ['systemctl', 'list-unit-files', f'{service_name}.service'],
                capture_output=True, text=True, check=False
            )
            return service_name in result.stdout
        except Exception as e:
            logger.warning(f"Failed to check service {service_name}: {str(e)}")
            return False

    def is_service_active(self, service_name):
        """Check if a service is active"""
        try:
            result = subprocess.run(
                ['systemctl', 'is-active', service_name], 
                capture_output=True, text=True, check=False
            )
            return result.stdout.strip() == 'active'
        except Exception:
            return False

    def load_initial_config(self):
        """Initialize configuration files and network setup"""
        logger.info("Initializing firewall configuration")
        
        # Initialize users if file doesn't exist
        if not os.path.exists(self.users_file):
            with open(self.users_file, 'w') as f:
                # Use SHA-256 hashing for passwords
                json.dump({'admin': sha256_crypt.hash('admin')}, f)
            logger.info("Created default user configuration")
        
        # Initialize rules if file doesn't exist
        if not os.path.exists(self.rules_file):
            with open(self.rules_file, 'w') as f:
                json.dump([], f)
            logger.info("Created empty rules configuration")
        
        # Load network adapters
        try:
            self.network_adapters = netifaces.interfaces()
            logger.info(f"Detected network adapters: {', '.join(self.network_adapters)}")
        except Exception as e:
            logger.error(f"Failed to detect network adapters: {str(e)}")

        # Handle firewall service
        self.handle_system_firewall()

    def handle_system_firewall(self):
        """Manage system firewall services"""
        # Check if firewalld is available
        if self.is_service_available('firewalld'):
            logger.info("Firewalld service detected")
            
            # Check if firewalld is running
            if self.is_service_active('firewalld'):
                logger.info("Stopping firewalld service")
                try:
                    subprocess.run(['systemctl', 'stop', 'firewalld'], check=False)
                    logger.info("Firewalld service stopped")
                except Exception as e:
                    logger.warning(f"Failed to stop firewalld: {str(e)}")
            else:
                logger.info("Firewalld service is not active")
        
        # Check if UFW is available
        elif self.is_service_available('ufw'):
            logger.info("UFW service detected")
            
            # Check if UFW is enabled
            try:
                result = subprocess.run(
                    ['ufw', 'status'], 
                    capture_output=True, text=True, check=False
                )
                
                if 'active' in result.stdout:
                    logger.info("Disabling UFW firewall")
                    subprocess.run(['ufw', 'disable'], check=False)
            except Exception as e:
                logger.warning(f"Failed to manage UFW: {str(e)}")
        
        else:
            logger.info("No system firewall detected, using direct iptables")

    def authenticate(self):
        """Authenticate user credentials"""
        attempts = 0
        max_attempts = 3
        
        while attempts < max_attempts:
            username = input("Username: ")
            password = getpass.getpass("Password: ")
            
            try:
                with open(self.users_file, 'r') as f:
                    users = json.load(f)
                    
                if username in users and sha256_crypt.verify(password, users[username]):
                    self.current_user = username
                    logger.info(f"Successful login: {username}")
                    return True
            except Exception as e:
                logger.error(f"Error reading user data: {str(e)}")
                # Create default admin user if file is corrupt
                with open(self.users_file, 'w') as f:
                    json.dump({'admin': sha256_crypt.hash('admin')}, f)
                logger.info("Reset user configuration to defaults")
                
            logger.error(f"Invalid login attempt for user: {username}")
            attempts += 1
            print(f"Invalid credentials. {max_attempts - attempts} attempts remaining.")
            
        logger.critical("Too many failed login attempts")
        return False

    # === Rule Management ===
    def add_rule(self):
        """Add a new firewall rule"""
        rule = {
            'name': input("Rule name: "),
            'src_ip': input("Source IP (CIDR or empty for any): ") or 'any',
            'dst_ip': input("Destination IP/Domain (or empty for any): ") or 'any',
            'protocol': input("Protocol (tcp/udp/icmp/all): ").lower(),
            'port': input("Port(s) (or empty for all): ") or 'any',
            'action': input("Action (allow/deny): ").lower(),
            'direction': input("Direction (in/out/both): ").lower(),
            'permanent': input("Permanent (y/n): ").lower() == 'y'
        }
        
        # Validate inputs
        if rule['protocol'] not in ['tcp', 'udp', 'icmp', 'all']:
            rule['protocol'] = 'all'
            print(f"Invalid protocol specified, defaulting to 'all'")
            
        if rule['action'] not in ['allow', 'deny']:
            rule['action'] = 'deny'
            print(f"Invalid action specified, defaulting to 'deny'")
            
        if rule['direction'] not in ['in', 'out', 'both']:
            rule['direction'] = 'both'
            print(f"Invalid direction specified, defaulting to 'both'")
        
        try:
            with open(self.rules_file, 'r') as f:
                rules = json.load(f)
            
            rules.append(rule)
            
            with open(self.rules_file, 'w') as f:
                json.dump(rules, f, indent=4)
                
            # Apply the rule
            self._apply_rule(rule)
            
            # Log the action
            log_message = f"{self.current_user} added rule '{rule['name']}' to {rule['action']} {rule['protocol']} traffic"
            if rule['action'] == 'allow':
                logger.info(log_message)
            else:
                logger.error(log_message)  # Red for deny rules
            
            # Notify GUI clients about the rule update
            try:
                socketio.emit('rules_updated', {'action': 'add', 'rule': rule})
            except Exception as e:
                logger.error(f"Failed to emit socket event: {str(e)}")
                
            print(f"Rule '{rule['name']}' added successfully.")
            
        except Exception as e:
            logger.error(f"Failed to add rule: {str(e)}")
            print(f"Error: Failed to add rule. {str(e)}")
    
    def _apply_rule(self, rule):
        """Apply a rule to the firewall using iptables"""
        try:
            if rule['protocol'] in ['tcp', 'udp'] and rule['port'] != 'any':
                port_spec = f" --dport {rule['port']}"
            else:
                port_spec = ""
                
            src_spec = f" -s {rule['src_ip']}" if rule['src_ip'] != 'any' else ""
            dst_spec = f" -d {rule['dst_ip']}" if rule['dst_ip'] != 'any' else ""
            proto_spec = f" -p {rule['protocol']}" if rule['protocol'] != 'all' else ""
            
            target = "ACCEPT" if rule['action'] == 'allow' else "DROP"
            
            # Apply the rule based on direction
            if rule['direction'] in ['in', 'both']:
                cmd = f"iptables -A INPUT{src_spec}{dst_spec}{proto_spec}{port_spec} -j {target}"
                subprocess.run(cmd, shell=True, check=False)
                
            if rule['direction'] in ['out', 'both']:
                cmd = f"iptables -A OUTPUT{src_spec}{dst_spec}{proto_spec}{port_spec} -j {target}"
                subprocess.run(cmd, shell=True, check=False)
                
        except Exception as e:
            logger.error(f"Failed to apply iptables rule: {str(e)}")
            raise
    
    def view_rules(self):
        """Display existing firewall rules"""
        try:
            with open(self.rules_file, 'r') as f:
                rules = json.load(f)
                
            if not rules:
                print("No rules defined.")
                return
                
            print("\n" + "="*80)
            print(f"{'Index':^6} | {'Name':^15} | {'Protocol':^8} | {'Source IP':^15} | {'Dest IP':^15} | {'Port':^8} | {'Action':^8}")
            print("-"*80)
            
            for i, rule in enumerate(rules):
                print(f"{i:^6} | {rule['name']:^15} | {rule['protocol']:^8} | {rule['src_ip']:^15} | {rule['dst_ip']:^15} | {rule['port']:^8} | {rule['action']:^8}")
                
            print("="*80 + "\n")
            
        except Exception as e:
            logger.error(f"Failed to view rules: {str(e)}")
            print(f"Error: Failed to view rules. {str(e)}")
    
    def delete_rule(self):
        """Delete a firewall rule by index"""
        self.view_rules()
        
        try:
            with open(self.rules_file, 'r') as f:
                rules = json.load(f)
                
            if not rules:
                print("No rules to delete.")
                return
                
            index = int(input("Enter rule index to delete: "))
            
            if 0 <= index < len(rules):
                rule = rules.pop(index)
                
                with open(self.rules_file, 'w') as f:
                    json.dump(rules, f, indent=4)
                    
                # Remove the rule from iptables
                self._remove_rule(rule)
                
                logger.warning(f"{self.current_user} deleted rule '{rule['name']}'")
                
                # Notify GUI clients about the rule update
                try:
                    socketio.emit('rules_updated', {'action': 'delete', 'index': index})
                except Exception as e:
                    logger.error(f"Failed to emit socket event: {str(e)}")
                
                print(f"Rule '{rule['name']}' deleted successfully.")
            else:
                print("Invalid rule index.")
                
        except ValueError:
            print("Please enter a valid number.")
        except Exception as e:
            logger.error(f"Failed to delete rule: {str(e)}")
            print(f"Error: Failed to delete rule. {str(e)}")
    
    def _remove_rule(self, rule):
        """Remove a rule from iptables"""
        try:
            if rule['protocol'] in ['tcp', 'udp'] and rule['port'] != 'any':
                port_spec = f" --dport {rule['port']}"
            else:
                port_spec = ""
                
            src_spec = f" -s {rule['src_ip']}" if rule['src_ip'] != 'any' else ""
            dst_spec = f" -d {rule['dst_ip']}" if rule['dst_ip'] != 'any' else ""
            proto_spec = f" -p {rule['protocol']}" if rule['protocol'] != 'all' else ""
            
            target = "ACCEPT" if rule['action'] == 'allow' else "DROP"
            
            # Remove rules based on direction
            if rule['direction'] in ['in', 'both']:
                cmd = f"iptables -D INPUT{src_spec}{dst_spec}{proto_spec}{port_spec} -j {target}"
                subprocess.run(cmd, shell=True, check=False)
                
            if rule['direction'] in ['out', 'both']:
                cmd = f"iptables -D OUTPUT{src_spec}{dst_spec}{proto_spec}{port_spec} -j {target}"
                subprocess.run(cmd, shell=True, check=False)
                
        except Exception as e:
            logger.error(f"Failed to remove iptables rule: {str(e)}")
            raise
    
    def manage_rule_order(self):
        """Manage the order of firewall rules"""
        self.view_rules()
        
        try:
            with open(self.rules_file, 'r') as f:
                rules = json.load(f)
                
            if len(rules) <= 1:
                print("Not enough rules to reorder.")
                return
                
            index = int(input("Enter rule index to move: "))
            
            if 0 <= index < len(rules):
                direction = input("Move up or down (u/d): ").lower()
                
                if direction == 'u' and index > 0:
                    rules[index], rules[index-1] = rules[index-1], rules[index]
                    print(f"Rule '{rules[index]['name']}' moved up.")
                elif direction == 'd' and index < len(rules) - 1:
                    rules[index], rules[index+1] = rules[index+1], rules[index]
                    print(f"Rule '{rules[index]['name']}' moved down.")
                else:
                    print("Cannot move rule in that direction.")
                    return
                    
                with open(self.rules_file, 'w') as f:
                    json.dump(rules, f, indent=4)
                    
                # Reapply all rules to maintain the order
                self._reapply_all_rules(rules)
                
                # Notify GUI clients about the rule reordering
                try:
                    socketio.emit('rules_updated', {'action': 'reorder', 'rules': rules})
                except Exception as e:
                    logger.error(f"Failed to emit socket event: {str(e)}")
                
                logger.warning(f"{self.current_user} changed rule order")
            else:
                print("Invalid rule index.")
                
        except ValueError:
            print("Please enter a valid number.")
        except Exception as e:
            logger.error(f"Failed to manage rule order: {str(e)}")
            print(f"Error: Failed to manage rule order. {str(e)}")
    
    def _reapply_all_rules(self, rules):
        """Clear and reapply all rules to maintain order"""
        try:
            # Clear all existing rules
            subprocess.run("iptables -F", shell=True, check=False)
            
            # Reapply all rules in order
            for rule in rules:
                self._apply_rule(rule)
                
            logger.info("Rules reordered and reapplied successfully")
            
        except Exception as e:
            logger.error(f"Failed to reapply rules: {str(e)}")
            raise
    
    # === System Security Management ===
    def user_management_menu(self):
        """Handle user management submenu"""
        if self.current_user != 'admin':
            logger.error(f"User {self.current_user} attempted to access system security")
            print("Only admin can access system security settings.")
            return
            
        while True:
            print("\nSystem Security")
            print("1 - Add new user")
            print("2 - View users")
            print("3 - Change password")
            print("4 - Delete user")
            print("5 - Exit")
            
            choice = input("Select option: ")
            
            if choice == '1':
                self.add_user()
            elif choice == '2':
                self.view_users()
            elif choice == '3':
                self.change_password()
            elif choice == '4':
                self.delete_user()
            elif choice == '5':
                return
            else:
                print("Invalid option.")
    
    def add_user(self):
        """Add a new user to the system"""
        new_username = input("New username: ")
        
        try:
            with open(self.users_file, 'r') as f:
                users = json.load(f)
                
            if new_username in users:
                print("Username already exists.")
                return
                
            password = getpass.getpass("Password: ")
            retype_password = getpass.getpass("Retype password: ")
            
            if password != retype_password:
                print("Passwords do not match.")
                return
                
            # Hash the password using SHA-256
            hashed_password = sha256_crypt.hash(password)
            users[new_username] = hashed_password
            
            with open(self.users_file, 'w') as f:
                json.dump(users, f, indent=4)
                
            logger.warning(f"{self.current_user} added new user: {new_username}")
            
            # Notify GUI clients about the user update
            try:
                socketio.emit('users_updated')
            except Exception as e:
                logger.error(f"Failed to emit socket event: {str(e)}")
            
            print(f"User '{new_username}' added successfully.")
            
        except Exception as e:
            logger.error(f"Failed to add user: {str(e)}")
            print(f"Error: Failed to add user. {str(e)}")
    
    def view_users(self):
        """Display all users in the system"""
        try:
            with open(self.users_file, 'r') as f:
                users = json.load(f)
                
            print("\n" + "="*40)
            print(f"{'Index':^6} | {'Username':^20}")
            print("-"*40)
            
            for i, username in enumerate(users.keys()):
                print(f"{i:^6} | {username:^20}")
                
            print("="*40 + "\n")
            
        except Exception as e:
            logger.error(f"Failed to view users: {str(e)}")
            print(f"Error: Failed to view users. {str(e)}")
    
    def change_password(self):
        """Change a user's password"""
        self.view_users()
        
        try:
            with open(self.users_file, 'r') as f:
                users = json.load(f)
                
            user_list = list(users.keys())
            index = int(input("Enter user index to change password: "))
            
            if 0 <= index < len(user_list):
                username = user_list[index]
                
                password = getpass.getpass("New password: ")
                retype_password = getpass.getpass("Retype password: ")
                
                if password != retype_password:
                    print("Passwords do not match.")
                    return
                    
                # Hash the new password
                users[username] = sha256_crypt.hash(password)
                
                with open(self.users_file, 'w') as f:
                    json.dump(users, f, indent=4)
                    
                logger.warning(f"{self.current_user} changed password for user: {username}")
                print(f"Password for '{username}' changed successfully.")
                
                # Notify GUI clients about the user update
                try:
                    socketio.emit('users_updated')
                except Exception as e:
                    logger.error(f"Failed to emit socket event: {str(e)}")
                
            else:
                print("Invalid user index.")
                
        except ValueError:
            print("Please enter a valid number.")
        except Exception as e:
            logger.error(f"Failed to change password: {str(e)}")
            print(f"Error: Failed to change password. {str(e)}")
    
    def delete_user(self):
        """Delete a user from the system"""
        self.view_users()
        
        try:
            with open(self.users_file, 'r') as f:
                users = json.load(f)
                
            user_list = list(users.keys())
            index = int(input("Enter user index to delete: "))
            
            if 0 <= index < len(user_list):
                username = user_list[index]
                
                if username == 'admin':
                    print("Cannot delete admin user.")
                    return
                    
                del users[username]
                
                with open(self.users_file, 'w') as f:
                    json.dump(users, f, indent=4)
                    
                logger.warning(f"{self.current_user} deleted user: {username}")
                print(f"User '{username}' deleted successfully.")
                
                # Notify GUI clients about the user update
                try:
                    socketio.emit('users_updated')
                except Exception as e:
                    logger.error(f"Failed to emit socket event: {str(e)}")
                
            else:
                print("Invalid user index.")
                
        except ValueError:
            print("Please enter a valid number.")
        except Exception as e:
            logger.error(f"Failed to delete user: {str(e)}")
            print(f"Error: Failed to delete user. {str(e)}")
    
    # === IDS/IPS Management ===
    def ids_ips_management_menu(self):
        """Handle IDS/IPS management submenu"""
        while True:
            mode = "IDS" if self.ids_mode else "IPS"
            print(f"\nIDS/IPS Management (Current mode: {mode})")
            print("1 - Switch between IDS/IPS")
            print("2 - Read logs and manage")
            print("3 - Exit")
            
            choice = input("Select option: ")
            
            if choice == '1':
                self.switch_ids_ips_mode()
            elif choice == '2':
                self.view_ids_ips_logs()
            elif choice == '3':
                return
            else:
                print("Invalid option.")
    
    def switch_ids_ips_mode(self):
        """Switch between IDS and IPS modes"""
        self.ids_mode = not self.ids_mode
        mode = "IDS" if self.ids_mode else "IPS"
        
        logger.warning(f"{self.current_user} switched to {mode} mode")
        print(f"Switched to {mode} mode successfully.")
        
        # Notify GUI clients about the mode switch
        try:
            socketio.emit('ids_mode_changed', {'mode': mode})
        except Exception as e:
            logger.error(f"Failed to emit socket event: {str(e)}")
    
    def view_ids_ips_logs(self):
        """View and manage IDS/IPS logs"""
        # In a real implementation, this would read from actual IDS/IPS logs
        # This is a simplified simulation
        logs = [
            {"id": 1, "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"), 
             "src_ip": "192.168.1.100", "dst_ip": "10.0.0.1", "event": "Port scan detected"},
            {"id": 2, "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"), 
             "src_ip": "172.16.0.5", "dst_ip": "192.168.1.1", "event": "Excessive login attempts"}
        ]
        
        print("\nIDS/IPS Logs")
        print("="*80)
        print(f"{'ID':^4} | {'Timestamp':^19} | {'Source IP':^15} | {'Destination IP':^15} | {'Event':^25}")
        print("-"*80)
        
        for log in logs:
            print(f"{log['id']:^4} | {log['timestamp']:^19} | {log['src_ip']:^15} | {log['dst_ip']:^15} | {log['event']:^25}")
            
        print("="*80 + "\n")
        
        if not self.ids_mode:  # IPS mode - can take action
            log_id = input("Enter log ID to take action (or press Enter to skip): ")
            
            if log_id:
                try:
                    log_id = int(log_id)
                    action = input("Action (block/allow): ").lower()
                    
                    if action in ['block', 'allow']:
                        # In a real implementation, this would apply firewall rules
                        print(f"Action '{action}' applied to log ID {log_id}.")
                        logger.warning(f"{self.current_user} applied {action} action to log ID {log_id}")
                    else:
                        print("Invalid action.")
                except ValueError:
                    print("Please enter a valid number.")
    
    # === System Logs ===
    def view_system_logs(self):
        """View system logs"""
        try:
            with open('firewall.log', 'r') as f:
                logs = f.readlines()
                
            if not logs:
                print("No logs available.")
                return
                
            print("\nSystem Logs")
            print("="*100)
            
            # Show the last 20 logs for readability
            for log in logs[-20:]:
                print(log.strip())
                
            print("="*100)
            
        except Exception as e:
            print(f"Error: Failed to read logs. {str(e)}")
    
    # === Firewall Management ===
    def firewall_management_menu(self):
        """Handle firewall management submenu"""
        while True:
            status = "Running" if self.firewall_running else "Stopped"
            print(f"\nFirewall Management (Current status: {status})")
            print("1 - Start firewall")
            print("2 - Status firewall")
            print("3 - Restart firewall")
            print("4 - Stop firewall")
            print("5 - Exit")
            
            choice = input("Select option: ")
            
            if choice == '1':
                self.start_firewall()
            elif choice == '2':
                self.check_firewall_status()
            elif choice == '3':
                self.restart_firewall()
            elif choice == '4':
                self.stop_firewall()
            elif choice == '5':
                return
            else:
                print("Invalid option.")
    
    def start_firewall(self):
        """Start the firewall"""
        try:
            # Clear existing rules
            subprocess.run("iptables -F", shell=True, check=False)
            
            # Apply default policies
            subprocess.run("iptables -P INPUT ACCEPT", shell=True, check=False)
            subprocess.run("iptables -P OUTPUT ACCEPT", shell=True, check=False)
            subprocess.run("iptables -P FORWARD DROP", shell=True, check=False)
            
            # Apply saved rules
            with open(self.rules_file, 'r') as f:
                rules = json.load(f)
                
            for rule in rules:
                self._apply_rule(rule)
                
            self.firewall_running = True
            
            logger.info(f"{self.current_user} started the firewall")
            print("Firewall started successfully.")
            
            # Notify GUI clients about the firewall status
            try:
                socketio.emit('firewall_status_changed', {'status': 'running'})
            except Exception as e:
                logger.error(f"Failed to emit socket event: {str(e)}")
            
        except Exception as e:
            logger.error(f"Failed to start firewall: {str(e)}")
            print(f"Error: Failed to start firewall. {str(e)}")
    
    def check_firewall_status(self):
        """Check firewall status"""
        try:
            result = subprocess.run(
                ["iptables", "-L", "-v", "-n"], 
                capture_output=True, 
                text=True, 
                check=False
            )
            
            print("\nFirewall Status")
            print("="*80)
            print(result.stdout)
            print("="*80)
            
            logger.info(f"{self.current_user} checked firewall status")
            
        except Exception as e:
            logger.error(f"Failed to check firewall status: {str(e)}")
            print(f"Error: Failed to check firewall status. {str(e)}")
    
    def restart_firewall(self):
        """Restart the firewall"""
        self.stop_firewall()
        time.sleep(1)  # Small delay to ensure proper restart
        self.start_firewall()
        
        logger.warning(f"{self.current_user} restarted the firewall")
        print("Firewall restarted successfully.")
    
    def stop_firewall(self):
        """Stop the firewall"""
        try:
            # Clear all rules
            subprocess.run("iptables -F", shell=True, check=False)
            
            # Set default policies to ACCEPT
            subprocess.run("iptables -P INPUT ACCEPT", shell=True, check=False)
            subprocess.run("iptables -P OUTPUT ACCEPT", shell=True, check=False)
            subprocess.run("iptables -P FORWARD ACCEPT", shell=True, check=False)
            
            self.firewall_running = False
            
            logger.warning(f"{self.current_user} stopped the firewall")
            print("Firewall stopped successfully.")
            
            # Notify GUI clients about the firewall status
            try:
                socketio.emit('firewall_status_changed', {'status': 'stopped'})
            except Exception as e:
                logger.error(f"Failed to emit socket event: {str(e)}")
            
        except Exception as e:
            logger.error(f"Failed to stop firewall: {str(e)}")
            print(f"Error: Failed to stop firewall. {str(e)}")
    
    # === Network Management ===
    def network_management_menu(self):
        """Handle network management submenu"""
        while True:
            print("\nNetwork Manager")
            print("1 - Add network adapter")
            print("2 - Display available adapters")
            print("3 - Remove network adapter")
            print("4 - Exit")
            
            choice = input("Select option: ")
            
            if choice == '1':
                self.add_network_adapter()
            elif choice == '2':
                self.display_network_adapters()
            elif choice == '3':
                self.remove_network_adapter()
            elif choice == '4':
                return
            else:
                print("Invalid option.")
    
    def add_network_adapter(self):
        """Add a network adapter to the firewall"""
        try:
            all_adapters = netifaces.interfaces()
            current_adapters = self.network_adapters
            
            available_adapters = [a for a in all_adapters if a not in current_adapters]
            
            if not available_adapters:
                print("No additional adapters available to add.")
                return
                
            print("\nAvailable Adapters")
            print("="*30)
            
            for i, adapter in enumerate(available_adapters):
                print(f"{i} - {adapter}")
                
            print("="*30)
            
            index = int(input("Enter adapter index to add: "))
            
            if 0 <= index < len(available_adapters):
                adapter = available_adapters[index]
                self.network_adapters.append(adapter)
                
                logger.warning(f"{self.current_user} added network adapter: {adapter}")
                print(f"Network adapter '{adapter}' added successfully.")
                
                # Notify GUI clients about the adapter update
                try:
                    socketio.emit('adapters_updated', {'adapters': self.network_adapters})
                except Exception as e:
                    logger.error(f"Failed to emit socket event: {str(e)}")
                
            else:
                print("Invalid adapter index.")
                
        except ValueError:
            print("Please enter a valid number.")
        except Exception as e:
            logger.error(f"Failed to add network adapter: {str(e)}")
            print(f"Error: Failed to add network adapter. {str(e)}")
    
    def display_network_adapters(self):
        """Display available network adapters"""
        try:
            if not self.network_adapters:
                print("No network adapters configured.")
                return
                
            print("\nConfigured Network Adapters")
            print("="*50)
            
            for i, adapter in enumerate(self.network_adapters):
                # Get adapter details
                try:
                    addrs = netifaces.ifaddresses(adapter)
                    ipv4 = addrs.get(netifaces.AF_INET, [{'addr': 'N/A'}])[0]['addr']
                    mac = addrs.get(netifaces.AF_LINK, [{'addr': 'N/A'}])[0]['addr']
                    print(f"{i} - {adapter} (IP: {ipv4}, MAC: {mac})")
                except:
                    print(f"{i} - {adapter} (Status: Unknown)")
                
            print("="*50)
            
        except Exception as e:
            logger.error(f"Failed to display network adapters: {str(e)}")
            print(f"Error: Failed to display network adapters. {str(e)}")
    
    def remove_network_adapter(self):
        """Remove a network adapter from the firewall"""
        self.display_network_adapters()
        
        try:
            if not self.network_adapters:
                return
                
            index = int(input("Enter adapter index to remove: "))
            
            if 0 <= index < len(self.network_adapters):
                adapter = self.network_adapters.pop(index)
                
                logger.warning(f"{self.current_user} removed network adapter: {adapter}")
                print(f"Network adapter '{adapter}' removed successfully.")
                
                # Notify GUI clients about the adapter update
                try:
                    socketio.emit('adapters_updated', {'adapters': self.network_adapters})
                except Exception as e:
                    logger.error(f"Failed to emit socket event: {str(e)}")
                
            else:
                print("Invalid adapter index.")
                
        except ValueError:
            print("Please enter a valid number.")
        except Exception as e:
            logger.error(f"Failed to remove network adapter: {str(e)}")
            print(f"Error: Failed to remove network adapter. {str(e)}")
    
    # === Web-based GUI Management ===
    def start_gui_mode(self):
        """Start the web-based GUI interface"""
        if self.web_server_active:
            print("GUI mode is already running.")
            print(f"Access the web interface at http://127.0.0.1:5000")
            return
            
        try:
            self.web_server_active = True
            logger.info(f"{self.current_user} started GUI mode")
            print("Starting GUI mode...")
            print("Access the web interface at http://127.0.0.1:5000")
            
            # Create the necessary HTML templates
            self._create_html_templates()
            
            # No need to start a separate thread, we'll just return to the main menu
            # and let the user use Ctrl+C to return to the CLI interface when done
            
        except Exception as e:
            self.web_server_active = False
            logger.error(f"Failed to start GUI mode: {str(e)}")
            print(f"Error: Failed to start GUI mode. {str(e)}")
    
    def _create_html_templates(self):
        """Create HTML templates for the web interface"""
        if not os.path.exists('templates'):
            os.makedirs('templates')
            
        # Create login template
        login_html = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PyFirewall - Login</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            background-color: #f4f4f4;
            margin: 0;
            padding: 0;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
        }
        .login-container {
            background-color: white;
            padding: 30px;
            border-radius: 5px;
            box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
            width: 350px;
        }
        h1 {
            text-align: center;
            color: #333;
        }
        input[type="text"], input[type="password"] {
            width: 100%;
            padding: 10px;
            margin: 10px 0;
            border: 1px solid #ddd;
            border-radius: 3px;
            box-sizing: border-box;
        }
        button {
            width: 100%;
            padding: 10px;
            background-color: #4CAF50;
            color: white;
            border: none;
            border-radius: 3px;
            cursor: pointer;
            font-size: 16px;
        }
        button:hover {
            background-color: #45a049;
        }
        .alert {
            background-color: #f8d7da;
            color: #721c24;
            padding: 10px;
            margin: 10px 0;
            border-radius: 3px;
            display: none;
        }
    </style>
</head>
<body>
    <div class="login-container">
        <h1>PyFirewall</h1>
        <div class="alert" id="alert-box"></div>
        <form id="login-form" method="post" action="/login">
            <input type="text" name="username" placeholder="Username" required>
            <input type="password" name="password" placeholder="Password" required>
            <button type="submit">Login</button>
        </form>
    </div>
    
    <script>
        // Check for flash messages
        const urlParams = new URLSearchParams(window.location.search);
        const error = urlParams.get('error');
        if (error) {
            const alertBox = document.getElementById('alert-box');
            alertBox.textContent = error;
            alertBox.style.display = 'block';
        }
    </script>
</body>
</html>
'''
        
        # Create index template with fixed navigation
        index_html = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PyFirewall - Web UI</title>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/socket.io/4.0.1/socket.io.min.js"></script>
    <style>
        body {
            font-family: Arial, sans-serif;
            margin: 0;
            padding: 0;
            background-color: #f4f4f4;
        }
        .container {
            display: flex;
            min-height: 100vh;
        }
        .sidebar {
            width: 250px;
            background-color: #2c3e50;
            color: white;
            padding: 20px 0;
        }
        .sidebar h1 {
            text-align: center;
            margin-bottom: 30px;
            font-size: 24px;
        }
        .sidebar ul {
            list-style: none;
            padding: 0;
        }
        .sidebar li {
            padding: 15px 20px;
            cursor: pointer;
            border-left: 3px solid transparent;
        }
        .sidebar li:hover, .sidebar li.active {
            background-color: #34495e;
            border-left: 3px solid #3498db;
        }
        .content {
            flex: 1;
            padding: 20px;
            max-height: 100vh;
            overflow-y: auto;
            position: relative;
            z-index: 999;  # Lower than logout button
            margin-top: 60px;  # Add space below logout
        }
        .content-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
        }
        .content-header h2 {
            margin: 0;
        }
        #add-adapter-btn, #add-rule-btn, #add-user-btn {
          position: relative;
         z-index: 1001;
        }  
        .panel {
            background-color: white;
            border-radius: 5px;
            box-shadow: 0 2px 5px rgba(0, 0, 0, 0.1);
            padding: 20px;
            margin-bottom: 20px;
        }
        .button {
            padding: 8px 15px;
            border: none;
            border-radius: 3px;
            cursor: pointer;
            font-size: 14px;
        }
        .button-primary {
            background-color: #3498db;
            color: white;
        }
        .button-success {
            background-color: #2ecc71;
            color: white;
        }
        .button-danger {
            background-color: #e74c3c;
            color: white;
        }
        .button-warning {
            background-color: #f39c12;
            color: white;
        }
        table {
            width: 100%;
            border-collapse: collapse;
        }
        table th, table td {
            padding: 12px 15px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }
        table th {
            background-color: #f8f9fa;
        }
        form .form-group {
            margin-bottom: 15px;
        }
        form label {
            display: block;
            margin-bottom: 5px;
            font-weight: bold;
        }
        form input, form select {
            width: 100%;
            padding: 8px;
            border: 1px solid #ddd;
            border-radius: 3px;
        }
        .status-badge {
            display: inline-block;
            padding: 5px 10px;
            border-radius: 15px;
            font-size: 12px;
            color: white;
        }
        .status-running {
            background-color: #2ecc71;
        }
        .status-stopped {
            background-color: #e74c3c;
        }
        .logs-container {
            background-color: #2c3e50;
            color: #ecf0f1;
            padding: 15px;
            border-radius: 5px;
            font-family: monospace;
            max-height: 400px;
            overflow-y: auto;
        }
        .log-info {
            color: #2ecc71;
        }
        .log-warning {
            color: #f39c12;
        }
        .log-error {
            color: #e74c3c;
        }
        .hidden {
            display: none;
        }
        .logout-button {
            position: fixed;
            z-index: 1000;
            top: 20px;
            right: 20px;
            background-color: #e74c3c;
            color: white;
            padding: 8px 15px;
            border: none;
            border-radius: 3px;
            margin-right: 140px;
            cursor: pointer;
            font-size: 14px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="sidebar">
            <h1>PyFirewall</h1>
            <ul id="sidebar-nav">
                <li class="nav-item active" data-page="dashboard">Dashboard</li>
                <li class="nav-item" data-page="rules">Manage Rules</li>
                <li class="nav-item" data-page="security">System Security</li>
                <li class="nav-item" data-page="ids">IDS/IPS Management</li>
                <li class="nav-item" data-page="logs">System Logs</li>
                <li class="nav-item" data-page="firewall">Firewall Manage</li>
                <li class="nav-item" data-page="network">Network Manager</li>
            </ul>
        </div>
        
        <div class="content">
            <a href="/logout" class="logout-button">Logout</a>
            
            <!-- Dashboard Page -->
            <div class="page-content" id="dashboard-page">
                <div class="content-header">
                    <h2>Dashboard</h2>
                </div>
                <div class="panel">
                    <h3>Firewall Status</h3>
                    <p>
                        Status: <span class="status-badge" id="firewall-status-badge">Loading...</span>
                    </p>
                    <div>
                        <button class="button button-success" id="start-firewall-btn">Start</button>
                        <button class="button button-danger" id="stop-firewall-btn">Stop</button>
                        <button class="button button-warning" id="restart-firewall-btn">Restart</button>
                    </div>
                </div>
                <div class="panel">
                    <h3>Rules Summary</h3>
                    <p id="rules-count">Loading rules...</p>
                </div>
                <div class="panel">
                    <h3>Network Adapters</h3>
                    <div id="adapters-list">Loading adapters...</div>
                </div>
            </div>
            
            <!-- Rules Page -->
            <div class="page-content hidden" id="rules-page">
                <div class="content-header">
                    <h2>Manage Rules</h2>
                    <button class="button button-primary" id="add-rule-btn">Add Rule</button>
                </div>
                <div class="panel">
                    <table>
                        <thead>
                            <tr>
                                <th>Name</th>
                                <th>Protocol</th>
                                <th>Source IP</th>
                                <th>Destination IP</th>
                                <th>Port</th>
                                <th>Action</th>
                                <th>Direction</th>
                                <th>Options</th>
                            </tr>
                        </thead>
                        <tbody id="rules-table-body">
                            <tr>
                                <td colspan="8">Loading rules...</td>
                            </tr>
                        </tbody>
                    </table>
                </div>
                
                <!-- Add Rule Form -->
                <div class="panel hidden" id="add-rule-form">
                    <h3>Add New Rule</h3>
                    <form id="rule-form">
                        <div class="form-group">
                            <label for="rule-name">Rule Name</label>
                            <input type="text" id="rule-name" required>
                        </div>
                        <div class="form-group">
                            <label for="rule-src-ip">Source IP (empty for any)</label>
                            <input type="text" id="rule-src-ip">
                        </div>
                        <div class="form-group">
                            <label for="rule-dst-ip">Destination IP/Domain (empty for any)</label>
                            <input type="text" id="rule-dst-ip">
                        </div>
                        <div class="form-group">
                            <label for="rule-protocol">Protocol</label>
                            <select id="rule-protocol">
                                <option value="tcp">TCP</option>
                                <option value="udp">UDP</option>
                                <option value="icmp">ICMP</option>
                                <option value="all">All</option>
                            </select>
                        </div>
                        <div class="form-group">
                            <label for="rule-port">Port(s) (empty for all)</label>
                            <input type="text" id="rule-port">
                        </div>
                        <div class="form-group">
                            <label for="rule-action">Action</label>
                            <select id="rule-action">
                                <option value="allow">Allow</option>
                                <option value="deny">Deny</option>
                            </select>
                        </div>
                        <div class="form-group">
                            <label for="rule-direction">Direction</label>
                            <select id="rule-direction">
                                <option value="in">Inbound</option>
                                <option value="out">Outbound</option>
                                <option value="both">Both</option>
                            </select>
                        </div>
                        <div class="form-group">
                            <label>
                                <input type="checkbox" id="rule-permanent"> Permanent
                            </label>
                        </div>
                        <button type="submit" class="button button-primary">Add Rule</button>
                        <button type="button" class="button button-danger" id="cancel-rule-btn">Cancel</button>
                    </form>
                </div>
            </div>
            
            <!-- Security Page -->
            <div class="page-content hidden" id="security-page">
                <div class="content-header">
                    <h2>System Security</h2>
                    <button class="button button-primary" id="add-user-btn">Add User</button>
                </div>
                <div class="panel">
                    <table>
                        <thead>
                            <tr>
                                <th>Username</th>
                                <th>Options</th>
                            </tr>
                        </thead>
                        <tbody id="users-table-body">
                            <tr>
                                <td colspan="2">Loading users...</td>
                            </tr>
                        </tbody>
                    </table>
                </div>
                
                <!-- Add User Form -->
                <div class="panel hidden" id="add-user-form">
                    <h3>Add New User</h3>
                    <form id="user-form">
                        <div class="form-group">
                            <label for="user-username">Username</label>
                            <input type="text" id="user-username" required>
                        </div>
                        <div class="form-group">
                            <label for="user-password">Password</label>
                            <input type="password" id="user-password" required>
                        </div>
                        <div class="form-group">
                            <label for="user-confirm-password">Confirm Password</label>
                            <input type="password" id="user-confirm-password" required>
                        </div>
                        <button type="submit" class="button button-primary">Add User</button>
                        <button type="button" class="button button-danger" id="cancel-user-btn">Cancel</button>
                    </form>
                </div>
            </div>
            
            <!-- IDS/IPS Page -->
            <div class="page-content hidden" id="ids-page">
                <div class="content-header">
                    <h2>IDS/IPS Management</h2>
                </div>
                <div class="panel">
                    <h3>Current Mode</h3>
                    <p>
                        Mode: <span id="ids-mode">Loading...</span>
                        <button class="button button-primary" id="switch-ids-mode-btn">Switch Mode</button>
                    </p>
                </div>
                <div class="panel">
                    <h3>Event Logs</h3>
                    <p>IDS/IPS event logs will be displayed here.</p>
                    <table>
                        <thead>
                            <tr>
                                <th>ID</th>
                                <th>Timestamp</th>
                                <th>Source IP</th>
                                <th>Destination IP</th>
                                <th>Event</th>
                                <th>Action</th>
                            </tr>
                        </thead>
                        <tbody id="ids-logs-table">
                            <tr>
                                <td>1</td>
                                <td>2025-04-26 16:54:00</td>
                                <td>192.168.1.100</td>
                                <td>10.0.0.1</td>
                                <td>Port scan detected</td>
                                <td>
                                    <button class="button button-success">Allow</button>
                                    <button class="button button-danger">Block</button>
                                </td>
                            </tr>
                            <tr>
                                <td>2</td>
                                <td>2025-04-26 16:55:30</td>
                                <td>172.16.0.5</td>
                                <td>192.168.1.1</td>
                                <td>Excessive login attempts</td>
                                <td>
                                    <button class="button button-success">Allow</button>
                                    <button class="button button-danger">Block</button>
                                </td>
                            </tr>
                        </tbody>
                    </table>
                </div>
            </div>
            
            <!-- Logs Page -->
            <div class="page-content hidden" id="logs-page">
                <div class="content-header">
                    <h2>System Logs</h2>
                    <button class="button button-primary" id="refresh-logs-btn">Refresh</button>
                </div>
                <div class="panel">
                    <div class="logs-container" id="logs-container">
                        Loading logs...
                    </div>
                </div>
            </div>
            
            <!-- Firewall Page -->
            <div class="page-content hidden" id="firewall-page">
                <div class="content-header">
                    <h2>Firewall Management</h2>
                </div>
                <div class="panel">
                    <h3>Firewall Control</h3>
                    <p>
                        Status: <span class="status-badge" id="firewall-status-badge2">Loading...</span>
                    </p>
                    <div>
                        <button class="button button-success" id="start-firewall-btn2">Start</button>
                        <button class="button button-danger" id="stop-firewall-btn2">Stop</button>
                        <button class="button button-warning" id="restart-firewall-btn2">Restart</button>
                    </div>
                </div>
                <div class="panel">
                    <h3>Firewall Status Output</h3>
                    <pre id="firewall-status-output">Click 'Check Status' to view iptables rules</pre>
                    <button class="button button-primary" id="check-status-btn">Check Status</button>
                </div>
            </div>
            
            <!-- Network Page -->
            <div class="page-content hidden" id="network-page">
                <div class="content-header">
                    <h2>Network Manager</h2>
                    <div>
                    <button class="button button-primary" id="add-adapter-btn">Add Adapter</button>
                    </div>
                </div>
                <div class="panel">
                    <h3>Configured Network Adapters</h3>
                    <table>
                        <thead>
                            <tr>
                                <th>Adapter</th>
                                <th>IP Address</th>
                                <th>MAC Address</th>
                                <th>Options</th>
                            </tr>
                        </thead>
                        <tbody id="adapters-table-body">
                            <tr>
                                <td colspan="4">Loading adapters...</td>
                            </tr>
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    </div>
    
    <script>
        // Initialize Socket.IO
        const socket = io();
        
        // Socket.IO event listeners
        socket.on('connect', () => {
            console.log('Connected to server');
        });
        
        socket.on('rules_updated', (data) => {
            console.log('Rules updated:', data);
            loadRules();
        });
        
        socket.on('users_updated', () => {
            console.log('Users updated');
            loadUsers();
        });
        
        socket.on('firewall_status_changed', (data) => {
            console.log('Firewall status changed:', data);
            updateFirewallStatus(data.status);
        });
        
        socket.on('ids_mode_changed', (data) => {
            console.log('IDS mode changed:', data);
            document.getElementById('ids-mode').textContent = data.mode;
        });
        
        socket.on('adapters_updated', (data) => {
            console.log('Adapters updated:', data);
            loadNetworkAdapters();
        });
        
        // Page navigation - FIXED
        document.addEventListener('DOMContentLoaded', function() {
            // Select all navigation items
            const navItems = document.querySelectorAll('.nav-item');
            
            // Add click event for each navigation item
            navItems.forEach(item => {
                item.addEventListener('click', function() {
                    // Remove active class from all items
                    navItems.forEach(i => i.classList.remove('active'));
                    
                    // Add active class to clicked item
                    this.classList.add('active');
                    
                    // Get the page ID from data attribute
                    const pageId = this.getAttribute('data-page');
                    
                    // Hide all pages
                    document.querySelectorAll('.page-content').forEach(page => {
                        page.classList.add('hidden');
                    });
                    
                    // Show the selected page
                    document.getElementById(pageId + '-page').classList.remove('hidden');
                    // Load data for specific pages
            switch(pageId) {
                case 'security':
                    loadUsers();
                    break;
                case 'dashboard':
                    loadNetworkAdapters();
                    loadDashboard(); 
                    break;
                case 'logs':
                    loadLogs();
                    break;
                case 'network':
                    loadNetworkAdapters();
                    break;
                case 'rules':
                    loadRules();
                    break;
                case 'firewall':
                    fetchFirewallStatus();
                    break;
                case 'ids':
                    loadIdsMode();
                    break;
            }
                    
                    // Log navigation
                    console.log('Navigated to:', pageId);
                });
            });
            
            // Dashboard functions
            loadDashboard();
            
            // Initial loading of other sections
            loadDashboard();
            loadRules();
            loadUsers();
            loadIdsMode();
            loadLogs();
            loadNetworkAdapters();
        });
        
        // Dashboard functions
        function loadDashboard() {
            fetchFirewallStatus();
            loadRulesSummary();
            loadNetworkAdapters();
        }
        
        function loadRulesSummary() {
            fetch('/api/rules')
                .then(response => response.json())
                .then(data => {
                    const allowCount = data.filter(rule => rule.action === 'allow').length;
                    const denyCount = data.filter(rule => rule.action === 'deny').length;
                    
                    document.getElementById('rules-count').innerHTML = `
                        Total Rules: ${data.length}<br>
                        Allow Rules: ${allowCount}<br>
                        Deny Rules: ${denyCount}
                    `;
                })
                .catch(error => {
                    console.error('Error loading rules summary:', error);
                    document.getElementById('rules-count').textContent = 'Error loading rules';
                });
        }
        // In the loadNetworkAdapters() function within the Dashboard section
function loadNetworkAdapters() {
    fetch('/api/adapters')
        .then(response => response.json())
        .then(data => {
            // Update dashboard panel (div)
            const adaptersList = document.getElementById('adapters-list');
            if (adaptersList) {
                if (!data.adapters || data.adapters.length === 0) {
                    adaptersList.innerHTML = '<p>No network adapters found</p>';
                } else {
                    adaptersList.innerHTML = `
                        <table style="width: 100%">
                            <tr>
                                <th>Adapter</th>
                                <th>IP Address</th>
                                <th>MAC Address</th>
                            </tr>
                            ${data.adapters.map(adapter => `
                                <tr>
                                    <td>${adapter.name}</td>
                                    <td>${adapter.ip || 'N/A'}</td>
                                    <td>${adapter.mac || 'N/A'}</td>
                                </tr>
                            `).join('')}
                        </table>
                    `;
                }
            }

            // Update Network Manager table (tbody)
            const tbody = document.getElementById('adapters-table-body');
            if (tbody) {
                if (!data.adapters || data.adapters.length === 0) {
                    tbody.innerHTML = '<tr><td colspan="4">No adapters found</td></tr>';
                } else {
                    tbody.innerHTML = data.adapters.map(adapter => `
                        <tr>
                            <td>${adapter.name}</td>
                            <td>${adapter.ip || 'N/A'}</td>
                            <td>${adapter.mac || 'N/A'}</td>
                            <td>
                                <button class="button button-danger delete-adapter-btn" data-adapter="${adapter.name}">Remove</button>
                            </td>
                        </tr>
                    `).join('');
                }
            }
        })
        .catch(error => {
            console.error('Error loading adapters:', error);
            const adaptersList = document.getElementById('adapters-list');
            if (adaptersList) adaptersList.innerHTML = '<p>Error loading network adapters</p>';
            const tbody = document.getElementById('adapters-table-body');
            if (tbody) tbody.innerHTML = '<tr><td colspan="4">Error loading adapters</td></tr>';
        });
}


        
        // Firewall functions
        function fetchFirewallStatus() {
            fetch('/api/firewall/status')
                .then(response => response.json())
                .then(data => {
                    updateFirewallStatus(data.status);
                })
                .catch(error => {
                    console.error('Error fetching firewall status:', error);
                });
        }
        
        function updateFirewallStatus(status) {
            const badges = document.querySelectorAll('#firewall-status-badge, #firewall-status-badge2');
            
            badges.forEach(badge => {
                badge.textContent = status.charAt(0).toUpperCase() + status.slice(1);
                badge.classList.remove('status-running', 'status-stopped');
                badge.classList.add(status === 'running' ? 'status-running' : 'status-stopped');
            });
        }
        
        // Add event listeners for firewall control buttons
        document.addEventListener('DOMContentLoaded', function() {
            document.querySelectorAll('#start-firewall-btn, #start-firewall-btn2').forEach(btn => {
                btn.addEventListener('click', () => {
                    fetch('/api/firewall/start', { method: 'POST' })
                        .then(response => response.json())
                        .then(data => {
                            if (data.success) {
                                updateFirewallStatus('running');
                            }
                        })
                        .catch(error => console.error('Error starting firewall:', error));
                });
            });
            
            document.querySelectorAll('#stop-firewall-btn, #stop-firewall-btn2').forEach(btn => {
                btn.addEventListener('click', () => {
                    fetch('/api/firewall/stop', { method: 'POST' })
                        .then(response => response.json())
                        .then(data => {
                            if (data.success) {
                                updateFirewallStatus('stopped');
                            }
                        })
                        .catch(error => console.error('Error stopping firewall:', error));
                });
            });
            
            document.querySelectorAll('#restart-firewall-btn, #restart-firewall-btn2').forEach(btn => {
                btn.addEventListener('click', () => {
                    fetch('/api/firewall/restart', { method: 'POST' })
                        .then(response => response.json())
                        .then(data => {
                            if (data.success) {
                                updateFirewallStatus('running');
                            }
                        })
                        .catch(error => console.error('Error restarting firewall:', error));
                });
            });
            
            if (document.getElementById('check-status-btn')) {
                document.getElementById('check-status-btn').addEventListener('click', () => {
                    document.getElementById('firewall-status-output').textContent = 'Loading iptables rules...';
                    
                    // For now, just show a placeholder message
                    setTimeout(() => {
                        document.getElementById('firewall-status-output').textContent = `
Chain INPUT (policy ACCEPT 0 packets, 0 bytes)
 pkts bytes target     prot opt in     out     source               destination         
    0     0 ACCEPT     tcp  --  *      *       0.0.0.0/0            0.0.0.0/0            tcp dpt:22
    0     0 DROP       tcp  --  *      *       0.0.0.0/0            0.0.0.0/0            tcp dpt:3389

Chain FORWARD (policy DROP 0 packets, 0 bytes)
 pkts bytes target     prot opt in     out     source               destination         

Chain OUTPUT (policy ACCEPT 0 packets, 0 bytes)
 pkts bytes target     prot opt in     out     source               destination         
    0     0 ACCEPT     tcp  --  *      *       0.0.0.0/0            0.0.0.0/0            tcp dpt:80
    0     0 ACCEPT     tcp  --  *      *       0.0.0.0/0            0.0.0.0/0            tcp dpt:443
                        `;
                    }, 500);
                });
            }
            
            // Other event listeners...
            if (document.getElementById('add-rule-btn')) {
                document.getElementById('add-rule-btn').addEventListener('click', () => {
                    document.getElementById('add-rule-form').classList.remove('hidden');
                });
            }
            
            if (document.getElementById('cancel-rule-btn')) {
                document.getElementById('cancel-rule-btn').addEventListener('click', () => {
                    document.getElementById('add-rule-form').classList.add('hidden');
                    document.getElementById('rule-form').reset();
                });
            }
            
            if (document.getElementById('rule-form')) {
                document.getElementById('rule-form').addEventListener('submit', function(e) {
                    e.preventDefault();
                    
                    const rule = {
                        name: document.getElementById('rule-name').value,
                        src_ip: document.getElementById('rule-src-ip').value,
                        dst_ip: document.getElementById('rule-dst-ip').value,
                        protocol: document.getElementById('rule-protocol').value,
                        port: document.getElementById('rule-port').value,
                        action: document.getElementById('rule-action').value,
                        direction: document.getElementById('rule-direction').value,
                        permanent: document.getElementById('rule-permanent').checked
                    };
                    
                    fetch('/api/rules', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json'
                        },
                        body: JSON.stringify(rule)
                    })
                    .then(response => response.json())
                    .then(data => {
                        if (data.success) {
                            document.getElementById('add-rule-form').classList.add('hidden');
                            document.getElementById('rule-form').reset();
                            loadRules();
                        } else {
                            alert('Error adding rule: ' + data.error);
                        }
                    })
                    .catch(error => {
                        console.error('Error adding rule:', error);
                        alert('Error adding rule');
                    });
                });
            }
            
            // Add other form handlers here...
        });
        
        // Rules functions
        function loadRules() {
            fetch('/api/rules')
                .then(response => response.json())
                .then(rules => {
                    const tableBody = document.getElementById('rules-table-body');
                    
                    if (!tableBody) {
                        console.error('Rules table body element not found');
                        return;
                    }
                    
                    if (rules.length === 0) {
                        tableBody.innerHTML = '<tr><td colspan="8">No rules defined</td></tr>';
                        return;
                    }
                    
                    tableBody.innerHTML = '';
                    
                    rules.forEach((rule, index) => {
                        const row = document.createElement('tr');
                        
                        row.innerHTML = `
                            <td>${rule.name}</td>
                            <td>${rule.protocol}</td>
                            <td>${rule.src_ip}</td>
                            <td>${rule.dst_ip}</td>
                            <td>${rule.port}</td>
                            <td>${rule.action}</td>
                            <td>${rule.direction}</td>
                            <td>
                                 <button class="button button-warning move-up-btn" data-index="${index}">↑</button>
                                 <button class="button button-warning move-down-btn" data-index="${index}">↓</button>
                                 <button class="button button-danger delete-rule-btn" data-index="${index}">Delete</button>
                             </td>
                        `;
                        
                        tableBody.appendChild(row);
                    });
                    
                    // Add event listeners for delete buttons
                    document.querySelectorAll('.delete-rule-btn').forEach(btn => {
                        btn.addEventListener('click', function() {
                            const index = this.getAttribute('data-index');
                            
                            if (confirm('Are you sure you want to delete this rule?')) {
                                fetch(`/api/rules/${index}`, { method: 'DELETE' })
                                    .then(response => response.json())
                                    .then(data => {
                                        if (data.success) {
                                            loadRules();
                                        }
                                    })
                                    .catch(error => console.error('Error deleting rule:', error));
                            }
                        });
                    });
                })
                .catch(error => {
                    console.error('Error loading rules:', error);
                    const tableBody = document.getElementById('rules-table-body');
                    if (tableBody) {
                        tableBody.innerHTML = '<tr><td colspan="8">Error loading rules</td></tr>';
                    }
                });
        }
        
        // Other functions (loadUsers, loadIdsMode, loadLogs, etc.)
       function loadUsers() {
    fetch('/api/users')
        .then(response => response.json())
        .then(data => {
            const tbody = document.getElementById('users-table-body');
            if (!tbody) return;
            if (!data.users || data.users.length === 0) {
                tbody.innerHTML = '<tr><td colspan="2">No users found</td></tr>';
                return;
            }
            tbody.innerHTML = data.users.map(user => `
                <tr>
                    <td>${user}</td>
                    <td>
                        <button class="button button-danger delete-user-btn" data-user="${user}">Delete</button>
                    </td>
                </tr>
            `).join('');
            // Add delete handlers
            document.querySelectorAll('.delete-user-btn').forEach(btn => {
                btn.addEventListener('click', function() {
                    const username = this.getAttribute('data-user');
                    if (confirm(`Delete user ${username}?`)) {
                        fetch(`/api/users/${username}`, { method: 'DELETE' })
                            .then(response => response.json())
                            .then(data => {
                                if (data.success) loadUsers();
                                else alert(data.error || 'Failed to delete user');
                            });
                    }
                });
            });
        })
        .catch(error => {
            console.error('Error loading users:', error);
            const tbody = document.getElementById('users-table-body');
            if (tbody) tbody.innerHTML = '<tr><td colspan="2">Error loading users</td></tr>';
        });
}

function loadLogs() {
    fetch('/api/logs')
        .then(response => response.json())
        .then(data => {
            const logsContainer = document.getElementById('logs-container');
            if (!logsContainer) return;
            if (!data.logs || data.logs.length === 0) {
                logsContainer.innerHTML = '<div>No logs found</div>';
                return;
            }
            logsContainer.innerHTML = data.logs.reverse().map(log => {
                const logClass = log.includes('[INFO]') ? 'log-info' :
                                 log.includes('[WARNING]') ? 'log-warning' :
                                 log.includes('[ERROR]') ? 'log-error' : '';
                return `<div class="log-entry ${logClass}">${log}</div>`;
            }).join('');
        })
        .catch(error => {
            console.error('Error loading logs:', error);
            const logsContainer = document.getElementById('logs-container');
            if (logsContainer) logsContainer.innerHTML = '<div>Error loading logs</div>';
        });
}
function loadIdsMode() {
    fetch('/api/ids_mode')
        .then(response => response.json())
        .then(data => {
            document.getElementById('ids-mode').textContent = data.mode;
        })
        .catch(error => {
            console.error('Error loading IDS/IPS mode:', error);
            document.getElementById('ids-mode').textContent = 'Error';
        });
}

document.addEventListener('DOMContentLoaded', function() {
    const switchBtn = document.getElementById('switch-ids-mode-btn');
    if (switchBtn) {
        switchBtn.addEventListener('click', function() {
            fetch('/api/ids_mode', { method: 'POST' })
                .then(response => response.json())
                .then(data => {
                    document.getElementById('ids-mode').textContent = data.mode;
                })
                .catch(error => {
                    console.error('Error switching IDS/IPS mode:', error);
                });
        });
    }
});


</script>
</body>
</html>
'''
        
        with open('templates/login.html', 'w') as f:
            f.write(login_html.strip())
            
        with open('templates/index.html', 'w') as f:
            f.write(index_html.strip())
    
    # === Rule Management Menu ===
    def rule_management_menu(self):
        """Handle rule management submenu"""
        while True:
            print("\nRule Management")
            print("1 - Add a firewall rule")
            print("2 - View existing rules")
            print("3 - Manage order")
            print("4 - Delete rules")
            print("5 - Exit to main menu")
            
            choice = input("Select option: ")
            
            if choice == '1':
                self.add_rule()
            elif choice == '2':
                self.view_rules()
            elif choice == '3':
                self.manage_rule_order()
            elif choice == '4':
                self.delete_rule()
            elif choice == '5':
                return
            else:
                print("Invalid option.")
    
    def main_menu(self):
        """Display and handle main menu"""
        # Start the firewall by default
        if not self.firewall_running:
            self.start_firewall()
            
        while True:
            print("\n" + "="*30)
            print("PyFirewall Main Menu")
            print("1 - Manage rules")
            print("2 - System Security")
            print("3 - IDS/IPS Management")
            print("4 - System Logs")
            print("5 - Firewall Manage")
            print("6 - Network Manager")
            print("7 - Open in GUI Mode")
            print("8 - Exit")
            print("="*30)
            
            choice = input("Select option: ")
            
            if choice == '1':
                self.rule_management_menu()
            elif choice == '2':
                self.user_management_menu()
            elif choice == '3':
                self.ids_ips_management_menu()
            elif choice == '4':
                self.view_system_logs()
            elif choice == '5':
                self.firewall_management_menu()
            elif choice == '6':
                self.network_management_menu()
            elif choice == '7':
                self.start_gui_mode()
            elif choice == '8':
                logger.info(f"{self.current_user} exited the firewall")
                print("Thank you for using PyFirewall.")
                sys.exit(0)
            else:
                print("Invalid option.")

# Global instance of the firewall for Flask routes to use
fw = PyFirewall()

# Flask routes
@app.route('/')
def home():
    if 'username' not in session:
        return redirect(url_for('login'))
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        try:
            with open(fw.users_file, 'r') as f:
                users = json.load(f)
                
            if username in users and sha256_crypt.verify(password, users[username]):
                session['username'] = username
                logger.info(f"GUI login successful: {username}")
                return redirect(url_for('home'))
            
            logger.error(f"GUI invalid login attempt for user: {username}")
            flash('Invalid username or password')
            
        except Exception as e:
            logger.error(f"GUI login error: {str(e)}")
            flash('An error occurred during login')
            
    return render_template('login.html')

@app.route('/logout')
def logout():
    username = session.pop('username', None)
    if username:
        logger.info(f"GUI user logged out: {username}")
    return redirect(url_for('login'))

# API routes for the GUI to interact with the firewall
@app.route('/api/rules', methods=['GET'])
def get_rules():
    if 'username' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    try:
        with open(fw.rules_file, 'r') as f:
            rules = json.load(f)
        return jsonify(rules)
    except Exception as e:
        logger.error(f"Error retrieving rules: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/rules', methods=['POST'])
def add_rule_api():
    if 'username' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    try:
        rule_data = request.json
        
        # Validate the rule data
        required_fields = ['name', 'src_ip', 'dst_ip', 'protocol', 'port', 'action', 'direction']
        for field in required_fields:
            if field not in rule_data:
                return jsonify({'error': f'Missing field: {field}'}), 400
        
        # Set default values
        rule_data['src_ip'] = rule_data['src_ip'] or 'any'
        rule_data['dst_ip'] = rule_data['dst_ip'] or 'any'
        rule_data['port'] = rule_data['port'] or 'any'
        rule_data['permanent'] = rule_data.get('permanent', False)
        
        # Validate protocols and actions
        if rule_data['protocol'] not in ['tcp', 'udp', 'icmp', 'all']:
            rule_data['protocol'] = 'all'
        
        if rule_data['action'] not in ['allow', 'deny']:
            rule_data['action'] = 'deny'
            
        if rule_data['direction'] not in ['in', 'out', 'both']:
            rule_data['direction'] = 'both'
        
        # Add the rule
        with open(fw.rules_file, 'r') as f:
            rules = json.load(f)
        
        rules.append(rule_data)
        
        with open(fw.rules_file, 'w') as f:
            json.dump(rules, f, indent=4)
            
        # Apply the rule
        fw._apply_rule(rule_data)
        
        # Log the action
        log_message = f"{session['username']} (GUI) added rule '{rule_data['name']}' to {rule_data['action']} {rule_data['protocol']} traffic"
        if rule_data['action'] == 'allow':
            logger.info(log_message)
        else:
            logger.error(log_message)
        
        # Notify all clients about the update
        try:
            socketio.emit('rules_updated', {'action': 'add', 'rule': rule_data})
        except Exception as e:
            logger.error(f"Failed to emit socket event: {str(e)}")
        
        return jsonify({'success': True, 'rule': rule_data})
    
    except Exception as e:
        logger.error(f"Error adding rule: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/rules/<int:index>', methods=['DELETE'])
def delete_rule_api(index):
    if 'username' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    try:
        with open(fw.rules_file, 'r') as f:
            rules = json.load(f)
        
        if index < 0 or index >= len(rules):
            return jsonify({'error': 'Invalid rule index'}), 400
        
        rule = rules.pop(index)
        
        with open(fw.rules_file, 'w') as f:
            json.dump(rules, f, indent=4)
            
        # Remove the rule from iptables
        fw._remove_rule(rule)
        
        logger.warning(f"{session['username']} (GUI) deleted rule '{rule['name']}'")
        
        # Notify all clients about the update
        try:
            socketio.emit('rules_updated', {'action': 'delete', 'index': index})
        except Exception as e:
            logger.error(f"Failed to emit socket event: {str(e)}")
        
        return jsonify({'success': True})
    
    except Exception as e:
        logger.error(f"Error deleting rule: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/firewall/status', methods=['GET'])
def get_firewall_status():
    if 'username' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    return jsonify({'status': 'running' if fw.firewall_running else 'stopped'})

@app.route('/api/firewall/start', methods=['POST'])
def start_firewall_api():
    if 'username' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    try:
        fw.start_firewall()
        return jsonify({'success': True, 'status': 'running'})
    except Exception as e:
        logger.error(f"Error starting firewall: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/firewall/stop', methods=['POST'])
def stop_firewall_api():
    if 'username' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    try:
        fw.stop_firewall()
        return jsonify({'success': True, 'status': 'stopped'})
    except Exception as e:
        logger.error(f"Error stopping firewall: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/firewall/restart', methods=['POST'])
def restart_firewall_api():
    if 'username' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    try:
        fw.restart_firewall()
        return jsonify({'success': True, 'status': 'running'})
    except Exception as e:
        logger.error(f"Error restarting firewall: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/adapters', methods=['GET'])
def get_adapters():
    if 'username' not in session:
        return jsonify({'error': 'Not authenticated'}), 401

    adapters = []
    for adapter in fw.network_adapters:
        try:
            addrs = netifaces.ifaddresses(adapter)
            ipv4 = addrs.get(netifaces.AF_INET, [{}])[0].get('addr', 'N/A')
            mac = addrs.get(netifaces.AF_LINK, [{}])[0].get('addr', 'N/A')
        except Exception:
            ipv4 = 'N/A'
            mac = 'N/A'
        adapters.append({
            'name': adapter,
            'ip': ipv4,
            'mac': mac
        })
    return jsonify({'adapters': adapters})

@app.route('/api/logs', methods=['GET'])
def get_logs():
    if 'username' not in session:
        return jsonify({'error': 'Not authenticated'}), 401

    try:
        with open('firewall.log', 'r') as f:
            logs = f.readlines()
        return jsonify({'logs': logs[-100:]})  # Return last 100 lines
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/users', methods=['GET'])
def get_users():
    if 'username' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    try:
        with open(fw.users_file, 'r') as f:
            users = json.load(f)
        return jsonify({'users': list(users.keys())})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/rules/reorder', methods=['POST'])
def reorder_rules():
    if 'username' not in session:
        return jsonify({'error': 'Not authenticated'}), 401

    try:
        data = request.json
        old_index = int(data['oldIndex'])
        new_index = int(data['newIndex'])

        with open(fw.rules_file, 'r') as f:
            rules = json.load(f)

        if 0 <= old_index < len(rules) and 0 <= new_index < len(rules):
            # Move the rule
            rule = rules.pop(old_index)
            rules.insert(new_index, rule)

            # Save new order
            with open(fw.rules_file, 'w') as f:
                json.dump(rules, f, indent=4)

            # Reapply all rules to maintain the order
            fw._reapply_all_rules(rules)

            # Notify GUI clients about the rule reordering
            try:
                socketio.emit('rules_updated', {'action': 'reorder', 'rules': rules})
            except Exception as e:
                logger.error(f"Failed to emit socket event: {str(e)}")

            return jsonify({'success': True})

        return jsonify({'error': 'Invalid indices'}), 400

    except Exception as e:
        logger.error(f"Error reordering rules: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/users/<username>', methods=['DELETE'])  # <-- ADD THIS ROUTE
def delete_user_api(username):
    if 'username' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    try:
        with open(fw.users_file, 'r') as f:
            users = json.load(f)
            
        if username == 'admin':
            return jsonify({'error': 'Cannot delete admin user'}), 400
            
        if username in users:
            del users[username]
            
            with open(fw.users_file, 'w') as f:
                json.dump(users, f, indent=4)
                
            logger.warning(f"{session['username']} deleted user: {username}")
            socketio.emit('users_updated')
            
            return jsonify({'success': True})
            
        return jsonify({'error': 'User not found'}), 404
        
    except Exception as e:
        logger.error(f"Error deleting user: {str(e)}")
        return jsonify({'error': str(e)}), 500

# Socket.IO event handlers
@socketio.on('connect')
def handle_connect():
    if 'username' in session:
        logger.info(f"WebSocket connected: {session['username']}")
    else:
        logger.info("Unauthenticated WebSocket connection")

@socketio.on('disconnect')
def handle_disconnect():
    if 'username' in session:
        logger.info(f"WebSocket disconnected: {session['username']}")
    else:
        logger.info("Unauthenticated WebSocket disconnected")

@app.route('/api/ids_mode', methods=['GET'])
def get_ids_mode():
    if 'username' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    mode = "IDS" if fw.ids_mode else "IPS"
    return jsonify({'mode': mode})

@app.route('/api/ids_mode', methods=['POST'])
def switch_ids_mode():
    if 'username' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    fw.ids_mode = not fw.ids_mode
    mode = "IDS" if fw.ids_mode else "IPS"
    # Notify clients via Socket.IO
    try:
        socketio.emit('ids_mode_changed', {'mode': mode})
    except Exception as e:
        logger.error(f"Failed to emit socket event: {str(e)}")
    return jsonify({'mode': mode})


# Combined CLI and web server run function
def run_firewall():
    if os.geteuid() != 0:
        print("Error: This program must be run with root privileges.")
        sys.exit(1)
        
    if fw.authenticate():
        # Start web server in a separate thread
        web_thread = threading.Thread(target=socketio.run, 
                                    args=(app,), 
                                    kwargs={'host': '0.0.0.0', 'port': 5000, 'debug': False})
        web_thread.daemon = True
        web_thread.start()
        
        # Run CLI interface in main thread
        fw.main_menu()
    else:
        print("Authentication failed. Exiting.")
        sys.exit(1)

if __name__ == "__main__":
    print("="*50)
    print("PyFirewall - Linux-based Firewall")
    print("="*50)
    
    run_firewall()
