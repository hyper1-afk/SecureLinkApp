#!/usr/bin/env python3
"""
SecureLink Admin Management Tool
A simple command-line tool to manage employee/admin accounts.
Like a mini Active Directory for your SecureLink application.

Usage:
    python manage_admins.py list                    - List all employees
    python manage_admins.py add                     - Add new employee (interactive)
    python manage_admins.py add --email EMAIL --username USER --name "Full Name" --role admin --password PASS
    python manage_admins.py remove <username>       - Remove an employee
    python manage_admins.py reset-password <user>   - Reset password (interactive)
    python manage_admins.py promote <username>      - Promote to admin
    python manage_admins.py demote <username>       - Demote to support
    python manage_admins.py activate <username>     - Activate account
    python manage_admins.py deactivate <username>   - Deactivate account
    python manage_admins.py info <username>         - Show employee details

Copyright (c) 2026 SecureLink. All rights reserved.
"""

import sys
import argparse
import getpass
from datetime import datetime
from tabulate import tabulate

# Add current directory to path for imports
sys.path.insert(0, '.')

from admin import get_admin_manager, EmployeeRole


def colorize(text, color):
    """Add color to terminal output"""
    colors = {
        'green': '\033[92m',
        'red': '\033[91m',
        'yellow': '\033[93m',
        'blue': '\033[94m',
        'cyan': '\033[96m',
        'bold': '\033[1m',
        'end': '\033[0m'
    }
    return f"{colors.get(color, '')}{text}{colors['end']}"


def print_header():
    """Print tool header"""
    print()
    print(colorize("╔════════════════════════════════════════════════════════╗", 'cyan'))
    print(colorize("║      SecureLink Admin Management Tool                  ║", 'cyan'))
    print(colorize("║      Manage employee and admin accounts                ║", 'cyan'))
    print(colorize("╚════════════════════════════════════════════════════════╝", 'cyan'))
    print()


def list_employees(args):
    """List all employees"""
    manager = get_admin_manager()
    employees = manager.get_all_employees()
    
    if not employees:
        print(colorize("No employees found.", 'yellow'))
        print("Use 'python manage_admins.py add' to create your first employee.")
        return
    
    # Prepare table data
    table_data = []
    for emp in employees:
        status = colorize("✓ Active", 'green') if emp['is_active'] else colorize("✗ Inactive", 'red')
        role_color = 'red' if emp['role'] == 'admin' else ('yellow' if emp['role'] == 'manager' else 'blue')
        role = colorize(emp['role'].upper(), role_color)
        last_login = emp['last_login'][:10] if emp['last_login'] else 'Never'
        
        table_data.append([
            emp['id'],
            emp['username'],
            emp['full_name'],
            emp['email'],
            role,
            status,
            last_login
        ])
    
    headers = ['ID', 'Username', 'Full Name', 'Email', 'Role', 'Status', 'Last Login']
    print(tabulate(table_data, headers=headers, tablefmt='rounded_grid'))
    print(f"\nTotal: {len(employees)} employee(s)")


def add_employee(args):
    """Add a new employee"""
    manager = get_admin_manager()
    
    # Interactive mode if no args provided
    if not args.email:
        print(colorize("=== Add New Employee ===", 'bold'))
        print()
        email = input("Email: ").strip()
        username = input("Username: ").strip()
        full_name = input("Full Name: ").strip()
        phone = input("Phone (optional): ").strip() or None
        
        print("\nRoles: admin, manager, support")
        role = input("Role [support]: ").strip().lower() or 'support'
        
        password = getpass.getpass("Password: ")
        confirm = getpass.getpass("Confirm Password: ")
        
        if password != confirm:
            print(colorize("Error: Passwords do not match!", 'red'))
            return
    else:
        email = args.email
        username = args.username
        full_name = args.name
        phone = args.phone
        role = args.role or 'support'
        password = args.password or getpass.getpass("Password: ")
    
    # Validate role
    valid_roles = ['admin', 'manager', 'support']
    if role not in valid_roles:
        print(colorize(f"Error: Invalid role. Must be one of: {', '.join(valid_roles)}", 'red'))
        return
    
    # Create employee
    result = manager.create_employee(
        email=email,
        username=username,
        password=password,
        full_name=full_name,
        role=role,
        phone=phone
    )
    
    if result['success']:
        print()
        print(colorize("✓ Employee created successfully!", 'green'))
        print(f"  Username: {username}")
        print(f"  Email: {email}")
        print(f"  Role: {role}")
        print()
        print(f"They can now log in at: http://localhost:5000/admin/login")
    else:
        print(colorize(f"✗ Error: {result['error']}", 'red'))


def remove_employee(args):
    """Remove an employee"""
    manager = get_admin_manager()
    session = manager.get_session()
    
    try:
        from admin import Employee
        emp = session.query(Employee).filter(
            (Employee.username == args.username) | (Employee.email == args.username)
        ).first()
        
        if not emp:
            print(colorize(f"Error: Employee '{args.username}' not found.", 'red'))
            return
        
        # Confirm deletion
        print(f"\nAbout to delete: {emp.full_name} ({emp.email})")
        confirm = input("Are you sure? (yes/no): ").strip().lower()
        
        if confirm != 'yes':
            print("Cancelled.")
            return
        
        result = manager.delete_employee(emp.id)
        
        if result['success']:
            print(colorize(f"✓ Employee '{emp.username}' has been removed.", 'green'))
        else:
            print(colorize(f"✗ Error: {result['error']}", 'red'))
    finally:
        session.close()


def reset_password(args):
    """Reset an employee's password"""
    manager = get_admin_manager()
    session = manager.get_session()
    
    try:
        from admin import Employee
        emp = session.query(Employee).filter(
            (Employee.username == args.username) | (Employee.email == args.username)
        ).first()
        
        if not emp:
            print(colorize(f"Error: Employee '{args.username}' not found.", 'red'))
            return
        
        print(f"\nResetting password for: {emp.full_name} ({emp.email})")
        
        new_password = getpass.getpass("New Password: ")
        confirm = getpass.getpass("Confirm Password: ")
        
        if new_password != confirm:
            print(colorize("Error: Passwords do not match!", 'red'))
            return
        
        result = manager.update_employee(emp.id, {'password': new_password})
        
        if result['success']:
            print(colorize(f"✓ Password reset successfully for '{emp.username}'.", 'green'))
        else:
            print(colorize(f"✗ Error: {result['error']}", 'red'))
    finally:
        session.close()


def change_role(args, new_role):
    """Change an employee's role"""
    manager = get_admin_manager()
    session = manager.get_session()
    
    try:
        from admin import Employee
        emp = session.query(Employee).filter(
            (Employee.username == args.username) | (Employee.email == args.username)
        ).first()
        
        if not emp:
            print(colorize(f"Error: Employee '{args.username}' not found.", 'red'))
            return
        
        if emp.role == new_role:
            print(colorize(f"Employee is already a {new_role}.", 'yellow'))
            return
        
        result = manager.update_employee(emp.id, {'role': new_role})
        
        if result['success']:
            print(colorize(f"✓ {emp.full_name} is now a {new_role.upper()}.", 'green'))
        else:
            print(colorize(f"✗ Error: {result['error']}", 'red'))
    finally:
        session.close()


def toggle_active(args, active):
    """Activate or deactivate an employee"""
    manager = get_admin_manager()
    session = manager.get_session()
    
    try:
        from admin import Employee
        emp = session.query(Employee).filter(
            (Employee.username == args.username) | (Employee.email == args.username)
        ).first()
        
        if not emp:
            print(colorize(f"Error: Employee '{args.username}' not found.", 'red'))
            return
        
        if emp.is_active == active:
            status = "active" if active else "inactive"
            print(colorize(f"Employee is already {status}.", 'yellow'))
            return
        
        result = manager.update_employee(emp.id, {'is_active': active})
        
        if result['success']:
            status = "activated" if active else "deactivated"
            print(colorize(f"✓ {emp.full_name} has been {status}.", 'green'))
        else:
            print(colorize(f"✗ Error: {result['error']}", 'red'))
    finally:
        session.close()


def show_info(args):
    """Show detailed employee info"""
    manager = get_admin_manager()
    session = manager.get_session()
    
    try:
        from admin import Employee
        emp = session.query(Employee).filter(
            (Employee.username == args.username) | (Employee.email == args.username)
        ).first()
        
        if not emp:
            print(colorize(f"Error: Employee '{args.username}' not found.", 'red'))
            return
        
        print()
        print(colorize(f"═══ Employee Details: {emp.full_name} ═══", 'bold'))
        print()
        print(f"  ID:         {emp.id}")
        print(f"  Username:   {emp.username}")
        print(f"  Email:      {emp.email}")
        print(f"  Full Name:  {emp.full_name}")
        print(f"  Phone:      {emp.phone or 'Not set'}")
        print()
        
        role_color = 'red' if emp.role == 'admin' else ('yellow' if emp.role == 'manager' else 'blue')
        print(f"  Role:       {colorize(emp.role.upper(), role_color)}")
        
        status = colorize("Active", 'green') if emp.is_active else colorize("Inactive", 'red')
        print(f"  Status:     {status}")
        print()
        print(f"  Created:    {emp.created_at.strftime('%Y-%m-%d %H:%M') if emp.created_at else 'Unknown'}")
        print(f"  Last Login: {emp.last_login.strftime('%Y-%m-%d %H:%M') if emp.last_login else 'Never'}")
        print()
        
        # Show assigned tickets count
        ticket_count = len(emp.assigned_tickets) if emp.assigned_tickets else 0
        print(f"  Assigned Tickets: {ticket_count}")
        print()
    finally:
        session.close()


def set_role(args):
    """Set employee role to a specific value"""
    valid_roles = ['admin', 'manager', 'support']
    if args.role not in valid_roles:
        print(colorize(f"Error: Invalid role. Must be one of: {', '.join(valid_roles)}", 'red'))
        return
    change_role(args, args.role)


def main():
    parser = argparse.ArgumentParser(
        description='SecureLink Admin Management Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python manage_admins.py list
  python manage_admins.py add
  python manage_admins.py add --email john@example.com --username john --name "John Doe" --role admin
  python manage_admins.py remove john
  python manage_admins.py reset-password john
  python manage_admins.py set-role john --role manager
  python manage_admins.py activate john
  python manage_admins.py deactivate john
  python manage_admins.py info john
        """
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # List command
    subparsers.add_parser('list', help='List all employees')
    
    # Add command
    add_parser = subparsers.add_parser('add', help='Add a new employee')
    add_parser.add_argument('--email', '-e', help='Employee email')
    add_parser.add_argument('--username', '-u', help='Username for login')
    add_parser.add_argument('--name', '-n', help='Full name')
    add_parser.add_argument('--phone', '-p', help='Phone number (optional)')
    add_parser.add_argument('--role', '-r', choices=['admin', 'manager', 'support'], help='Employee role')
    add_parser.add_argument('--password', help='Password (will prompt if not provided)')
    
    # Remove command
    remove_parser = subparsers.add_parser('remove', help='Remove an employee')
    remove_parser.add_argument('username', help='Username or email of employee to remove')
    
    # Reset password command
    reset_parser = subparsers.add_parser('reset-password', help='Reset employee password')
    reset_parser.add_argument('username', help='Username or email')
    
    # Set role command
    role_parser = subparsers.add_parser('set-role', help='Set employee role')
    role_parser.add_argument('username', help='Username or email')
    role_parser.add_argument('--role', '-r', required=True, choices=['admin', 'manager', 'support'], help='New role')
    
    # Promote/demote shortcuts
    promote_parser = subparsers.add_parser('promote', help='Promote to admin')
    promote_parser.add_argument('username', help='Username or email')
    
    demote_parser = subparsers.add_parser('demote', help='Demote to support')
    demote_parser.add_argument('username', help='Username or email')
    
    # Activate/deactivate
    activate_parser = subparsers.add_parser('activate', help='Activate an account')
    activate_parser.add_argument('username', help='Username or email')
    
    deactivate_parser = subparsers.add_parser('deactivate', help='Deactivate an account')
    deactivate_parser.add_argument('username', help='Username or email')
    
    # Info command
    info_parser = subparsers.add_parser('info', help='Show employee details')
    info_parser.add_argument('username', help='Username or email')
    
    args = parser.parse_args()
    
    print_header()
    
    if not args.command:
        parser.print_help()
        return
    
    # Install tabulate if needed
    try:
        from tabulate import tabulate
    except ImportError:
        print("Installing required package: tabulate...")
        import subprocess
        subprocess.check_call([sys.executable, '-m', 'pip', 'install', 'tabulate', '-q'])
        from tabulate import tabulate
    
    # Execute command
    commands = {
        'list': list_employees,
        'add': add_employee,
        'remove': remove_employee,
        'reset-password': reset_password,
        'set-role': set_role,
        'promote': lambda a: change_role(a, 'admin'),
        'demote': lambda a: change_role(a, 'support'),
        'activate': lambda a: toggle_active(a, True),
        'deactivate': lambda a: toggle_active(a, False),
        'info': show_info,
    }
    
    if args.command in commands:
        commands[args.command](args)
    else:
        parser.print_help()


if __name__ == '__main__':
    main()
