#!/usr/bin/env python3
"""
SecureLink Admin Manager - Desktop Application (Multi-Environment)
A graphical interface for managing employee/admin accounts.
Supports both local and production database connections.

Double-click this file or run: python admin_manager_gui.py

Copyright (c) 2026 Ryan Haley. All Rights Reserved.
"""

import sys
import os
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
from datetime import datetime

# Add project directory to path
PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, PROJECT_DIR)

# Import environment config
from env_config import (
    load_config, save_config, get_current_environment, 
    get_environment_config, set_current_environment, 
    get_database_url, list_environments, update_environment
)

from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

# Import admin models
from admin import get_admin_manager, EmployeeRole, Employee, Base


class DatabaseConnection:
    """Manages database connections for different environments"""
    
    def __init__(self, env_name=None):
        self.env_name = env_name or get_current_environment()
        self.engine = None
        self.Session = None
        self._connect()
    
    def _connect(self):
        """Establish database connection"""
        db_url = get_database_url(self.env_name)
        if not db_url:
            raise ValueError(f"No database URL configured for environment: {self.env_name}")
        
        self.engine = create_engine(db_url)
        self.Session = sessionmaker(bind=self.engine)
    
    def get_session(self):
        return self.Session()
    
    def test_connection(self):
        """Test if the database connection works"""
        try:
            session = self.get_session()
            session.execute(text("SELECT 1"))
            session.close()
            return True, "Connection successful"
        except Exception as e:
            return False, str(e)


class AdminManagerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("SecureLink Admin Manager")
        self.root.geometry("950x650")
        self.root.minsize(850, 550)
        
        # Set icon if available
        try:
            self.root.iconbitmap(os.path.join(PROJECT_DIR, 'icon.ico'))
        except:
            pass
        
        # Colors - Dark theme
        self.colors = {
            'bg': '#0f172a',
            'card': '#1e293b',
            'primary': '#0ea5e9',
            'success': '#10b981',
            'warning': '#f59e0b',
            'danger': '#ef4444',
            'text': '#f8fafc',
            'text_secondary': '#94a3b8',
            'border': '#334155'
        }
        
        self.root.configure(bg=self.colors['bg'])
        
        # Configure styles
        self.setup_styles()
        
        # Environment and database
        self.current_env = get_current_environment()
        self.db_connection = None
        self.manager = None
        
        # Build UI
        self.create_header()
        self.create_environment_bar()
        self.create_toolbar()
        self.create_employee_list()
        self.create_status_bar()
        
        # Connect and load data
        self.connect_to_database()
        
        # Bind keyboard shortcuts
        self.root.bind('<F5>', lambda e: self.refresh_employees())
        self.root.bind('<Control-n>', lambda e: self.add_employee())
        self.root.bind('<Delete>', lambda e: self.delete_employee())
    
    def setup_styles(self):
        """Configure ttk styles for dark theme"""
        style = ttk.Style()
        style.theme_use('clam')
        
        # Treeview (table) style
        style.configure("Treeview",
            background=self.colors['card'],
            foreground=self.colors['text'],
            fieldbackground=self.colors['card'],
            borderwidth=0,
            rowheight=35
        )
        style.configure("Treeview.Heading",
            background=self.colors['border'],
            foreground=self.colors['text'],
            borderwidth=0,
            font=('Segoe UI', 10, 'bold')
        )
        style.map("Treeview",
            background=[('selected', self.colors['primary'])],
            foreground=[('selected', 'white')]
        )
        
        # Button styles
        style.configure("Primary.TButton",
            background=self.colors['primary'],
            foreground='white',
            padding=(15, 8),
            font=('Segoe UI', 10)
        )
        style.configure("Danger.TButton",
            background=self.colors['danger'],
            foreground='white',
            padding=(15, 8)
        )
        style.configure("TButton",
            background=self.colors['border'],
            foreground=self.colors['text'],
            padding=(15, 8),
            font=('Segoe UI', 10)
        )
        
        # Frame style
        style.configure("Card.TFrame", background=self.colors['card'])
        style.configure("TLabel", background=self.colors['bg'], foreground=self.colors['text'])
    
    def create_header(self):
        """Create header section"""
        header = tk.Frame(self.root, bg=self.colors['card'], height=70)
        header.pack(fill='x', padx=0, pady=0)
        header.pack_propagate(False)
        
        # Logo/Title
        title_frame = tk.Frame(header, bg=self.colors['card'])
        title_frame.pack(side='left', padx=20, pady=15)
        
        tk.Label(title_frame, text="🛡️", font=('Segoe UI', 24), 
                bg=self.colors['card'], fg=self.colors['primary']).pack(side='left')
        
        title_text = tk.Frame(title_frame, bg=self.colors['card'])
        title_text.pack(side='left', padx=10)
        
        tk.Label(title_text, text="SecureLink Admin Manager", 
                font=('Segoe UI', 14, 'bold'),
                bg=self.colors['card'], fg=self.colors['text']).pack(anchor='w')
        tk.Label(title_text, text="Manage employee and admin accounts", 
                font=('Segoe UI', 9),
                bg=self.colors['card'], fg=self.colors['text_secondary']).pack(anchor='w')
        
        # Stats in header
        self.stats_frame = tk.Frame(header, bg=self.colors['card'])
        self.stats_frame.pack(side='right', padx=20)
        
        self.stats_label = tk.Label(self.stats_frame, text="", 
                font=('Segoe UI', 10),
                bg=self.colors['card'], fg=self.colors['text_secondary'])
        self.stats_label.pack()
    
    def create_environment_bar(self):
        """Create environment selector bar"""
        env_bar = tk.Frame(self.root, bg=self.colors['border'], height=45)
        env_bar.pack(fill='x', padx=0, pady=0)
        env_bar.pack_propagate(False)
        
        inner = tk.Frame(env_bar, bg=self.colors['border'])
        inner.pack(fill='both', expand=True, padx=20, pady=8)
        
        tk.Label(inner, text="Environment:", 
            font=('Segoe UI', 10),
            bg=self.colors['border'], fg=self.colors['text']).pack(side='left')
        
        # Environment dropdown
        self.env_var = tk.StringVar(value=self.current_env)
        self.env_dropdown = ttk.Combobox(inner, textvariable=self.env_var, 
            state='readonly', width=20)
        self.update_env_dropdown()
        self.env_dropdown.pack(side='left', padx=(10, 0))
        self.env_dropdown.bind('<<ComboboxSelected>>', self.on_environment_change)
        
        # Connection status indicator
        self.conn_status = tk.Label(inner, text="● Disconnected", 
            font=('Segoe UI', 10),
            bg=self.colors['border'], fg=self.colors['danger'])
        self.conn_status.pack(side='left', padx=(20, 0))
        
        # Settings button
        tk.Button(inner, text="⚙️ Settings", 
            command=self.open_settings,
            bg=self.colors['card'], fg=self.colors['text'],
            font=('Segoe UI', 9), relief='flat', padx=10, pady=3,
            cursor='hand2').pack(side='right')
        
        # Test connection button
        tk.Button(inner, text="🔌 Test", 
            command=self.test_connection,
            bg=self.colors['card'], fg=self.colors['text'],
            font=('Segoe UI', 9), relief='flat', padx=10, pady=3,
            cursor='hand2').pack(side='right', padx=(0, 10))
    
    def update_env_dropdown(self):
        """Update the environment dropdown with available environments"""
        envs = list_environments()
        self.env_dropdown['values'] = [e['name'] for e in envs]
    
    def on_environment_change(self, event=None):
        """Handle environment change"""
        new_env = self.env_var.get()
        if new_env != self.current_env:
            if messagebox.askyesno("Switch Environment", 
                    f"Switch to {new_env} environment?\n\nThis will connect to a different database."):
                self.current_env = new_env
                set_current_environment(new_env)
                self.connect_to_database()
            else:
                self.env_var.set(self.current_env)
    
    def connect_to_database(self):
        """Connect to the current environment's database"""
        self.conn_status.config(text="● Connecting...", fg=self.colors['warning'])
        self.root.update()
        
        try:
            env_config = get_environment_config(self.current_env)
            db_url = get_database_url(self.current_env)
            
            if not db_url or (env_config.get('database_type') == 'postgresql' and not env_config.get('database_url')):
                self.conn_status.config(text="● Not Configured", fg=self.colors['danger'])
                self.status_label.config(text=f"Environment '{self.current_env}' needs configuration - click Settings")
                return
            
            self.db_connection = DatabaseConnection(self.current_env)
            
            # Create tables if they don't exist
            Base.metadata.create_all(self.db_connection.engine)
            
            # Also update the manager for local operations
            if self.current_env == 'local':
                self.manager = get_admin_manager()
            else:
                self.manager = None  # Use direct DB access for remote
            
            db_type = env_config.get('database_type', 'unknown').upper()
            self.conn_status.config(text=f"● Connected ({db_type})", fg=self.colors['success'])
            self.refresh_employees()
            
        except Exception as e:
            self.conn_status.config(text="● Connection Failed", fg=self.colors['danger'])
            self.status_label.config(text=f"Error: {str(e)[:50]}...")
            messagebox.showerror("Connection Error", f"Failed to connect to database:\n\n{str(e)}")
    
    def test_connection(self):
        """Test the current database connection"""
        try:
            db_url = get_database_url(self.current_env)
            if not db_url:
                messagebox.showerror("Error", "No database URL configured for this environment.\n\nClick Settings to configure.")
                return
            
            test_conn = DatabaseConnection(self.current_env)
            success, message = test_conn.test_connection()
            
            if success:
                messagebox.showinfo("Success", f"✓ Connection successful!\n\nEnvironment: {self.current_env}")
            else:
                messagebox.showerror("Failed", f"Connection failed:\n\n{message}")
        except Exception as e:
            messagebox.showerror("Error", f"Connection error:\n\n{str(e)}")
    
    def open_settings(self):
        """Open environment settings dialog"""
        dialog = EnvironmentSettingsDialog(self.root, self.colors, self.current_env)
        self.root.wait_window(dialog.top)
        
        if dialog.result:
            update_environment(self.current_env, dialog.result)
            self.update_env_dropdown()
            self.connect_to_database()
    
    def create_toolbar(self):
        """Create toolbar with action buttons"""
        toolbar = tk.Frame(self.root, bg=self.colors['bg'])
        toolbar.pack(fill='x', padx=20, pady=15)
        
        # Left side - action buttons
        left_buttons = tk.Frame(toolbar, bg=self.colors['bg'])
        left_buttons.pack(side='left')
        
        self.add_btn = tk.Button(left_buttons, text="➕ Add Employee", 
            command=self.add_employee,
            bg=self.colors['primary'], fg='white',
            font=('Segoe UI', 10, 'bold'),
            relief='flat', padx=15, pady=8, cursor='hand2')
        self.add_btn.pack(side='left', padx=(0, 10))
        
        self.edit_btn = tk.Button(left_buttons, text="✏️ Edit", 
            command=self.edit_employee,
            bg=self.colors['border'], fg=self.colors['text'],
            font=('Segoe UI', 10),
            relief='flat', padx=15, pady=8, cursor='hand2')
        self.edit_btn.pack(side='left', padx=(0, 10))
        
        self.delete_btn = tk.Button(left_buttons, text="🗑️ Delete", 
            command=self.delete_employee,
            bg=self.colors['border'], fg=self.colors['text'],
            font=('Segoe UI', 10),
            relief='flat', padx=15, pady=8, cursor='hand2')
        self.delete_btn.pack(side='left', padx=(0, 10))
        
        self.reset_pwd_btn = tk.Button(left_buttons, text="🔑 Reset Password", 
            command=self.reset_password,
            bg=self.colors['border'], fg=self.colors['text'],
            font=('Segoe UI', 10),
            relief='flat', padx=15, pady=8, cursor='hand2')
        self.reset_pwd_btn.pack(side='left', padx=(0, 10))
        
        # Right side - refresh
        right_buttons = tk.Frame(toolbar, bg=self.colors['bg'])
        right_buttons.pack(side='right')
        
        self.refresh_btn = tk.Button(right_buttons, text="🔄 Refresh", 
            command=self.refresh_employees,
            bg=self.colors['border'], fg=self.colors['text'],
            font=('Segoe UI', 10),
            relief='flat', padx=15, pady=8, cursor='hand2')
        self.refresh_btn.pack(side='right')
    
    def create_employee_list(self):
        """Create the employee list table"""
        # Container frame
        container = tk.Frame(self.root, bg=self.colors['bg'])
        container.pack(fill='both', expand=True, padx=20, pady=(0, 10))
        
        # Table frame with border
        table_frame = tk.Frame(container, bg=self.colors['border'])
        table_frame.pack(fill='both', expand=True)
        
        inner_frame = tk.Frame(table_frame, bg=self.colors['card'])
        inner_frame.pack(fill='both', expand=True, padx=1, pady=1)
        
        # Columns
        columns = ('id', 'username', 'fullname', 'email', 'role', 'status', 'lastlogin')
        
        self.tree = ttk.Treeview(inner_frame, columns=columns, show='headings', selectmode='browse')
        
        # Define headings
        self.tree.heading('id', text='ID')
        self.tree.heading('username', text='Username')
        self.tree.heading('fullname', text='Full Name')
        self.tree.heading('email', text='Email')
        self.tree.heading('role', text='Role')
        self.tree.heading('status', text='Status')
        self.tree.heading('lastlogin', text='Last Login')
        
        # Column widths
        self.tree.column('id', width=50, anchor='center')
        self.tree.column('username', width=100)
        self.tree.column('fullname', width=150)
        self.tree.column('email', width=200)
        self.tree.column('role', width=80, anchor='center')
        self.tree.column('status', width=80, anchor='center')
        self.tree.column('lastlogin', width=100, anchor='center')
        
        # Scrollbar
        scrollbar = ttk.Scrollbar(inner_frame, orient='vertical', command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        
        self.tree.pack(side='left', fill='both', expand=True)
        scrollbar.pack(side='right', fill='y')
        
        # Double-click to edit
        self.tree.bind('<Double-1>', lambda e: self.edit_employee())
        
        # Right-click menu
        self.context_menu = tk.Menu(self.root, tearoff=0, 
            bg=self.colors['card'], fg=self.colors['text'],
            activebackground=self.colors['primary'], activeforeground='white')
        self.context_menu.add_command(label="Edit", command=self.edit_employee)
        self.context_menu.add_command(label="Reset Password", command=self.reset_password)
        self.context_menu.add_separator()
        self.context_menu.add_command(label="Promote to Admin", command=lambda: self.change_role('admin'))
        self.context_menu.add_command(label="Set as Manager", command=lambda: self.change_role('manager'))
        self.context_menu.add_command(label="Set as Support", command=lambda: self.change_role('support'))
        self.context_menu.add_separator()
        self.context_menu.add_command(label="Activate", command=lambda: self.toggle_active(True))
        self.context_menu.add_command(label="Deactivate", command=lambda: self.toggle_active(False))
        self.context_menu.add_separator()
        self.context_menu.add_command(label="Delete", command=self.delete_employee)
        
        self.tree.bind('<Button-3>', self.show_context_menu)
    
    def create_status_bar(self):
        """Create status bar at bottom"""
        self.status_bar = tk.Frame(self.root, bg=self.colors['card'], height=30)
        self.status_bar.pack(fill='x', side='bottom')
        self.status_bar.pack_propagate(False)
        
        self.status_label = tk.Label(self.status_bar, text="Ready", 
            font=('Segoe UI', 9),
            bg=self.colors['card'], fg=self.colors['text_secondary'])
        self.status_label.pack(side='left', padx=15, pady=5)
        
        # Environment indicator
        self.env_status_label = tk.Label(self.status_bar, 
            text="", 
            font=('Segoe UI', 9),
            bg=self.colors['card'], fg=self.colors['text_secondary'])
        self.env_status_label.pack(side='right', padx=15, pady=5)
    
    def show_context_menu(self, event):
        """Show right-click context menu"""
        item = self.tree.identify_row(event.y)
        if item:
            self.tree.selection_set(item)
            self.context_menu.post(event.x_root, event.y_root)
    
    def refresh_employees(self):
        """Refresh the employee list"""
        if not self.db_connection:
            return
            
        self.status_label.config(text="Refreshing...")
        self.root.update()
        
        # Clear existing items
        for item in self.tree.get_children():
            self.tree.delete(item)
        
        try:
            # Get employees from database
            session = self.db_connection.get_session()
            employees_query = session.query(Employee).order_by(Employee.full_name).all()
            
            employees = []
            for emp in employees_query:
                employees.append({
                    'id': emp.id,
                    'username': emp.username,
                    'full_name': emp.full_name,
                    'email': emp.email,
                    'role': emp.role,
                    'is_active': emp.is_active,
                    'last_login': emp.last_login.strftime('%Y-%m-%d') if emp.last_login else None
                })
            session.close()
            
            # Count stats
            admins = sum(1 for e in employees if e['role'] == 'admin')
            managers = sum(1 for e in employees if e['role'] == 'manager')
            support = sum(1 for e in employees if e['role'] == 'support')
            active = sum(1 for e in employees if e['is_active'])
            
            # Update stats label
            self.stats_label.config(text=f"👥 {len(employees)} Total  |  🔴 {admins} Admins  |  🟡 {managers} Managers  |  🔵 {support} Support  |  ✓ {active} Active")
            
            # Insert data
            for emp in employees:
                status = "✓ Active" if emp['is_active'] else "✗ Inactive"
                last_login = emp['last_login'] if emp['last_login'] else "Never"
                role = emp['role'].upper()
                
                self.tree.insert('', 'end', values=(
                    emp['id'],
                    emp['username'],
                    emp['full_name'],
                    emp['email'],
                    role,
                    status,
                    last_login
                ))
            
            env_config = get_environment_config(self.current_env)
            self.env_status_label.config(text=f"Environment: {env_config.get('name', self.current_env)}")
            self.status_label.config(text=f"Loaded {len(employees)} employees")
            
        except Exception as e:
            self.status_label.config(text=f"Error: {str(e)[:50]}...")
    
    def get_selected_employee(self):
        """Get currently selected employee"""
        selection = self.tree.selection()
        if not selection:
            messagebox.showwarning("No Selection", "Please select an employee first.")
            return None
        
        item = self.tree.item(selection[0])
        values = item['values']
        return {
            'id': values[0],
            'username': values[1],
            'full_name': values[2],
            'email': values[3],
            'role': values[4].lower(),
            'is_active': 'Active' in values[5]
        }
    
    def add_employee(self):
        """Open dialog to add new employee"""
        if not self.db_connection:
            messagebox.showerror("Error", "Not connected to database")
            return
            
        dialog = EmployeeDialog(self.root, self.colors, title="Add New Employee")
        self.root.wait_window(dialog.top)
        
        if dialog.result:
            try:
                import secrets
                import hashlib
                
                session = self.db_connection.get_session()
                
                # Check if exists
                existing = session.query(Employee).filter(
                    (Employee.email == dialog.result['email']) | 
                    (Employee.username == dialog.result['username'])
                ).first()
                
                if existing:
                    messagebox.showerror("Error", "Email or username already exists")
                    session.close()
                    return
                
                salt = secrets.token_hex(32)
                password_hash = hashlib.sha256((dialog.result['password'] + salt).encode()).hexdigest()
                
                employee = Employee(
                    email=dialog.result['email'],
                    username=dialog.result['username'],
                    password_hash=password_hash,
                    salt=salt,
                    full_name=dialog.result['full_name'],
                    role=dialog.result['role'],
                    phone=dialog.result.get('phone')
                )
                
                session.add(employee)
                session.commit()
                session.close()
                
                messagebox.showinfo("Success", f"Employee '{dialog.result['username']}' created!")
                self.refresh_employees()
                
            except Exception as e:
                messagebox.showerror("Error", str(e))
    
    def edit_employee(self):
        """Edit selected employee"""
        emp = self.get_selected_employee()
        if not emp or not self.db_connection:
            return
        
        dialog = EmployeeDialog(self.root, self.colors, title="Edit Employee", employee=emp)
        self.root.wait_window(dialog.top)
        
        if dialog.result:
            try:
                session = self.db_connection.get_session()
                employee = session.query(Employee).filter(Employee.id == emp['id']).first()
                
                if employee:
                    employee.full_name = dialog.result['full_name']
                    employee.email = dialog.result['email']
                    employee.role = dialog.result['role']
                    if dialog.result.get('phone'):
                        employee.phone = dialog.result['phone']
                    
                    session.commit()
                    messagebox.showinfo("Success", "Employee updated!")
                    self.refresh_employees()
                
                session.close()
                
            except Exception as e:
                messagebox.showerror("Error", str(e))
    
    def delete_employee(self):
        """Delete selected employee"""
        emp = self.get_selected_employee()
        if not emp or not self.db_connection:
            return
        
        if messagebox.askyesno("Confirm Delete", 
                f"Are you sure you want to delete '{emp['full_name']}'?\n\nThis action cannot be undone."):
            try:
                session = self.db_connection.get_session()
                employee = session.query(Employee).filter(Employee.id == emp['id']).first()
                
                if employee:
                    session.delete(employee)
                    session.commit()
                    messagebox.showinfo("Success", "Employee deleted.")
                    self.refresh_employees()
                
                session.close()
                
            except Exception as e:
                messagebox.showerror("Error", str(e))
    
    def reset_password(self):
        """Reset password for selected employee"""
        emp = self.get_selected_employee()
        if not emp or not self.db_connection:
            return
        
        dialog = PasswordDialog(self.root, self.colors, emp['full_name'])
        self.root.wait_window(dialog.top)
        
        if dialog.result:
            try:
                import secrets
                import hashlib
                
                session = self.db_connection.get_session()
                employee = session.query(Employee).filter(Employee.id == emp['id']).first()
                
                if employee:
                    employee.salt = secrets.token_hex(32)
                    employee.password_hash = hashlib.sha256((dialog.result + employee.salt).encode()).hexdigest()
                    session.commit()
                    messagebox.showinfo("Success", f"Password reset for '{emp['username']}'.")
                
                session.close()
                
            except Exception as e:
                messagebox.showerror("Error", str(e))
    
    def change_role(self, new_role):
        """Change role for selected employee"""
        emp = self.get_selected_employee()
        if not emp or not self.db_connection:
            return
        
        try:
            session = self.db_connection.get_session()
            employee = session.query(Employee).filter(Employee.id == emp['id']).first()
            
            if employee:
                employee.role = new_role
                session.commit()
                self.status_label.config(text=f"Changed {emp['username']} to {new_role}")
                self.refresh_employees()
            
            session.close()
            
        except Exception as e:
            messagebox.showerror("Error", str(e))
    
    def toggle_active(self, active):
        """Activate or deactivate employee"""
        emp = self.get_selected_employee()
        if not emp or not self.db_connection:
            return
        
        try:
            session = self.db_connection.get_session()
            employee = session.query(Employee).filter(Employee.id == emp['id']).first()
            
            if employee:
                employee.is_active = active
                session.commit()
                status = "activated" if active else "deactivated"
                self.status_label.config(text=f"{emp['username']} {status}")
                self.refresh_employees()
            
            session.close()
            
        except Exception as e:
            messagebox.showerror("Error", str(e))


class EnvironmentSettingsDialog:
    """Dialog for configuring environment settings"""
    
    def __init__(self, parent, colors, env_name):
        self.result = None
        self.colors = colors
        self.env_name = env_name
        self.env_config = get_environment_config(env_name)
        
        self.top = tk.Toplevel(parent)
        self.top.title(f"Configure {env_name} Environment")
        self.top.geometry("500x420")
        self.top.configure(bg=colors['bg'])
        self.top.transient(parent)
        self.top.grab_set()
        
        self.top.geometry(f"+{parent.winfo_x() + 200}+{parent.winfo_y() + 100}")
        
        self.create_form()
    
    def create_form(self):
        main = tk.Frame(self.top, bg=self.colors['bg'])
        main.pack(fill='both', expand=True, padx=30, pady=20)
        
        tk.Label(main, text=f"Environment: {self.env_name}", 
            font=('Segoe UI', 14, 'bold'),
            bg=self.colors['bg'], fg=self.colors['text']).pack(anchor='w', pady=(0, 20))
        
        # Display Name
        tk.Label(main, text="Display Name", 
            font=('Segoe UI', 10),
            bg=self.colors['bg'], fg=self.colors['text_secondary']).pack(anchor='w', pady=(10, 2))
        
        self.name_entry = tk.Entry(main, font=('Segoe UI', 11),
            bg=self.colors['card'], fg=self.colors['text'],
            insertbackground=self.colors['text'], relief='flat')
        self.name_entry.pack(fill='x', ipady=8)
        self.name_entry.insert(0, self.env_config.get('name', ''))
        
        # Database Type
        tk.Label(main, text="Database Type", 
            font=('Segoe UI', 10),
            bg=self.colors['bg'], fg=self.colors['text_secondary']).pack(anchor='w', pady=(15, 2))
        
        self.db_type_var = tk.StringVar(value=self.env_config.get('database_type', 'sqlite'))
        type_frame = tk.Frame(main, bg=self.colors['bg'])
        type_frame.pack(fill='x')
        
        for db_type in ['sqlite', 'postgresql']:
            rb = tk.Radiobutton(type_frame, text=db_type.upper(), 
                variable=self.db_type_var, value=db_type,
                command=self.on_type_change,
                bg=self.colors['bg'], fg=self.colors['text'],
                selectcolor=self.colors['card'],
                activebackground=self.colors['bg'], activeforeground=self.colors['text'],
                font=('Segoe UI', 10))
            rb.pack(side='left', padx=(0, 20))
        
        # Database URL (for PostgreSQL)
        self.url_label = tk.Label(main, text="Database URL (PostgreSQL)", 
            font=('Segoe UI', 10),
            bg=self.colors['bg'], fg=self.colors['text_secondary'])
        self.url_label.pack(anchor='w', pady=(15, 2))
        
        self.url_entry = tk.Entry(main, font=('Segoe UI', 11),
            bg=self.colors['card'], fg=self.colors['text'],
            insertbackground=self.colors['text'], relief='flat', show='*')
        self.url_entry.pack(fill='x', ipady=8)
        self.url_entry.insert(0, self.env_config.get('database_url', '') or '')
        
        # Database Path (for SQLite)
        self.path_label = tk.Label(main, text="Database Path (SQLite)", 
            font=('Segoe UI', 10),
            bg=self.colors['bg'], fg=self.colors['text_secondary'])
        self.path_label.pack(anchor='w', pady=(15, 2))
        
        self.path_entry = tk.Entry(main, font=('Segoe UI', 11),
            bg=self.colors['card'], fg=self.colors['text'],
            insertbackground=self.colors['text'], relief='flat')
        self.path_entry.pack(fill='x', ipady=8)
        self.path_entry.insert(0, self.env_config.get('database_path', '') or '')
        
        # App URL
        tk.Label(main, text="App URL (optional)", 
            font=('Segoe UI', 10),
            bg=self.colors['bg'], fg=self.colors['text_secondary']).pack(anchor='w', pady=(15, 2))
        
        self.app_url_entry = tk.Entry(main, font=('Segoe UI', 11),
            bg=self.colors['card'], fg=self.colors['text'],
            insertbackground=self.colors['text'], relief='flat')
        self.app_url_entry.pack(fill='x', ipady=8)
        self.app_url_entry.insert(0, self.env_config.get('app_url', '') or '')
        
        # Buttons
        btn_frame = tk.Frame(main, bg=self.colors['bg'])
        btn_frame.pack(fill='x', pady=(25, 0))
        
        tk.Button(btn_frame, text="Cancel", command=self.top.destroy,
            bg=self.colors['border'], fg=self.colors['text'],
            font=('Segoe UI', 10), relief='flat', padx=20, pady=8,
            cursor='hand2').pack(side='right', padx=(10, 0))
        
        tk.Button(btn_frame, text="Save", command=self.save,
            bg=self.colors['primary'], fg='white',
            font=('Segoe UI', 10, 'bold'), relief='flat', padx=20, pady=8,
            cursor='hand2').pack(side='right')
        
        self.on_type_change()
    
    def on_type_change(self):
        """Show/hide fields based on database type"""
        if self.db_type_var.get() == 'postgresql':
            self.url_label.config(fg=self.colors['text_secondary'])
            self.url_entry.config(state='normal')
            self.path_label.config(fg=self.colors['border'])
            self.path_entry.config(state='disabled')
        else:
            self.url_label.config(fg=self.colors['border'])
            self.url_entry.config(state='disabled')
            self.path_label.config(fg=self.colors['text_secondary'])
            self.path_entry.config(state='normal')
    
    def save(self):
        self.result = {
            'name': self.name_entry.get().strip(),
            'database_type': self.db_type_var.get(),
            'database_url': self.url_entry.get().strip() if self.db_type_var.get() == 'postgresql' else None,
            'database_path': self.path_entry.get().strip() if self.db_type_var.get() == 'sqlite' else None,
            'app_url': self.app_url_entry.get().strip()
        }
        self.top.destroy()


class EmployeeDialog:
    """Dialog for adding/editing employees"""
    
    def __init__(self, parent, colors, title="Employee", employee=None):
        self.result = None
        self.colors = colors
        self.employee = employee
        
        self.top = tk.Toplevel(parent)
        self.top.title(title)
        self.top.geometry("400x450")
        self.top.configure(bg=colors['bg'])
        self.top.transient(parent)
        self.top.grab_set()
        
        # Center on parent
        self.top.geometry(f"+{parent.winfo_x() + 250}+{parent.winfo_y() + 100}")
        
        self.create_form()
    
    def create_form(self):
        """Create the form"""
        # Main frame with padding
        main = tk.Frame(self.top, bg=self.colors['bg'])
        main.pack(fill='both', expand=True, padx=30, pady=20)
        
        # Title
        tk.Label(main, text="Employee Details", 
            font=('Segoe UI', 14, 'bold'),
            bg=self.colors['bg'], fg=self.colors['text']).pack(anchor='w', pady=(0, 20))
        
        # Form fields
        fields = [
            ('full_name', 'Full Name'),
            ('username', 'Username'),
            ('email', 'Email'),
            ('phone', 'Phone (optional)')
        ]
        
        self.entries = {}
        
        for field, label in fields:
            tk.Label(main, text=label, 
                font=('Segoe UI', 10),
                bg=self.colors['bg'], fg=self.colors['text_secondary']).pack(anchor='w', pady=(10, 2))
            
            entry = tk.Entry(main, font=('Segoe UI', 11),
                bg=self.colors['card'], fg=self.colors['text'],
                insertbackground=self.colors['text'],
                relief='flat', bd=0)
            entry.pack(fill='x', ipady=8, pady=(0, 5))
            
            # Pre-fill if editing
            if self.employee and field in self.employee:
                entry.insert(0, self.employee.get(field, '') or '')
            
            self.entries[field] = entry
        
        # Role dropdown
        tk.Label(main, text="Role", 
            font=('Segoe UI', 10),
            bg=self.colors['bg'], fg=self.colors['text_secondary']).pack(anchor='w', pady=(10, 2))
        
        self.role_var = tk.StringVar(value=self.employee['role'] if self.employee else 'support')
        role_frame = tk.Frame(main, bg=self.colors['bg'])
        role_frame.pack(fill='x', pady=(0, 5))
        
        for role in ['admin', 'manager', 'support']:
            rb = tk.Radiobutton(role_frame, text=role.capitalize(), variable=self.role_var, value=role,
                bg=self.colors['bg'], fg=self.colors['text'],
                selectcolor=self.colors['card'],
                activebackground=self.colors['bg'], activeforeground=self.colors['text'],
                font=('Segoe UI', 10))
            rb.pack(side='left', padx=(0, 20))
        
        # Password (only for new employees)
        if not self.employee:
            tk.Label(main, text="Password", 
                font=('Segoe UI', 10),
                bg=self.colors['bg'], fg=self.colors['text_secondary']).pack(anchor='w', pady=(10, 2))
            
            self.password_entry = tk.Entry(main, font=('Segoe UI', 11), show='•',
                bg=self.colors['card'], fg=self.colors['text'],
                insertbackground=self.colors['text'],
                relief='flat', bd=0)
            self.password_entry.pack(fill='x', ipady=8, pady=(0, 5))
        
        # Buttons
        btn_frame = tk.Frame(main, bg=self.colors['bg'])
        btn_frame.pack(fill='x', pady=(20, 0))
        
        tk.Button(btn_frame, text="Cancel", command=self.top.destroy,
            bg=self.colors['border'], fg=self.colors['text'],
            font=('Segoe UI', 10), relief='flat', padx=20, pady=8,
            cursor='hand2').pack(side='right', padx=(10, 0))
        
        tk.Button(btn_frame, text="Save", command=self.save,
            bg=self.colors['primary'], fg='white',
            font=('Segoe UI', 10, 'bold'), relief='flat', padx=20, pady=8,
            cursor='hand2').pack(side='right')
    
    def save(self):
        """Save the form"""
        self.result = {
            'full_name': self.entries['full_name'].get().strip(),
            'email': self.entries['email'].get().strip(),
            'role': self.role_var.get()
        }
        
        if not self.employee:
            self.result['username'] = self.entries['username'].get().strip()
            self.result['password'] = self.password_entry.get()
            
            if not self.result['password']:
                messagebox.showerror("Error", "Password is required")
                return
        
        phone = self.entries['phone'].get().strip()
        if phone:
            self.result['phone'] = phone
        
        if not self.result['full_name'] or not self.result['email']:
            messagebox.showerror("Error", "Full name and email are required")
            return
        
        self.top.destroy()


class PasswordDialog:
    """Dialog for resetting password"""
    
    def __init__(self, parent, colors, employee_name):
        self.result = None
        self.colors = colors
        
        self.top = tk.Toplevel(parent)
        self.top.title("Reset Password")
        self.top.geometry("350x250")
        self.top.configure(bg=colors['bg'])
        self.top.transient(parent)
        self.top.grab_set()
        
        # Center on parent
        self.top.geometry(f"+{parent.winfo_x() + 275}+{parent.winfo_y() + 175}")
        
        main = tk.Frame(self.top, bg=colors['bg'])
        main.pack(fill='both', expand=True, padx=30, pady=20)
        
        tk.Label(main, text=f"Reset Password for {employee_name}", 
            font=('Segoe UI', 12, 'bold'),
            bg=colors['bg'], fg=colors['text']).pack(anchor='w', pady=(0, 20))
        
        tk.Label(main, text="New Password", 
            font=('Segoe UI', 10),
            bg=colors['bg'], fg=colors['text_secondary']).pack(anchor='w', pady=(0, 2))
        
        self.pw1 = tk.Entry(main, font=('Segoe UI', 11), show='•',
            bg=colors['card'], fg=colors['text'],
            insertbackground=colors['text'], relief='flat')
        self.pw1.pack(fill='x', ipady=8, pady=(0, 10))
        
        tk.Label(main, text="Confirm Password", 
            font=('Segoe UI', 10),
            bg=colors['bg'], fg=colors['text_secondary']).pack(anchor='w', pady=(0, 2))
        
        self.pw2 = tk.Entry(main, font=('Segoe UI', 11), show='•',
            bg=colors['card'], fg=colors['text'],
            insertbackground=colors['text'], relief='flat')
        self.pw2.pack(fill='x', ipady=8, pady=(0, 10))
        
        btn_frame = tk.Frame(main, bg=colors['bg'])
        btn_frame.pack(fill='x', pady=(15, 0))
        
        tk.Button(btn_frame, text="Cancel", command=self.top.destroy,
            bg=colors['border'], fg=colors['text'],
            font=('Segoe UI', 10), relief='flat', padx=20, pady=8,
            cursor='hand2').pack(side='right', padx=(10, 0))
        
        tk.Button(btn_frame, text="Reset Password", command=self.save,
            bg=colors['primary'], fg='white',
            font=('Segoe UI', 10, 'bold'), relief='flat', padx=20, pady=8,
            cursor='hand2').pack(side='right')
        
        self.pw1.focus_set()
    
    def save(self):
        pw1 = self.pw1.get()
        pw2 = self.pw2.get()
        
        if not pw1:
            messagebox.showerror("Error", "Password is required")
            return
        
        if pw1 != pw2:
            messagebox.showerror("Error", "Passwords do not match")
            return
        
        self.result = pw1
        self.top.destroy()


def main():
    root = tk.Tk()
    app = AdminManagerApp(root)
    
    # Center window on screen
    root.update_idletasks()
    width = root.winfo_width()
    height = root.winfo_height()
    x = (root.winfo_screenwidth() // 2) - (width // 2)
    y = (root.winfo_screenheight() // 2) - (height // 2)
    root.geometry(f"+{x}+{y}")
    
    root.mainloop()


if __name__ == '__main__':
    main()
