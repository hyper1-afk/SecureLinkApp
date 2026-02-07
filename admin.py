"""
Admin Panel and Support Ticket System
Handles employee management, customer support, and backend operations.

Copyright (c) 2026 Ryan Haley. All Rights Reserved.
Unauthorized copying, modification, or distribution of this software is strictly prohibited.
"""
import os
import hashlib
import secrets
from datetime import datetime, timedelta
from typing import Optional, Dict, List
from enum import Enum
from functools import wraps

from flask import Blueprint, render_template, request, jsonify, redirect, url_for, session
from sqlalchemy import create_engine, Column, Integer, String, Float, Boolean, DateTime, Text, ForeignKey, Enum as SQLEnum
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship

from config import Config
from notifications import send_ticket_notification, send_ticket_closure_notification

Base = declarative_base()


# ============== Enums ==============

class EmployeeRole(Enum):
    """Employee roles with different permission levels"""
    ADMIN = "admin"           # Full access, can manage employees
    MANAGER = "manager"       # Can manage tickets and view reports
    SUPPORT = "support"       # Can handle support tickets only


class TicketStatus(Enum):
    """Support ticket statuses"""
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    WAITING_CUSTOMER = "waiting_customer"
    RESOLVED = "resolved"
    CLOSED = "closed"


class TicketPriority(Enum):
    """Support ticket priorities"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    URGENT = "urgent"


class TicketCategory(Enum):
    """Support ticket categories"""
    GENERAL = "general"
    BILLING = "billing"
    TECHNICAL = "technical"
    ACCOUNT = "account"
    FEATURE_REQUEST = "feature_request"
    BUG_REPORT = "bug_report"
    COMPLAINT = "complaint"


# ============== Models ==============

class Employee(Base):
    """Employee/Admin account model"""
    __tablename__ = 'employees'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    username = Column(String(100), unique=True, nullable=False, index=True)
    password_hash = Column(String(256), nullable=False)
    salt = Column(String(64), nullable=False)
    
    # Profile
    full_name = Column(String(200), nullable=False)
    role = Column(String(20), default=EmployeeRole.SUPPORT.value)
    avatar_url = Column(String(500), nullable=True)
    phone = Column(String(20), nullable=True)
    
    # Status
    is_active = Column(Boolean, default=True)
    last_login = Column(DateTime, nullable=True)
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    sessions = relationship("EmployeeSession", back_populates="employee", cascade="all, delete-orphan")
    assigned_tickets = relationship("SupportTicket", foreign_keys="SupportTicket.assigned_to_id", back_populates="assigned_to")
    responses = relationship("TicketResponse", back_populates="employee")
    
    def to_dict(self) -> Dict:
        return {
            'id': self.id,
            'email': self.email,
            'username': self.username,
            'full_name': self.full_name,
            'role': self.role,
            'avatar_url': self.avatar_url,
            'phone': self.phone,
            'is_active': self.is_active,
            'last_login': self.last_login.isoformat() if self.last_login else None,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }
    
    def has_permission(self, required_role: str) -> bool:
        """Check if employee has required permission level"""
        role_hierarchy = {
            EmployeeRole.SUPPORT.value: 1,
            EmployeeRole.MANAGER.value: 2,
            EmployeeRole.ADMIN.value: 3
        }
        return role_hierarchy.get(self.role, 0) >= role_hierarchy.get(required_role, 0)


class EmployeeSession(Base):
    """Employee session tokens"""
    __tablename__ = 'employee_sessions'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    employee_id = Column(Integer, ForeignKey('employees.id'), nullable=False)
    token_hash = Column(String(256), unique=True, nullable=False, index=True)
    device_info = Column(String(500), nullable=True)
    ip_address = Column(String(45), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=False)
    last_used = Column(DateTime, default=datetime.utcnow)
    is_active = Column(Boolean, default=True)
    
    employee = relationship("Employee", back_populates="sessions")


class SupportTicket(Base):
    """Customer support tickets"""
    __tablename__ = 'support_tickets'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    ticket_number = Column(String(20), unique=True, nullable=False, index=True)  # e.g., TKT-2026-00001
    
    # Customer info
    user_id = Column(Integer, nullable=True)  # Links to User table
    customer_email = Column(String(255), nullable=False)
    customer_name = Column(String(200), nullable=True)
    
    # Ticket details
    subject = Column(String(500), nullable=False)
    description = Column(Text, nullable=False)
    category = Column(String(50), default=TicketCategory.GENERAL.value)
    priority = Column(String(20), default=TicketPriority.MEDIUM.value)
    status = Column(String(30), default=TicketStatus.OPEN.value)
    
    # Assignment
    assigned_to_id = Column(Integer, ForeignKey('employees.id'), nullable=True)
    
    # Metadata
    source = Column(String(50), default='web')  # web, email, api
    tags = Column(Text, nullable=True)  # comma-separated tags
    
    # Resolution
    resolution_notes = Column(Text, nullable=True)
    resolved_at = Column(DateTime, nullable=True)
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    first_response_at = Column(DateTime, nullable=True)
    
    # Relationships
    assigned_to = relationship("Employee", foreign_keys=[assigned_to_id], back_populates="assigned_tickets")
    responses = relationship("TicketResponse", back_populates="ticket", cascade="all, delete-orphan", order_by="TicketResponse.created_at")
    
    def to_dict(self, include_responses: bool = False) -> Dict:
        data = {
            'id': self.id,
            'ticket_number': self.ticket_number,
            'user_id': self.user_id,
            'customer_email': self.customer_email,
            'customer_name': self.customer_name,
            'subject': self.subject,
            'description': self.description,
            'category': self.category,
            'priority': self.priority,
            'status': self.status,
            'assigned_to_id': self.assigned_to_id,
            'assigned_to_name': self.assigned_to.full_name if self.assigned_to else None,
            'source': self.source,
            'tags': self.tags.split(',') if self.tags else [],
            'resolution_notes': self.resolution_notes,
            'resolved_at': self.resolved_at.isoformat() if self.resolved_at else None,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
            'first_response_at': self.first_response_at.isoformat() if self.first_response_at else None,
            'response_count': len(self.responses) if self.responses else 0
        }
        
        if include_responses:
            data['responses'] = [r.to_dict() for r in self.responses]
        
        return data


class TicketResponse(Base):
    """Responses/messages on a support ticket"""
    __tablename__ = 'ticket_responses'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    ticket_id = Column(Integer, ForeignKey('support_tickets.id'), nullable=False)
    
    # Who sent this response
    employee_id = Column(Integer, ForeignKey('employees.id'), nullable=True)  # Staff response
    is_customer_response = Column(Boolean, default=False)  # True if customer reply
    
    # Content
    message = Column(Text, nullable=False)
    is_internal_note = Column(Boolean, default=False)  # Internal notes not visible to customer
    
    # Attachments (JSON list of file URLs/paths)
    attachments = Column(Text, nullable=True)
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    ticket = relationship("SupportTicket", back_populates="responses")
    employee = relationship("Employee", back_populates="responses")
    
    def to_dict(self) -> Dict:
        return {
            'id': self.id,
            'ticket_id': self.ticket_id,
            'employee_id': self.employee_id,
            'employee_name': self.employee.full_name if self.employee else None,
            'is_customer_response': self.is_customer_response,
            'message': self.message,
            'is_internal_note': self.is_internal_note,
            'attachments': self.attachments.split(',') if self.attachments else [],
            'created_at': self.created_at.isoformat() if self.created_at else None
        }


class OnboardingStatus(Enum):
    """Status of employee onboarding requests"""
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"


class PendingEmployee(Base):
    """Pending employee onboarding requests"""
    __tablename__ = 'pending_employees'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    
    # Request info
    email = Column(String(255), unique=True, nullable=False, index=True)
    username = Column(String(100), unique=True, nullable=False, index=True)
    full_name = Column(String(200), nullable=False)
    phone = Column(String(20), nullable=True)
    
    # Desired role (admin will confirm/change)
    requested_role = Column(String(20), default=EmployeeRole.SUPPORT.value)
    
    # Password (stored temporarily until approved)
    password_hash = Column(String(256), nullable=False)
    salt = Column(String(64), nullable=False)
    
    # Verification
    verification_token = Column(String(256), nullable=True, index=True)
    email_verified = Column(Boolean, default=False)
    
    # Reason/notes for request
    reason = Column(Text, nullable=True)  # Why they need access
    department = Column(String(100), nullable=True)
    
    # Status
    status = Column(String(20), default=OnboardingStatus.PENDING.value)
    reviewed_by_id = Column(Integer, nullable=True)  # Admin who reviewed
    review_notes = Column(Text, nullable=True)
    reviewed_at = Column(DateTime, nullable=True)
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def to_dict(self) -> Dict:
        return {
            'id': self.id,
            'email': self.email,
            'username': self.username,
            'full_name': self.full_name,
            'phone': self.phone,
            'requested_role': self.requested_role,
            'email_verified': self.email_verified,
            'reason': self.reason,
            'department': self.department,
            'status': self.status,
            'reviewed_by_id': self.reviewed_by_id,
            'review_notes': self.review_notes,
            'reviewed_at': self.reviewed_at.isoformat() if self.reviewed_at else None,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }


# ============== Admin Manager ==============

class AdminManager:
    """Handles admin panel operations"""
    
    SESSION_DURATION = timedelta(hours=8)  # Admin sessions last 8 hours
    
    def __init__(self, config: Config = None):
        self.config = config or Config()
        
        # Use SEPARATE admin database engine (isolated from user data)
        from admin_db_engine import get_admin_database_engine, safe_create_admin_tables
        self.engine = get_admin_database_engine(self.config)
        
        # Only create tables if they don't exist (safe for production)
        safe_create_admin_tables(Base.metadata, self.engine)
        self.Session = sessionmaker(bind=self.engine)
        self._ensure_default_admin()
    
    def _ensure_default_admin(self):
        """Create a default admin account if none exists"""
        session = self.get_session()
        try:
            admin_count = session.query(Employee).filter(
                Employee.role == EmployeeRole.ADMIN.value
            ).count()
            
            if admin_count == 0:
                # Create default admin
                salt = secrets.token_hex(32)
                password_hash = hashlib.sha256(('admin123' + salt).encode()).hexdigest()
                
                admin = Employee(
                    email='admin@securelinkapp.com',
                    username='admin',
                    password_hash=password_hash,
                    salt=salt,
                    full_name='System Administrator',
                    role=EmployeeRole.ADMIN.value
                )
                session.add(admin)
                session.commit()
                print("Default admin created: admin / admin123 (CHANGE THIS PASSWORD!)")
        except Exception as e:
            session.rollback()
            print(f"Error creating default admin: {e}")
        finally:
            session.close()
    
    def get_session(self):
        return self.Session()
    
    def _hash_password(self, password: str, salt: str) -> str:
        return hashlib.sha256((password + salt).encode()).hexdigest()
    
    def _generate_salt(self) -> str:
        return secrets.token_hex(32)
    
    def _generate_token(self) -> str:
        return secrets.token_urlsafe(64)
    
    def _hash_token(self, token: str) -> str:
        return hashlib.sha256(token.encode()).hexdigest()
    
    def _generate_ticket_number(self, session) -> str:
        """Generate a unique ticket number"""
        year = datetime.utcnow().year
        # Count tickets this year
        count = session.query(SupportTicket).filter(
            SupportTicket.ticket_number.like(f'TKT-{year}-%')
        ).count()
        return f"TKT-{year}-{str(count + 1).zfill(5)}"
    
    # ============== Employee Management ==============
    
    def create_employee(self, email: str, username: str, password: str, 
                       full_name: str, role: str = EmployeeRole.SUPPORT.value,
                       phone: str = None) -> Dict:
        """Create a new employee account"""
        session = self.get_session()
        try:
            # Check if exists
            existing = session.query(Employee).filter(
                (Employee.email == email) | (Employee.username == username)
            ).first()
            
            if existing:
                if existing.email == email:
                    return {'success': False, 'error': 'Email already registered'}
                return {'success': False, 'error': 'Username already taken'}
            
            salt = self._generate_salt()
            password_hash = self._hash_password(password, salt)
            
            employee = Employee(
                email=email,
                username=username,
                password_hash=password_hash,
                salt=salt,
                full_name=full_name,
                role=role,
                phone=phone
            )
            
            session.add(employee)
            session.commit()
            
            return {'success': True, 'employee': employee.to_dict()}
            
        except Exception as e:
            session.rollback()
            return {'success': False, 'error': str(e)}
        finally:
            session.close()
    
    def login_employee(self, email_or_username: str, password: str,
                      device_info: str = None, ip_address: str = None) -> Dict:
        """Authenticate employee"""
        session = self.get_session()
        try:
            employee = session.query(Employee).filter(
                (Employee.email == email_or_username) | (Employee.username == email_or_username)
            ).first()
            
            if not employee:
                return {'success': False, 'error': 'Invalid credentials'}
            
            password_hash = self._hash_password(password, employee.salt)
            if password_hash != employee.password_hash:
                return {'success': False, 'error': 'Invalid credentials'}
            
            if not employee.is_active:
                return {'success': False, 'error': 'Account is deactivated'}
            
            # Update last login
            employee.last_login = datetime.utcnow()
            
            # Create session
            token = self._generate_token()
            token_hash = self._hash_token(token)
            
            emp_session = EmployeeSession(
                employee_id=employee.id,
                token_hash=token_hash,
                device_info=device_info,
                ip_address=ip_address,
                expires_at=datetime.utcnow() + self.SESSION_DURATION
            )
            
            session.add(emp_session)
            session.commit()
            
            return {
                'success': True,
                'employee': employee.to_dict(),
                'token': token,
                'expires_at': emp_session.expires_at.isoformat()
            }
            
        except Exception as e:
            session.rollback()
            return {'success': False, 'error': str(e)}
        finally:
            session.close()
    
    def validate_employee_token(self, token: str) -> Optional[Dict]:
        """Validate an employee session token"""
        session = self.get_session()
        try:
            token_hash = self._hash_token(token)
            
            emp_session = session.query(EmployeeSession).filter(
                EmployeeSession.token_hash == token_hash,
                EmployeeSession.is_active == True,
                EmployeeSession.expires_at > datetime.utcnow()
            ).first()
            
            if not emp_session:
                return None
            
            emp_session.last_used = datetime.utcnow()
            session.commit()
            
            return {'employee': emp_session.employee.to_dict()}
            
        except Exception as e:
            return None
        finally:
            session.close()
    
    def logout_employee(self, token: str) -> bool:
        """Invalidate an employee session"""
        session = self.get_session()
        try:
            token_hash = self._hash_token(token)
            emp_session = session.query(EmployeeSession).filter(
                EmployeeSession.token_hash == token_hash
            ).first()
            
            if emp_session:
                emp_session.is_active = False
                session.commit()
                return True
            return False
        except:
            return False
        finally:
            session.close()
    
    def get_all_employees(self) -> List[Dict]:
        """Get all employees"""
        session = self.get_session()
        try:
            employees = session.query(Employee).order_by(Employee.full_name).all()
            return [e.to_dict() for e in employees]
        finally:
            session.close()
    
    def update_employee(self, employee_id: int, data: Dict) -> Dict:
        """Update an employee"""
        session = self.get_session()
        try:
            employee = session.query(Employee).filter(Employee.id == employee_id).first()
            if not employee:
                return {'success': False, 'error': 'Employee not found'}
            
            # Update allowed fields
            if 'full_name' in data:
                employee.full_name = data['full_name']
            if 'role' in data:
                employee.role = data['role']
            if 'phone' in data:
                employee.phone = data['phone']
            if 'is_active' in data:
                employee.is_active = data['is_active']
            if 'password' in data and data['password']:
                employee.salt = self._generate_salt()
                employee.password_hash = self._hash_password(data['password'], employee.salt)
            
            session.commit()
            return {'success': True, 'employee': employee.to_dict()}
            
        except Exception as e:
            session.rollback()
            return {'success': False, 'error': str(e)}
        finally:
            session.close()
    
    def delete_employee(self, employee_id: int) -> Dict:
        """Delete an employee"""
        session = self.get_session()
        try:
            employee = session.query(Employee).filter(Employee.id == employee_id).first()
            if not employee:
                return {'success': False, 'error': 'Employee not found'}
            
            session.delete(employee)
            session.commit()
            return {'success': True}
            
        except Exception as e:
            session.rollback()
            return {'success': False, 'error': str(e)}
        finally:
            session.close()
    
    # ============== Employee Onboarding ==============
    
    def submit_onboarding_request(self, email: str, username: str, password: str,
                                  full_name: str, phone: str = None,
                                  requested_role: str = EmployeeRole.SUPPORT.value,
                                  reason: str = None, department: str = None) -> Dict:
        """Submit a new employee onboarding request"""
        session = self.get_session()
        try:
            # Check if email/username already exists in employees
            existing_emp = session.query(Employee).filter(
                (Employee.email == email) | (Employee.username == username)
            ).first()
            if existing_emp:
                if existing_emp.email == email:
                    return {'success': False, 'error': 'Email already registered as employee'}
                return {'success': False, 'error': 'Username already taken'}
            
            # Check if already has pending request
            existing_pending = session.query(PendingEmployee).filter(
                (PendingEmployee.email == email) | (PendingEmployee.username == username),
                PendingEmployee.status == OnboardingStatus.PENDING.value
            ).first()
            if existing_pending:
                return {'success': False, 'error': 'A pending request already exists for this email or username'}
            
            salt = self._generate_salt()
            password_hash = self._hash_password(password, salt)
            verification_token = secrets.token_urlsafe(32)
            
            pending = PendingEmployee(
                email=email,
                username=username,
                password_hash=password_hash,
                salt=salt,
                full_name=full_name,
                phone=phone,
                requested_role=requested_role,
                reason=reason,
                department=department,
                verification_token=self._hash_token(verification_token)
            )
            
            session.add(pending)
            session.commit()
            
            return {
                'success': True,
                'request': pending.to_dict(),
                'verification_token': verification_token,
                'message': 'Your request has been submitted and is pending admin approval.'
            }
            
        except Exception as e:
            session.rollback()
            return {'success': False, 'error': str(e)}
        finally:
            session.close()
    
    def verify_onboarding_email(self, token: str) -> Dict:
        """Verify email for onboarding request"""
        session = self.get_session()
        try:
            token_hash = self._hash_token(token)
            pending = session.query(PendingEmployee).filter(
                PendingEmployee.verification_token == token_hash,
                PendingEmployee.status == OnboardingStatus.PENDING.value
            ).first()
            
            if not pending:
                return {'success': False, 'error': 'Invalid or expired verification token'}
            
            pending.email_verified = True
            session.commit()
            
            return {'success': True, 'message': 'Email verified successfully'}
            
        except Exception as e:
            session.rollback()
            return {'success': False, 'error': str(e)}
        finally:
            session.close()
    
    def get_pending_requests(self, status: str = None) -> List[Dict]:
        """Get all pending onboarding requests"""
        session = self.get_session()
        try:
            query = session.query(PendingEmployee)
            if status:
                query = query.filter(PendingEmployee.status == status)
            else:
                query = query.filter(PendingEmployee.status == OnboardingStatus.PENDING.value)
            
            requests = query.order_by(PendingEmployee.created_at.desc()).all()
            return [r.to_dict() for r in requests]
            
        finally:
            session.close()
    
    def get_pending_request(self, request_id: int) -> Optional[Dict]:
        """Get a single pending request"""
        session = self.get_session()
        try:
            pending = session.query(PendingEmployee).filter(
                PendingEmployee.id == request_id
            ).first()
            return pending.to_dict() if pending else None
        finally:
            session.close()
    
    def approve_onboarding_request(self, request_id: int, reviewer_id: int,
                                   approved_role: str = None, notes: str = None) -> Dict:
        """Approve an onboarding request and create employee account"""
        session = self.get_session()
        try:
            pending = session.query(PendingEmployee).filter(
                PendingEmployee.id == request_id,
                PendingEmployee.status == OnboardingStatus.PENDING.value
            ).first()
            
            if not pending:
                return {'success': False, 'error': 'Request not found or already processed'}
            
            # Create employee from pending request
            employee = Employee(
                email=pending.email,
                username=pending.username,
                password_hash=pending.password_hash,
                salt=pending.salt,
                full_name=pending.full_name,
                phone=pending.phone,
                role=approved_role or pending.requested_role
            )
            
            session.add(employee)
            
            # Update pending request
            pending.status = OnboardingStatus.APPROVED.value
            pending.reviewed_by_id = reviewer_id
            pending.review_notes = notes
            pending.reviewed_at = datetime.utcnow()
            
            session.commit()
            
            return {
                'success': True,
                'employee': employee.to_dict(),
                'message': f'Employee {employee.full_name} has been approved and can now log in.'
            }
            
        except Exception as e:
            session.rollback()
            return {'success': False, 'error': str(e)}
        finally:
            session.close()
    
    def reject_onboarding_request(self, request_id: int, reviewer_id: int, 
                                  reason: str = None) -> Dict:
        """Reject an onboarding request"""
        session = self.get_session()
        try:
            pending = session.query(PendingEmployee).filter(
                PendingEmployee.id == request_id,
                PendingEmployee.status == OnboardingStatus.PENDING.value
            ).first()
            
            if not pending:
                return {'success': False, 'error': 'Request not found or already processed'}
            
            pending.status = OnboardingStatus.REJECTED.value
            pending.reviewed_by_id = reviewer_id
            pending.review_notes = reason
            pending.reviewed_at = datetime.utcnow()
            
            session.commit()
            
            return {
                'success': True,
                'message': 'Onboarding request has been rejected.'
            }
            
        except Exception as e:
            session.rollback()
            return {'success': False, 'error': str(e)}
        finally:
            session.close()
    
    def get_onboarding_stats(self) -> Dict:
        """Get onboarding statistics"""
        session = self.get_session()
        try:
            pending = session.query(PendingEmployee).filter(
                PendingEmployee.status == OnboardingStatus.PENDING.value
            ).count()
            approved = session.query(PendingEmployee).filter(
                PendingEmployee.status == OnboardingStatus.APPROVED.value
            ).count()
            rejected = session.query(PendingEmployee).filter(
                PendingEmployee.status == OnboardingStatus.REJECTED.value
            ).count()
            
            return {
                'pending': pending,
                'approved': approved,
                'rejected': rejected,
                'total': pending + approved + rejected
            }
        finally:
            session.close()
    
    # ============== Ticket Management ==============
    
    def create_ticket(self, customer_email: str, subject: str, description: str,
                     category: str = TicketCategory.GENERAL.value,
                     priority: str = TicketPriority.MEDIUM.value,
                     user_id: int = None, customer_name: str = None,
                     source: str = 'web') -> Dict:
        """Create a new support ticket"""
        session = self.get_session()
        try:
            ticket_number = self._generate_ticket_number(session)
            
            ticket = SupportTicket(
                ticket_number=ticket_number,
                user_id=user_id,
                customer_email=customer_email,
                customer_name=customer_name,
                subject=subject,
                description=description,
                category=category,
                priority=priority,
                source=source
            )
            
            session.add(ticket)
            session.commit()
            
            ticket_dict = ticket.to_dict()
            
            # Send email notification to support team
            try:
                send_ticket_notification(ticket_dict, self.config)
            except Exception as notify_error:
                # Don't fail ticket creation if notification fails
                import logging
                logging.getLogger(__name__).warning(f"Failed to send ticket notification: {notify_error}")
            
            return {'success': True, 'ticket': ticket_dict}
            
        except Exception as e:
            session.rollback()
            return {'success': False, 'error': str(e)}
        finally:
            session.close()
    
    def get_tickets(self, status: str = None, priority: str = None,
                   category: str = None, assigned_to_id: int = None,
                   search: str = None, page: int = 1, per_page: int = 20) -> Dict:
        """Get tickets with filtering and pagination"""
        session = self.get_session()
        try:
            query = session.query(SupportTicket)
            
            if status:
                query = query.filter(SupportTicket.status == status)
            if priority:
                query = query.filter(SupportTicket.priority == priority)
            if category:
                query = query.filter(SupportTicket.category == category)
            if assigned_to_id:
                query = query.filter(SupportTicket.assigned_to_id == assigned_to_id)
            if search:
                search_term = f'%{search}%'
                query = query.filter(
                    (SupportTicket.subject.ilike(search_term)) |
                    (SupportTicket.customer_email.ilike(search_term)) |
                    (SupportTicket.ticket_number.ilike(search_term))
                )
            
            # Count total
            total = query.count()
            
            # Paginate
            tickets = query.order_by(SupportTicket.created_at.desc())\
                          .offset((page - 1) * per_page)\
                          .limit(per_page)\
                          .all()
            
            return {
                'tickets': [t.to_dict() for t in tickets],
                'total': total,
                'page': page,
                'per_page': per_page,
                'total_pages': (total + per_page - 1) // per_page
            }
            
        finally:
            session.close()
    
    def get_ticket(self, ticket_id: int = None, ticket_number: str = None) -> Optional[Dict]:
        """Get a single ticket with responses"""
        session = self.get_session()
        try:
            query = session.query(SupportTicket)
            if ticket_id:
                query = query.filter(SupportTicket.id == ticket_id)
            elif ticket_number:
                query = query.filter(SupportTicket.ticket_number == ticket_number)
            else:
                return None
            
            ticket = query.first()
            return ticket.to_dict(include_responses=True) if ticket else None
            
        finally:
            session.close()
    
    def update_ticket(self, ticket_id: int, data: Dict) -> Dict:
        """Update a ticket"""
        session = self.get_session()
        try:
            ticket = session.query(SupportTicket).filter(SupportTicket.id == ticket_id).first()
            if not ticket:
                return {'success': False, 'error': 'Ticket not found'}
            
            old_status = ticket.status
            if 'status' in data:
                ticket.status = data['status']
                if data['status'] == TicketStatus.RESOLVED.value:
                    ticket.resolved_at = datetime.utcnow()
            if 'priority' in data:
                ticket.priority = data['priority']
            if 'category' in data:
                ticket.category = data['category']
            if 'assigned_to_id' in data:
                ticket.assigned_to_id = data['assigned_to_id']
            if 'resolution_notes' in data:
                ticket.resolution_notes = data['resolution_notes']
            if 'tags' in data:
                ticket.tags = ','.join(data['tags']) if isinstance(data['tags'], list) else data['tags']
            
            session.commit()
            
            ticket_dict = ticket.to_dict()
            
            # Send closure notification to customer if ticket was just closed or resolved
            if 'status' in data and data['status'] in [TicketStatus.RESOLVED.value, TicketStatus.CLOSED.value]:
                print(f"[TICKET CLOSURE] Status changed to: {data['status']}, old_status: {old_status}")
                if old_status not in [TicketStatus.RESOLVED.value, TicketStatus.CLOSED.value]:
                    print(f"[TICKET CLOSURE] Sending notification to: {ticket_dict.get('customer_email')}")
                    try:
                        result = send_ticket_closure_notification(ticket_dict, self.config)
                        print(f"[TICKET CLOSURE] Notification result: {result}")
                    except Exception as notify_error:
                        print(f"[TICKET CLOSURE] Notification FAILED: {notify_error}")
                        logging.getLogger(__name__).warning(f"Failed to send closure notification: {notify_error}")
                else:
                    print(f"[TICKET CLOSURE] Skipping - ticket was already {old_status}")
            
            return {'success': True, 'ticket': ticket_dict}
            
        except Exception as e:
            session.rollback()
            return {'success': False, 'error': str(e)}
        finally:
            session.close()
    
    def add_ticket_response(self, ticket_id: int, message: str, 
                           employee_id: int = None, is_customer_response: bool = False,
                           is_internal_note: bool = False) -> Dict:
        """Add a response to a ticket"""
        session = self.get_session()
        try:
            ticket = session.query(SupportTicket).filter(SupportTicket.id == ticket_id).first()
            if not ticket:
                return {'success': False, 'error': 'Ticket not found'}
            
            response = TicketResponse(
                ticket_id=ticket_id,
                employee_id=employee_id,
                is_customer_response=is_customer_response,
                message=message,
                is_internal_note=is_internal_note
            )
            
            session.add(response)
            
            # Update ticket
            if not is_customer_response and not ticket.first_response_at:
                ticket.first_response_at = datetime.utcnow()
            
            # Update status if employee is responding
            if not is_customer_response and ticket.status == TicketStatus.OPEN.value:
                ticket.status = TicketStatus.IN_PROGRESS.value
            elif is_customer_response and ticket.status == TicketStatus.WAITING_CUSTOMER.value:
                ticket.status = TicketStatus.IN_PROGRESS.value
            
            session.commit()
            return {'success': True, 'response': response.to_dict()}
            
        except Exception as e:
            session.rollback()
            return {'success': False, 'error': str(e)}
        finally:
            session.close()
    
    def get_ticket_stats(self) -> Dict:
        """Get dashboard statistics"""
        session = self.get_session()
        try:
            total = session.query(SupportTicket).count()
            open_tickets = session.query(SupportTicket).filter(
                SupportTicket.status == TicketStatus.OPEN.value
            ).count()
            in_progress = session.query(SupportTicket).filter(
                SupportTicket.status == TicketStatus.IN_PROGRESS.value
            ).count()
            waiting = session.query(SupportTicket).filter(
                SupportTicket.status == TicketStatus.WAITING_CUSTOMER.value
            ).count()
            resolved_today = session.query(SupportTicket).filter(
                SupportTicket.resolved_at >= datetime.utcnow().replace(hour=0, minute=0, second=0)
            ).count()
            
            # By priority
            urgent = session.query(SupportTicket).filter(
                SupportTicket.priority == TicketPriority.URGENT.value,
                SupportTicket.status.notin_([TicketStatus.RESOLVED.value, TicketStatus.CLOSED.value])
            ).count()
            high = session.query(SupportTicket).filter(
                SupportTicket.priority == TicketPriority.HIGH.value,
                SupportTicket.status.notin_([TicketStatus.RESOLVED.value, TicketStatus.CLOSED.value])
            ).count()
            
            return {
                'total': total,
                'open': open_tickets,
                'in_progress': in_progress,
                'waiting_customer': waiting,
                'resolved_today': resolved_today,
                'urgent': urgent,
                'high_priority': high
            }
            
        finally:
            session.close()
    
    # ============== Customer Management ==============
    
    def get_customers(self, search: str = None, page: int = 1, per_page: int = 20) -> Dict:
        """Get all customers (users) with pagination"""
        # This requires importing from auth.py
        from auth import User, AuthManager
        
        auth_session = self.get_session()
        try:
            query = auth_session.query(User)
            
            if search:
                search_term = f'%{search}%'
                query = query.filter(
                    (User.email.ilike(search_term)) |
                    (User.username.ilike(search_term)) |
                    (User.full_name.ilike(search_term))
                )
            
            total = query.count()
            users = query.order_by(User.created_at.desc())\
                        .offset((page - 1) * per_page)\
                        .limit(per_page)\
                        .all()
            
            return {
                'customers': [u.to_dict() for u in users],
                'total': total,
                'page': page,
                'per_page': per_page,
                'total_pages': (total + per_page - 1) // per_page
            }
            
        finally:
            auth_session.close()
    
    def get_customer_tickets(self, user_id: int = None, email: str = None) -> List[Dict]:
        """Get all tickets for a specific customer"""
        session = self.get_session()
        try:
            query = session.query(SupportTicket)
            if user_id:
                query = query.filter(SupportTicket.user_id == user_id)
            elif email:
                query = query.filter(SupportTicket.customer_email == email)
            else:
                return []
            
            tickets = query.order_by(SupportTicket.created_at.desc()).all()
            return [t.to_dict() for t in tickets]
            
        finally:
            session.close()


# Singleton instance
_admin_manager: Optional[AdminManager] = None


def get_admin_manager(config: Config = None) -> AdminManager:
    """Get or create the admin manager singleton"""
    global _admin_manager
    if _admin_manager is None:
        _admin_manager = AdminManager(config)
    return _admin_manager
