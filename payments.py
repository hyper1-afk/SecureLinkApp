"""
SecureLink - Payment Processing Module
Handles Stripe integration for subscription payments.

Copyright (c) 2026 SecureLink. All rights reserved.
"""
import stripe
import logging
from datetime import datetime, timedelta
from typing import Optional, Dict, Any

logger = logging.getLogger(__name__)

# Stripe Price IDs - Replace with your actual Stripe Price IDs
STRIPE_PRICES = {
    'pro_monthly': 'price_1SwwuEPTu7BHdtL9Q7BIafqg',  # $14.99/month
    'pro_yearly': 'price_1SwwuEPTu7BHdtL9lfo8A4ga',    # $149.99/year
    'enterprise_monthly': 'price_1SwwuFPTu7BHdtL92eGnbVCT',  # $59.99/month
    'enterprise_yearly': 'price_1SwwuFPTu7BHdtL9R1KpiIph',   # $599.99/year
    # Team/seat-based prices (per-seat, quantity = seat count)
    'team_pro_monthly':        'price_team_pro_monthly',        # $12.99/seat/month
    'team_pro_yearly':         'price_team_pro_yearly',         # $129.99/seat/year
    'team_enterprise_monthly': 'price_team_enterprise_monthly', # $49.99/seat/month
    'team_enterprise_yearly':  'price_team_enterprise_yearly',  # $499.99/seat/year
}

# Per-seat prices shown in the UI
TEAM_SEAT_PRICES = {
    'pro': {
        'monthly': 12.99,
        'yearly':  129.99,
        'yearly_monthly_equiv': round(129.99 / 12, 2),
    },
    'enterprise': {
        'monthly': 49.99,
        'yearly':  499.99,
        'yearly_monthly_equiv': round(499.99 / 12, 2),
    },
}

PLAN_PRICES = {
    'pro': {
        'monthly': 14.99,
        'yearly': 149.99,
    },
    'enterprise': {
        'monthly': 59.99,
        'yearly': 599.99,
    }
}


class PaymentManager:
    """Manages Stripe payments and subscriptions"""
    
    def __init__(self, config):
        self.config = config
        self.stripe_secret_key = getattr(config, 'STRIPE_SECRET_KEY', None)
        self.stripe_publishable_key = getattr(config, 'STRIPE_PUBLISHABLE_KEY', None)
        self.stripe_webhook_secret = getattr(config, 'STRIPE_WEBHOOK_SECRET', None)
        
        if self.stripe_secret_key:
            stripe.api_key = self.stripe_secret_key
            logger.info("Stripe initialized successfully")
        else:
            logger.warning("Stripe API key not configured - payments will be in demo mode")
    
    def is_configured(self) -> bool:
        """Check if Stripe is properly configured"""
        return bool(self.stripe_secret_key and self.stripe_publishable_key)
    
    def get_publishable_key(self) -> Optional[str]:
        """Return the publishable key for frontend use"""
        return self.stripe_publishable_key
    
    def create_customer(self, email: str, name: str = None, metadata: Dict = None) -> Optional[str]:
        """Create a Stripe customer and return the customer ID"""
        if not self.is_configured():
            logger.info("Stripe not configured - skipping customer creation")
            return f"demo_customer_{email}"
        
        try:
            customer = stripe.Customer.create(
                email=email,
                name=name,
                metadata=metadata or {}
            )
            logger.info(f"Created Stripe customer: {customer.id}")
            return customer.id
        except stripe.error.StripeError as e:
            logger.error(f"Failed to create Stripe customer: {e}")
            return None
    
    def create_checkout_session(
        self,
        customer_id: str,
        plan: str,
        billing_period: str = 'monthly',
        success_url: str = None,
        cancel_url: str = None,
        user_id: str = None
    ) -> Optional[Dict[str, Any]]:
        """
        Create a Stripe Checkout session for subscription payment.
        Returns session ID and URL.
        """
        if not self.is_configured():
            # Demo mode - return fake session
            logger.info("Stripe not configured - returning demo checkout session")
            return {
                'session_id': 'demo_session_' + plan,
                'url': None,
                'demo_mode': True
            }
        
        price_key = f"{plan}_{billing_period}"
        price_id = STRIPE_PRICES.get(price_key)
        
        if not price_id:
            logger.error(f"Invalid plan/billing combination: {price_key}")
            return None
        
        try:
            session = stripe.checkout.Session.create(
                customer=customer_id,
                payment_method_types=['card'],
                line_items=[{
                    'price': price_id,
                    'quantity': 1,
                }],
                mode='subscription',
                success_url=success_url or 'http://localhost:5000/profile?payment=success',
                cancel_url=cancel_url or 'http://localhost:5000/profile?payment=cancelled',
                metadata={
                    'user_id': user_id,
                    'plan': plan,
                    'billing_period': billing_period
                },
                subscription_data={
                    'metadata': {
                        'user_id': user_id,
                        'plan': plan
                    }
                }
            )
            
            logger.info(f"Created checkout session: {session.id}")
            return {
                'session_id': session.id,
                'url': session.url,
                'demo_mode': False
            }
        except stripe.error.StripeError as e:
            logger.error(f"Failed to create checkout session: {e}")
            return None
    
    def create_portal_session(self, customer_id: str, return_url: str = None) -> Optional[Dict[str, Any]]:
        """
        Create a Stripe Customer Portal session for managing subscriptions.
        """
        if not self.is_configured():
            logger.info("Stripe not configured - portal not available in demo mode")
            return None
        
        try:
            session = stripe.billing_portal.Session.create(
                customer=customer_id,
                return_url=return_url or 'http://localhost:5000/profile'
            )
            
            return {
                'url': session.url
            }
        except stripe.error.StripeError as e:
            logger.error(f"Failed to create portal session: {e}")
            return None
    
    def get_subscription(self, subscription_id: str) -> Optional[Dict[str, Any]]:
        """Get subscription details from Stripe"""
        if not self.is_configured():
            return None
        
        try:
            subscription = stripe.Subscription.retrieve(subscription_id)
            return {
                'id': subscription.id,
                'status': subscription.status,
                'current_period_end': datetime.fromtimestamp(subscription.current_period_end),
                'cancel_at_period_end': subscription.cancel_at_period_end,
                'plan': subscription.metadata.get('plan')
            }
        except stripe.error.StripeError as e:
            logger.error(f"Failed to retrieve subscription: {e}")
            return None
    
    def verify_checkout_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Verify a checkout session and return its details"""
        if not self.is_configured():
            return None
        
        try:
            session = stripe.checkout.Session.retrieve(session_id)
            
            if session.payment_status == 'paid':
                return {
                    'success': True,
                    'customer_id': session.customer,
                    'subscription_id': session.subscription,
                    'user_id': session.metadata.get('user_id'),
                    'plan': session.metadata.get('plan'),
                    'billing_period': session.metadata.get('billing_period')
                }
            else:
                return {
                    'success': False,
                    'status': session.payment_status
                }
        except stripe.error.StripeError as e:
            logger.error(f"Failed to verify checkout session: {e}")
            return None
    
    def cancel_subscription(self, subscription_id: str, at_period_end: bool = True) -> bool:
        """Cancel a subscription (optionally at period end)"""
        if not self.is_configured():
            logger.info("Stripe not configured - demo cancellation")
            return True
        
        try:
            if at_period_end:
                stripe.Subscription.modify(
                    subscription_id,
                    cancel_at_period_end=True
                )
            else:
                stripe.Subscription.delete(subscription_id)
            
            logger.info(f"Cancelled subscription: {subscription_id}")
            return True
        except stripe.error.StripeError as e:
            logger.error(f"Failed to cancel subscription: {e}")
            return False
    
    def handle_webhook(self, payload: bytes, sig_header: str) -> Optional[Dict[str, Any]]:
        """
        Handle Stripe webhook events.
        Returns event data if valid, None otherwise.
        """
        if not self.stripe_webhook_secret:
            logger.warning("Webhook secret not configured")
            return None
        
        try:
            event = stripe.Webhook.construct_event(
                payload, sig_header, self.stripe_webhook_secret
            )
            
            logger.info(f"Received webhook event: {event['type']}")
            return {
                'type': event['type'],
                'data': event['data']['object']
            }
        except ValueError as e:
            logger.error(f"Invalid webhook payload: {e}")
            return None
        except stripe.error.SignatureVerificationError as e:
            logger.error(f"Invalid webhook signature: {e}")
            return None
    
    def get_plan_prices(self) -> Dict[str, Any]:
        """Return plan pricing information"""
        return {
            'pro': {
                'name': 'Pro',
                'monthly': {
                    'price': PLAN_PRICES['pro']['monthly'],
                    'display': '$14.99/month'
                },
                'yearly': {
                    'price': PLAN_PRICES['pro']['yearly'],
                    'display': '$149.99/year',
                    'savings': '2 months free!'
                }
            },
            'enterprise': {
                'name': 'Enterprise',
                'monthly': {
                    'price': PLAN_PRICES['enterprise']['monthly'],
                    'display': '$59.99/month'
                },
                'yearly': {
                    'price': PLAN_PRICES['enterprise']['yearly'],
                    'display': '$599.99/year',
                    'savings': '2 months free!'
                }
            }
        }

    def create_team_checkout_session(
        self,
        customer_id: str,
        tier: str,
        seat_count: int,
        billing_period: str = 'monthly',
        success_url: str = None,
        cancel_url: str = None,
        user_id: str = None,
        org_id: str = None,
    ) -> Optional[Dict[str, Any]]:
        """Create a Stripe Checkout session for a team/seat-based plan.

        Uses per-seat pricing with ``seat_count`` as the line-item quantity.
        Falls back to demo mode when Stripe is not configured.
        """
        if not self.is_configured():
            logger.info("Stripe not configured — returning demo team checkout")
            return {
                'session_id': f'demo_team_{tier}_{seat_count}',
                'url': None,
                'demo_mode': True,
            }

        price_key = f'team_{tier}_{billing_period}'
        price_id = STRIPE_PRICES.get(price_key)
        if not price_id:
            logger.error(f'Invalid team plan key: {price_key}')
            return None

        try:
            session = stripe.checkout.Session.create(
                customer=customer_id,
                payment_method_types=['card'],
                line_items=[{
                    'price': price_id,
                    'quantity': seat_count,
                }],
                mode='subscription',
                success_url=success_url or 'https://securelinkapp.com/organization?payment=success',
                cancel_url=cancel_url or 'https://securelinkapp.com/organization?payment=cancelled',
                metadata={
                    'type': 'team_seats',
                    'user_id': str(user_id),
                    'org_id': str(org_id),
                    'tier': tier,
                    'seat_count': str(seat_count),
                    'billing_period': billing_period,
                },
                subscription_data={
                    'metadata': {
                        'type': 'team_seats',
                        'org_id': str(org_id),
                        'tier': tier,
                        'seat_count': str(seat_count),
                    }
                },
            )
            logger.info(f'Created team checkout session {session.id} ({seat_count}x {tier} seats)')
            return {'session_id': session.id, 'url': session.url, 'demo_mode': False}
        except stripe.error.StripeError as e:
            logger.error(f'Failed to create team checkout session: {e}')
            return None

    def get_team_seat_prices(self) -> Dict[str, Any]:
        """Return per-seat pricing for the UI."""
        return TEAM_SEAT_PRICES


# Singleton instance
_payment_manager = None

def get_payment_manager(config=None):
    """Get or create the payment manager singleton"""
    global _payment_manager
    if _payment_manager is None and config is not None:
        _payment_manager = PaymentManager(config)
    return _payment_manager
