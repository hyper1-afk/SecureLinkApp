"""
SecureLink - Stripe Products Setup Script
Run this once to create your products and prices in Stripe.

Copyright (c) 2026 SecureLink. All rights reserved.
Unauthorized copying, modification, or distribution of this software is strictly prohibited.
"""
import stripe
from config import Config

# Initialize Stripe
stripe.api_key = Config.STRIPE_SECRET_KEY

def create_products_and_prices():
    """Create SecureLink products and prices in Stripe"""
    
    print("🔧 Setting up Stripe products for SecureLink...")
    print("-" * 50)
    
    # Create Pro Plan Product
    print("\n📦 Creating Pro Plan product...")
    pro_product = stripe.Product.create(
        name="SecureLink Pro",
        description="Pro subscription with email monitoring, priority scanning, and more",
        metadata={"plan": "pro"}
    )
    print(f"   ✅ Created product: {pro_product.id}")
    
    # Create Pro Monthly Price
    pro_monthly = stripe.Price.create(
        product=pro_product.id,
        unit_amount=999,  # $9.99 in cents
        currency="usd",
        recurring={"interval": "month"},
        metadata={"plan": "pro", "period": "monthly"}
    )
    print(f"   ✅ Pro Monthly Price: {pro_monthly.id} ($9.99/month)")
    
    # Create Pro Yearly Price
    pro_yearly = stripe.Price.create(
        product=pro_product.id,
        unit_amount=9999,  # $99.99 in cents
        currency="usd",
        recurring={"interval": "year"},
        metadata={"plan": "pro", "period": "yearly"}
    )
    print(f"   ✅ Pro Yearly Price: {pro_yearly.id} ($99.99/year)")
    
    # Create Enterprise Plan Product
    print("\n📦 Creating Enterprise Plan product...")
    enterprise_product = stripe.Product.create(
        name="SecureLink Enterprise",
        description="Enterprise subscription with unlimited scans, API access, and premium support",
        metadata={"plan": "enterprise"}
    )
    print(f"   ✅ Created product: {enterprise_product.id}")
    
    # Create Enterprise Monthly Price
    enterprise_monthly = stripe.Price.create(
        product=enterprise_product.id,
        unit_amount=4999,  # $49.99 in cents
        currency="usd",
        recurring={"interval": "month"},
        metadata={"plan": "enterprise", "period": "monthly"}
    )
    print(f"   ✅ Enterprise Monthly Price: {enterprise_monthly.id} ($49.99/month)")
    
    # Create Enterprise Yearly Price
    enterprise_yearly = stripe.Price.create(
        product=enterprise_product.id,
        unit_amount=49999,  # $499.99 in cents
        currency="usd",
        recurring={"interval": "year"},
        metadata={"plan": "enterprise", "period": "yearly"}
    )
    print(f"   ✅ Enterprise Yearly Price: {enterprise_yearly.id} ($499.99/year)")
    
    # Print summary
    print("\n" + "=" * 50)
    print("✅ SETUP COMPLETE!")
    print("=" * 50)
    print("\nCopy these price IDs to payments.py STRIPE_PRICES:")
    print(f"""
STRIPE_PRICES = {{
    'pro_monthly': '{pro_monthly.id}',
    'pro_yearly': '{pro_yearly.id}',
    'enterprise_monthly': '{enterprise_monthly.id}',
    'enterprise_yearly': '{enterprise_yearly.id}',
}}
""")
    
    return {
        'pro_monthly': pro_monthly.id,
        'pro_yearly': pro_yearly.id,
        'enterprise_monthly': enterprise_monthly.id,
        'enterprise_yearly': enterprise_yearly.id,
    }


if __name__ == "__main__":
    if not Config.STRIPE_SECRET_KEY:
        print("❌ Error: STRIPE_SECRET_KEY not configured in config.py")
        exit(1)
    
    print(f"Using Stripe key: {Config.STRIPE_SECRET_KEY[:20]}...")
    
    try:
        prices = create_products_and_prices()
    except stripe.error.StripeError as e:
        print(f"\n❌ Stripe Error: {e.user_message}")
        exit(1)
