"""
SecureLink - Stripe Products Setup Script
Run this once to create all products and prices in Stripe.

Usage:
  python setup_stripe_products.py           # create everything
  python setup_stripe_products.py --list    # list existing products only

Copyright (c) 2026 SecureLink. All rights reserved.
Unauthorized copying, modification, or distribution of this software is strictly prohibited.
"""
import sys
import stripe
from config import Config


def create_products_and_prices():
    """Create all SecureLink products and prices in Stripe."""

    print("Setting up Stripe products for SecureLink...")
    print("-" * 60)

    ids = {}

    # ── Individual Pro Plan ───────────────────────────────────────────────
    print("\n[1/4] Creating Pro Plan...")
    pro_product = stripe.Product.create(
        name="SecureLink Pro",
        description="Pro subscription with email monitoring, priority scanning, and more",
        metadata={"plan": "pro"},
    )
    print(f"      Product: {pro_product.id}")

    pro_monthly = stripe.Price.create(
        product=pro_product.id,
        unit_amount=1499,          # $14.99
        currency="usd",
        recurring={"interval": "month"},
        metadata={"plan": "pro", "period": "monthly"},
    )
    ids["pro_monthly"] = pro_monthly.id
    print(f"      Monthly : {pro_monthly.id}  ($14.99/month)")

    pro_yearly = stripe.Price.create(
        product=pro_product.id,
        unit_amount=14999,         # $149.99
        currency="usd",
        recurring={"interval": "year"},
        metadata={"plan": "pro", "period": "yearly"},
    )
    ids["pro_yearly"] = pro_yearly.id
    print(f"      Yearly  : {pro_yearly.id}  ($149.99/year)")

    # ── Individual Enterprise Plan ────────────────────────────────────────
    print("\n[2/4] Creating Enterprise Plan...")
    ent_product = stripe.Product.create(
        name="SecureLink Enterprise",
        description="Enterprise subscription with unlimited scans, API access, and premium support",
        metadata={"plan": "enterprise"},
    )
    print(f"      Product : {ent_product.id}")

    ent_monthly = stripe.Price.create(
        product=ent_product.id,
        unit_amount=5999,          # $59.99
        currency="usd",
        recurring={"interval": "month"},
        metadata={"plan": "enterprise", "period": "monthly"},
    )
    ids["enterprise_monthly"] = ent_monthly.id
    print(f"      Monthly : {ent_monthly.id}  ($59.99/month)")

    ent_yearly = stripe.Price.create(
        product=ent_product.id,
        unit_amount=59999,         # $599.99
        currency="usd",
        recurring={"interval": "year"},
        metadata={"plan": "enterprise", "period": "yearly"},
    )
    ids["enterprise_yearly"] = ent_yearly.id
    print(f"      Yearly  : {ent_yearly.id}  ($599.99/year)")

    # ── Team / Org — Pro Seats (per seat) ────────────────────────────────
    print("\n[3/4] Creating Team Pro seat pricing...")
    team_pro_product = stripe.Product.create(
        name="SecureLink Team Pro (per seat)",
        description="Pro plan for organizations — billed per seat",
        metadata={"plan": "team_pro"},
    )
    print(f"      Product : {team_pro_product.id}")

    team_pro_monthly = stripe.Price.create(
        product=team_pro_product.id,
        unit_amount=1599,          # $15.99/seat
        currency="usd",
        recurring={"interval": "month"},
        metadata={"plan": "team_pro", "period": "monthly"},
    )
    ids["team_pro_monthly"] = team_pro_monthly.id
    print(f"      Monthly : {team_pro_monthly.id}  ($15.99/seat/month)")

    team_pro_yearly = stripe.Price.create(
        product=team_pro_product.id,
        unit_amount=15999,         # $159.99/seat
        currency="usd",
        recurring={"interval": "year"},
        metadata={"plan": "team_pro", "period": "yearly"},
    )
    ids["team_pro_yearly"] = team_pro_yearly.id
    print(f"      Yearly  : {team_pro_yearly.id}  ($159.99/seat/year)")

    # ── Team / Org — Enterprise Seats (per seat) ──────────────────────────
    print("\n[4/4] Creating Team Enterprise seat pricing...")
    team_ent_product = stripe.Product.create(
        name="SecureLink Team Enterprise (per seat)",
        description="Enterprise plan for organizations — billed per seat",
        metadata={"plan": "team_enterprise"},
    )
    print(f"      Product : {team_ent_product.id}")

    team_ent_monthly = stripe.Price.create(
        product=team_ent_product.id,
        unit_amount=2999,          # $29.99/seat
        currency="usd",
        recurring={"interval": "month"},
        metadata={"plan": "team_enterprise", "period": "monthly"},
    )
    ids["team_enterprise_monthly"] = team_ent_monthly.id
    print(f"      Monthly : {team_ent_monthly.id}  ($29.99/seat/month)")

    team_ent_yearly = stripe.Price.create(
        product=team_ent_product.id,
        unit_amount=29999,         # $299.99/seat
        currency="usd",
        recurring={"interval": "year"},
        metadata={"plan": "team_enterprise", "period": "yearly"},
    )
    ids["team_enterprise_yearly"] = team_ent_yearly.id
    print(f"      Yearly  : {team_ent_yearly.id}  ($299.99/seat/year)")

    # ── Summary ──────────────────────────────────────────────────────────
    print("\n" + "=" * 60)
    print("SETUP COMPLETE — paste this block into payments.py STRIPE_PRICES:")
    print("=" * 60)
    print(f"""
STRIPE_PRICES = {{
    # Individual plans
    'pro_monthly':            '{ids["pro_monthly"]}',
    'pro_yearly':             '{ids["pro_yearly"]}',
    'enterprise_monthly':     '{ids["enterprise_monthly"]}',
    'enterprise_yearly':      '{ids["enterprise_yearly"]}',

    # Team / org seat-based plans (quantity = seat count)
    'team_pro_monthly':       '{ids["team_pro_monthly"]}',
    'team_pro_yearly':        '{ids["team_pro_yearly"]}',
    'team_enterprise_monthly':'{ids["team_enterprise_monthly"]}',
    'team_enterprise_yearly': '{ids["team_enterprise_yearly"]}',
}}
""")

    print("Next steps:")
    print("  1. Replace STRIPE_PRICES in payments.py with the block above.")
    print("  2. Add webhook endpoint in Stripe dashboard:")
    print("       URL:    https://securelinkapp.com/api/webhooks/stripe")
    print("       Events: checkout.session.completed")
    print("               customer.subscription.updated")
    print("               customer.subscription.deleted")
    print("  3. Copy the webhook signing secret to .env as STRIPE_WEBHOOK_SECRET.")
    print()

    return ids


def list_existing():
    """Print all active products in the Stripe account."""
    print("Existing Stripe products:")
    products = stripe.Product.list(active=True, limit=20)
    for p in products.data:
        print(f"  {p.id}  {p.name}")
        prices = stripe.Price.list(product=p.id, active=True)
        for pr in prices.data:
            amt = pr.unit_amount / 100 if pr.unit_amount else 0
            interval = pr.recurring.interval if pr.recurring else "one-time"
            print(f"    └ {pr.id}  ${amt:.2f}/{interval}")
    print()


if __name__ == "__main__":
    if not Config.STRIPE_SECRET_KEY or Config.STRIPE_SECRET_KEY.startswith("sk_live_xxx"):
        print("Error: STRIPE_SECRET_KEY not set in .env")
        sys.exit(1)

    stripe.api_key = Config.STRIPE_SECRET_KEY
    print(f"Using Stripe key: {Config.STRIPE_SECRET_KEY[:20]}...\n")

    if "--list" in sys.argv:
        list_existing()
        sys.exit(0)

    try:
        create_products_and_prices()
    except stripe.error.StripeError as e:
        print(f"\nStripe Error: {e.user_message}")
        sys.exit(1)
