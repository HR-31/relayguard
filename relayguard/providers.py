"""Card-network / wallet provider profiles.

Each profile carries the handful of fields the provider-specific detection layers
need (brand, contactless limit, on-device-CVM ceiling, transit support). Values are
illustrative and configurable — not scraped from any scheme spec.
"""
from dataclasses import dataclass


@dataclass(frozen=True)
class Provider:
    key: str
    display: str
    brand: str              # VISA / MASTERCARD / AMEX / EFTPOS
    aid_prefix: str         # expected EMV Application Identifier prefix for the brand
    is_wallet: bool         # tokenised phone wallet vs plastic
    contactless_limit: float  # no-CVM ceiling (local currency)
    cdcvm_ceiling: float    # max amount a single on-device-CVM tap should authorise
    supports_transit: bool  # express-transit style no-auth entitlement
    transit_ceiling: float


PROVIDERS = {
    "visa": Provider("visa", "Visa (card)", "VISA", "A0000000031010",
                     False, 100.0, 100.0, False, 0.0),
    "mastercard": Provider("mastercard", "Mastercard (card)", "MASTERCARD", "A0000000041010",
                           False, 100.0, 100.0, False, 0.0),
    "amex": Provider("amex", "American Express", "AMEX", "A00000002501",
                     False, 100.0, 100.0, False, 0.0),
    "googlepay": Provider("googlepay", "Google Pay", "VISA", "A0000000031010",
                          True, 100.0, 450.0, False, 0.0),
    "applepay": Provider("applepay", "Apple Pay", "MASTERCARD", "A0000000041010",
                         True, 100.0, 450.0, True, 50.0),
    "eftpos": Provider("eftpos", "ATM / EFTPOS", "EFTPOS", "A0000000032020",
                       False, 100.0, 0.0, False, 0.0),
}

ALL_PROVIDER_KEYS = list(PROVIDERS)


def get(key: str) -> Provider:
    return PROVIDERS[key]
