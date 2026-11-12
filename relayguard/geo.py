"""Geographic helpers (pure stdlib)."""
import math


def haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Great-circle distance between two points in kilometres."""
    r = 6371.0
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dlmb = math.radians(lon2 - lon1)
    a = math.sin(dphi / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dlmb / 2) ** 2
    return 2 * r * math.asin(min(1.0, math.sqrt(a)))


def implied_speed_kmh(dist_km: float, dt_seconds: float) -> float:
    """Speed required to cover dist_km in dt_seconds, in km/h."""
    dt_seconds = max(1.0, dt_seconds)
    return dist_km / (dt_seconds / 3600.0)
