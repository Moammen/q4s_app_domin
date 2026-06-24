
import datetime
from calendar import monthrange
from django.utils import timezone
from django.db.models import Q
from django.db.models.functions import TruncDate
from opc.models import OPCNode, OPCNodeHistory
from django.db.models import Avg
from core.models import ETSSite 
import json
from django.core.serializers.json import DjangoJSONEncoder
from opc.models import OPCObject
from core.serializers import ETSSiteSerializer
import requests
from requests.auth import HTTPBasicAuth
from django.http import JsonResponse
from django.conf import settings

# ─────────────────────────────────────────────────────────────────────────────
# Calculation of daily accumulated energy (delta of energy_mwh_4) for a node or group of nodes, over the last N days
# ─────────────────────────────────────────────────────────────────────────────

def get_energy_mwh4_daily_accumulated(
    node_opc_name=None,
    node_object_opc_name="energy_mwh_4",
    node_name="value",
    ets_site=None,
    days=7,
    ):
    """
    Returns same payload structure used by EnergyMWH4DailyAccumulatedView
    """

    today      = timezone.localdate()
    start_date = today - datetime.timedelta(days=days - 1)
    start_dt   = timezone.make_aware(datetime.datetime.combine(start_date, datetime.time.min))
    end_dt     = timezone.make_aware(datetime.datetime.combine(today + datetime.timedelta(days=1), datetime.time.min))

    # Build node queryset
    nodes = OPCNode.objects.all()

    if node_opc_name and node_object_opc_name:
        nodes = nodes.filter(
            opc_name__iexact=node_opc_name,
            object__opc_name__iexact=node_object_opc_name,
        )
    elif node_opc_name:
        nodes = nodes.filter(opc_name__iexact=node_opc_name)
    elif node_object_opc_name:
        nodes = nodes.filter(object__opc_name__iexact=node_object_opc_name)
    else:
        nodes = nodes.filter(
            Q(name__iexact=node_name) | Q(opc_name__iexact=node_name)
        )

    if ets_site:
        nodes = nodes.filter(object__asset__ets_site_id=ets_site)

    node_ids = list(nodes.values_list("id", flat=True))

    if not node_ids:
        return {
            "nodes_count": 0,
            "results": [],
        }

    # first readings per node per day (earliest actual_timestamp)
    first_readings = {
        (r["node_id"], r["day"]): r["actual_value"]
        for r in (
            OPCNodeHistory.objects
            .filter(
                node_id__in=node_ids,
                actual_timestamp__isnull=False,
                actual_timestamp__gte=start_dt,
                actual_timestamp__lt=end_dt,
                actual_value__isnull=False,
                actual_value__gt=-99998,
            )
            .annotate(day=TruncDate("actual_timestamp"))
            .order_by("node_id", "day", "actual_timestamp")
            .distinct("node_id", "day")
            .values("node_id", "day", "actual_value")
        )
    }

    # last readings per node per day (latest actual_timestamp)
    last_readings = {
        (r["node_id"], r["day"]): r["actual_value"]
        for r in (
            OPCNodeHistory.objects
            .filter(
                node_id__in=node_ids,
                actual_timestamp__isnull=False,
                actual_timestamp__gte=start_dt,
                actual_timestamp__lt=end_dt,
                actual_value__isnull=False,
                actual_value__gt=-99998,
            )
            .annotate(day=TruncDate("actual_timestamp"))
            .order_by("node_id", "day", "-actual_timestamp")
            .distinct("node_id", "day")
            .values("node_id", "day", "actual_value")
        )
    }

    results = []
    for i in range(days):
        day = start_date + datetime.timedelta(days=i)
        daily_energy = 0.0

        for node_id in node_ids:
            first = first_readings.get((node_id, day))
            last  = last_readings.get((node_id, day))
            if first is not None and last is not None:
                daily_energy += max(float(last or 0) - float(first or 0), 0)

        results.append({
            "day": day.isoformat(),
            "daily_energy": round(daily_energy, 4),
        })

    return {
        "nodes_count": len(node_ids),
        "results": results,
    }

# ─────────────────────────────────────────────────────────────────────────────
# Calculation of billing data for a site over a date range, including delta-T fees
# ─────────────────────────────────────────────────────────────────────────────

NODE_VALUE_NAMES       = ["VTS", "vts", "Value", "value"]
SENTINEL_THRESHOLD     = -99998
def calculate_site_billing(site, start_date, end_date):
    """
    Calculate billing data for a single site over the given date range.

    Args:
        site:       ETSSite instance (must have a billing_config relation).
        start_date: date — inclusive period start (e.g. 2026-05-01).
        end_date:   date — inclusive period end   (e.g. 2026-05-31).

    Returns:
        dict matching ETSSiteBilling fields, ready to spread into
        ETSSiteBilling.objects.create(**data). Returns None if the site
        has no billing_config (caller should skip).

    Example:
        data = calculate_site_billing(site, period_from, period_to)
        if data:
            ETSSiteBilling.objects.create(
                ets_site=site,
                from_date=period_from,
                to_date=period_to,
                **data,
            )
    """
    config = getattr(site, "billing_config", None)
    if config is None:
        return None

    # ── Convert dates to timezone-aware datetimes for filtering ──
    start_dt = timezone.make_aware(
        datetime.datetime.combine(start_date, datetime.time.min)
    )
    end_dt = timezone.make_aware(
        datetime.datetime.combine(end_date + datetime.timedelta(days=1), datetime.time.min)
    )

    # ── Base filter for site history in the period ──
    history = OPCNodeHistory.objects.filter(
        node__object__asset__ets_site_id=site.id,
        node__opc_name__in=NODE_VALUE_NAMES,
        actual_value__isnull=False,
        actual_value__gt=SENTINEL_THRESHOLD,
        actual_timestamp__gte=start_dt,
        actual_timestamp__lt=end_dt,
    )

    # ── Average delta-T (from temp_diff_k_7) ──
    avg_delta_t = history.filter(
        node__object__opc_name__iexact="temp_diff_k_7"
    ).aggregate(avg=Avg("actual_value"))["avg"]

    # ── Consumption: last − first of energy_mwh_4 ──
    energy        = history.filter(node__object__opc_name__iexact="energy_mwh_4")
    first_reading = energy.order_by("actual_timestamp").values_list("actual_value", flat=True).first()
    last_reading  = energy.order_by("-actual_timestamp").values_list("actual_value", flat=True).first()

    consumption = (
        max(float(last_reading) - float(first_reading), 0)
        if (first_reading is not None and last_reading is not None)
        else 0
    )

    # ── Average supply / return temperatures ──
    agg_temps = history.filter(
        node__object__opc_name__in=["temp_supply_c_2", "temp_return_c_3"]
    ).values("node__object__opc_name").annotate(avg=Avg("actual_value"))
    temp_map = {row["node__object__opc_name"]: row["avg"] for row in agg_temps}
    avg_supply_temp = temp_map.get("temp_supply_c_2")
    avg_return_temp = temp_map.get("temp_return_c_3")

    # ── Average flow & power ──
    agg_flow_power = history.filter(
        node__object__opc_name__in=["flow_m3h_1", "power_kw_5"]
    ).values("node__object__opc_name").annotate(avg=Avg("actual_value"))
    fp_map = {row["node__object__opc_name"]: row["avg"] for row in agg_flow_power}
    avg_flow  = fp_map.get("flow_m3h_1")
    avg_power = fp_map.get("power_kw_5")

    # ── Period stats ──
    period_days     = (end_date - start_date).days + 1
    readings_count  = history.filter(node__object__opc_name__iexact="energy_mwh_4").count()

    # ── Fees ──
    contracted_delta_t = float(site.contracted_delta_t or 0)
    tolerance_delta_t  = float(config.delta_t_tolerance or 0)
    rate_delta_t = float(config.delta_t_fee_rate or 0)

    delta_t_fees = 0.0
    """
    The Old Method was to calculate the fee based on the difference between

    if avg_delta_t is not None:
        # take absolute value of delta-T difference (in case actual delta-T is below contracted)
        avg_delta_t=float(abs(avg_delta_t))
        drop = contracted_delta_t - avg_delta_t - tolerance_delta_t
        if drop > 0 :
            delta_t_fees = drop * rate_delta_t
    """
    # ---------
    # consumption_fee_rate is used for both consumption and delta-T fees, as per original code.
    # ---------

    consumption_fee_rate_val = float(config.consumption_fee_rate or 0)
    consumption_fee          = consumption * consumption_fee_rate_val
    declared_load_fee        = float(site.declared_load_fee or 0)
    delta_t_fees             = 0.0

    other_fees = float(site.other_fees or 0)

    consumption_fee_formula        = "consumption × consumption_fee_rate"
    consumption_fee_formula_values = (
        f"{round(consumption, 4)} × {round(consumption_fee_rate_val, 4)}"
        f" = {round(consumption_fee, 2)}"
    )
    declared_load_fee_formula        = "declared_load_fee (flat monthly fee)"
    declared_load_fee_formula_values = f"{round(declared_load_fee, 2)}"

    delta_t_drop = None
    delta_t_fees_formula        = None
    delta_t_fees_formula_values = None

    if avg_delta_t is not None:
        avg_delta_t = float(abs(avg_delta_t))
        drop = contracted_delta_t - avg_delta_t - tolerance_delta_t
        delta_t_drop = round(drop, 4)
        if drop > 0:
            delta_t_fees = (drop + tolerance_delta_t) * rate_delta_t * float(consumption_fee)
            delta_t_fees_formula = (
                "(drop + tolerance) × rate × consumption fee"
            )
            delta_t_fees_formula_values = (
                f"({round(drop, 4)} + {round(tolerance_delta_t, 4)}) "
                f"× {round(rate_delta_t, 4)} "
                f"× {round(consumption_fee, 2)} "
                f"= {round(delta_t_fees, 2)}"
            )

    total = declared_load_fee + delta_t_fees + consumption_fee + other_fees

    return {
        # ── Core billing fields (stored in ETSSiteBilling) ──
        "average_delta_t":   avg_delta_t,
        "delta_t_fees":      round(delta_t_fees, 2),
        "consumption":       round(consumption, 4),
        "consumption_fee":   round(consumption_fee, 2),
        "declared_load_fee": round(declared_load_fee, 2),
        "total":             round(total, 2),

        # ── Energy snapshot ──
        "energy_start":      round(float(first_reading), 4) if first_reading is not None else None,
        "energy_end":        round(float(last_reading),  4) if last_reading  is not None else None,

        # ── Temperature averages ──
        "avg_supply_temp":   round(avg_supply_temp, 2) if avg_supply_temp is not None else None,
        "avg_return_temp":   round(avg_return_temp, 2) if avg_return_temp is not None else None,

        # ── Flow & power averages ──
        "avg_flow":          round(avg_flow,  2) if avg_flow  is not None else None,
        "avg_power":         round(avg_power, 2) if avg_power is not None else None,

        # ── Delta-T analysis ──
        "contracted_delta_t":        contracted_delta_t,
        "delta_t_drop":              delta_t_drop,
        "is_low_delta_t":            delta_t_drop is not None and delta_t_drop > 0,
        "delta_t_fees_formula":       delta_t_fees_formula,
        "delta_t_fees_formula_values": delta_t_fees_formula_values,

        # ── Consumption fee formula ──
        "consumption_fee_formula":        consumption_fee_formula,
        "consumption_fee_formula_values": consumption_fee_formula_values,

        # ── Declared load fee formula ──
        "declared_load_fee_formula":        declared_load_fee_formula,
        "declared_load_fee_formula_values": declared_load_fee_formula_values,

        # ── Period metadata ──
        "period_days":       period_days,
        "readings_count":    readings_count,

        # ── Billing date ──
        "billing_date":      end_date,
        "billing_period":    end_date,
    }


# ─────────────────────────────────────────────────────────────────────────────
# Low delta-T daily monitor
# ─────────────────────────────────────────────────────────────────────────────

def _safe_day(year: int, month: int, day: int) -> datetime.date:
    """
    Return date(year, month, day), clamping day to the last day of the month
    if the target month is shorter (e.g. billing_day=31 for February).
    """
    last_day_of_month = monthrange(year, month)[1]
    return datetime.date(year, month, min(day, last_day_of_month))


def get_last_billing_period(today: datetime.date, billing_day=None):
    """

    """
    day = int(billing_day) if billing_day else 1
    # ── Find the most recent past billing_day (the END of the period) ──
    if  day == 1 :

        if today.month == 1:
             end_year, end_month , day = today.year - 1, 12 , 31
        else:
            end_year, end_month , day = today.year, today.month - 1 , 31

    elif today.day >= day:

        end_year, end_month , day = today.year, today.month , day

    elif today.day < day:
        # billing_day hasn't been reached yet this month; use last month's
        if today.month == 1:
            end_year, end_month , day = today.year - 1, 12 , day
        else:
            end_year, end_month , day = today.year, today.month  - 1 , day

    period_to = _safe_day(end_year, end_month, day)
    # ── START = one month before END ──
    day = int(billing_day) if billing_day else 1
    if day == 1:
        end_month+=1
    else:
        end_month = end_month
        

    if end_month == 1:
        start_year, start_month = end_year - 1, 12
    else:
        start_year, start_month = end_year, end_month - 1

    period_from = _safe_day(start_year, start_month, day)

    return period_from, period_to


def find_low_delta_t_sites(reference_date: datetime.date = None):
    """
    Identify sites whose average delta-T over the last billing period is below
    the contracted delta-T minus the tolerance.

    For each non-deleted site that has a billing_config and a positive
    contracted_delta_t, the function:
      1. Computes the period via get_last_billing_period().
      2. Calls calculate_site_billing() to get the (absolute) average delta-T
         and the projected delta-T fees for that period.
      3. Applies the corrected formula:
            drop = contracted_delta_t − avg_delta_t − tolerance_delta_t
            site is flagged when drop > 0.

    Args:
        reference_date: Override "today" (useful for tests). Defaults to
                        timezone.localdate().

    Returns:
        list[dict] — one entry per underperforming site, including the
        period boundaries, average delta-T, drop magnitude, and projected
        delta_t_fees. Empty list when no site is underperforming.
    """
    today = reference_date or timezone.localdate()

    

    results = []

    sites = ETSSite.objects.filter(is_deleted=False).select_related("billing_config")

    for site in sites:
        config = getattr(site, "billing_config", None)

        if config is None:
            continue

        contracted_delta_t = float(site.contracted_delta_t or 0)

        if contracted_delta_t <= 0:
            continue   # no contract → nothing to compare against

        billing_day = getattr(config, "billing_day", None)
        period_from, period_to = get_last_billing_period(today, billing_day)

        # Reuse the existing billing helper so the avg/fee logic stays in one place.
        data = calculate_site_billing(site, period_from, period_to)
        if data is None or data.get("average_delta_t") is None:
            continue   # no history for this period
        avg_delta_t = float(data["average_delta_t"])   # already abs() inside calculate_site_billing
        tolerance   = float(config.delta_t_tolerance or 0)
        drop        = contracted_delta_t - avg_delta_t - tolerance


        if drop > 0 :
            results.append({
                "site_id":            site.id,
                "site_name":          site.name,
                "ets_name":           getattr(site, "ets_name", None),
                "billing_day":        billing_day,
                "period_from":        period_from.isoformat(),
                "period_to":          period_to.isoformat(),
                "contracted_delta_t": contracted_delta_t,
                "tolerance":          tolerance,
                "avg_delta_t":        round(avg_delta_t, 4),
                "drop":               round(drop, 4),
                "delta_t_fees":       data["delta_t_fees"],
            })

    return results

# ─────────────────────────────────────────────────────────────────────────────
# Casshing for low delta-T sites (dashboard optimization)
# ─────────────────────────────────────────────────────────────────────────────
# Process-local cache for the dashboard. Resets when the server restarts.
_LOW_DELTA_T_CACHE = {"sites": None, "computed_at": None}

def get_low_delta_t_sites_cached(max_age_hours: int = 24):
    """
    Wrapper around find_low_delta_t_sites() that caches results for a configurable
    number of hours to avoid expensive recalculations on every dashboard load.
    """
    now = timezone.now()
    cached_at = _LOW_DELTA_T_CACHE["computed_at"]

    if cached_at is not None and (now - cached_at) < datetime.timedelta(hours=max_age_hours):
        return _LOW_DELTA_T_CACHE["sites"]

    sites = find_low_delta_t_sites()
    _LOW_DELTA_T_CACHE["sites"] = sites
    _LOW_DELTA_T_CACHE["computed_at"] = now
    return sites

# ─────────────────────────────────────────────────────────────────────────────
# Snapshot builder for site links (OPCSiteLinkSnapshot)
# ─────────────────────────────────────────────────────────────────────────────

def build_site_link_snapshot(site, selected_node_ids, filter_start, filter_end):
    """
    Build the snapshot payload for an OPCGeneratedSiteLink.

    Mirrors OPCSiteDashboardView's structure (site + objects + nodes with
    live values), but:
      - filtered to only the `selected_node_ids`
      - each node also includes its history within
        [filter_start, filter_end] and the average over that window
      - alarms and billing_data are excluded

    The returned dict is JSON-safe (all datetimes converted to ISO strings)
    so it can be stored directly in a JSONField without psycopg complaining.
    """


    # Only nodes that actually belong to this site (defensive)
    valid_nodes = list(
        OPCNode.objects
        .filter(
            id__in=selected_node_ids,
            object__asset__ets_site_id=site.id,
        )
        .select_related("object", "object__connection", "opcnodelive")
    )

    valid_node_ids = [n.id for n in valid_nodes]

    # Fetch history for the selected nodes within the date range
    history_rows = (
        OPCNodeHistory.objects
        .filter(
            node_id__in=valid_node_ids,
            actual_value__isnull=False,
            actual_timestamp__isnull=False,
            actual_timestamp__gte=filter_start,
            actual_timestamp__lte=filter_end,
        )
        .order_by("node_id", "-actual_timestamp")
        .values("node_id", "actual_value", "actual_timestamp")
    )

    history_by_node = {}
    for row in history_rows:
        history_by_node.setdefault(row["node_id"], []).append({
            "actual_value":     row["actual_value"],
            "actual_timestamp": row["actual_timestamp"],
        })

    def calc_average(series):
        valid = [
            r["actual_value"] for r in series
            if r["actual_value"] is not None and r["actual_value"] > -99998
        ]
        if not valid:
            return None
        return round(sum(valid) / len(valid), 4)

    # Group nodes by parent object
    obj_to_nodes = {}
    for node in valid_nodes:
        obj_to_nodes.setdefault(node.object_id, []).append(node)

    obj_qs = (
        OPCObject.objects
        .filter(id__in=list(obj_to_nodes.keys()))
        .select_related("connection")
        .order_by("opc_name")
    )

    objects_data = []
    for obj in obj_qs:
        nodes_data = []
        for node in obj_to_nodes[obj.id]:
            live = getattr(node, "opcnodelive", None)
            node_history = history_by_node.get(node.id, [])
            nodes_data.append({
                "id":        node.id,
                "name":      node.name,
                "opc_name":  node.opc_name,
                "unit":      node.unit,
                "data_type": node.data_type,
                "live": {
                    "value":            live.value,
                    "actual_value":     live.actual_value,
                    "actual_timestamp": live.actual_timestamp,
                    "status":           live.status,
                    "source_ts":        live.source_ts,
                    "server_ts":        live.server_ts,
                    "updated_at":       live.updated_at,
                } if live else None,
                "history": node_history,
                "average": calc_average(node_history),
            })

        objects_data.append({
            "id":              obj.id,
            "name":            obj.name,
            "opc_name":        obj.opc_name,
            "connection_name": obj.connection.name if obj.connection_id else None,
            "nodes":           nodes_data,
        })

    snapshot = {
        "site":    ETSSiteSerializer(site).data,
        "objects": objects_data,
        "filter": {
            "from": filter_start.isoformat(),
            "to":   filter_end.isoformat(),
        },
    }

    # Roundtrip through DjangoJSONEncoder to convert datetimes/Decimals/UUIDs
    # to JSON-safe primitives (strings) so JSONField + psycopg can store it.
    return json.loads(json.dumps(snapshot, cls=DjangoJSONEncoder))

# ─────────────────────────────────────────────────────────────────────────────
# Api Fcunction to connect the other server
# ─────────────────────────────────────────────────────────────────────────────

def make_json_safe(data):
    return json.loads(json.dumps(data, cls=DjangoJSONEncoder))

def send_post_to_external_api(base_url,url_path, data=None, method="POST", auth=None):
    # Default URL
    if base_url is None:
        base_url = settings.EXTERNAL_SERVER_BACKEND_BASE_URL.rstrip("/")

    url = f"{base_url}/{url_path.lstrip('/')}"

    # Default auth
    if auth is None:
        auth = ("admin", "123456789")
    safe_data = make_json_safe(data) if data is not None else None
    try:
        response = requests.request(
            method=method.upper(),
            url=url,
            json=safe_data,
            auth=HTTPBasicAuth(auth[0], auth[1]),
            timeout=10
        )
        try:
            response_data = response.json()
        except ValueError:
            response_data = response.text

        return {
            "success": response.ok,
            "status_code": response.status_code,
            "response": response_data
        }

    except requests.exceptions.RequestException as e:
        return {
            "success": False,
            "error": str(e)
        }
