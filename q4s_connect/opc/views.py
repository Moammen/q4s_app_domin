import secrets

import django_filters
from django.contrib.auth.hashers import make_password
from django.utils import timezone
import datetime
from django.db import transaction
from rest_framework import status
from rest_framework.viewsets import ModelViewSet
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework.exceptions import NotFound
from collections import defaultdict

from opc.helpers import calculate_site_billing, build_site_link_snapshot , send_post_to_external_api
from .models import (
    OPCConnection, OPCAsset, OPCObject, OPCNode, OPCNodeLive, OPCNodeHistory,
    OPCAlarmRule, OPCAlarmLive, OPCAlarmEvent,
    OPCGeneratedSiteLink, OPCSiteBaseAlarmRule
)
from .serializers import (
    OPCConnectionSerializer, OPCAssetSerializer, OPCObjectSerializer, OPCNodeSerializer,
    OPCNodeLiveSerializer, OPCNodeHistorySerializer, SiteLiveTagSerializer,
    OPCAlarmRuleSerializer, OPCAlarmLiveSerializer, OPCAlarmEventSerializer,
    OPCGeneratedSiteLinkSerializer, OPCSiteBaseAlarmRuleSerializer
)
from core.models import ETSSite, ETSSiteBilling

from .opcua_client import OPCError, create_opcua_client
from .opc_polling_tasks import poll_due_opc_connections, poll_opc_connection
from django.db.models import Count, F, Q
from django.db.models.functions import TruncDate
from django.db.models import Prefetch
from core.serializers import ETSSiteSerializer
from accounts.permissions import IsSuperAdmin
import re
import logging
import json as _json
from urllib.parse import urlparse
from urllib.request import Request as URLRequest, urlopen
from urllib.error import URLError, HTTPError
from django.conf import settings
logger = logging.getLogger(__name__)

#-----------------------------------------------------------------------------
# ── Filters and ViewSets for OPC models ─────────────────────────────
#-----------------------------------------------------------------------------


class OPCNodeHistoryFilter(django_filters.FilterSet):
    from_date = django_filters.DateTimeFilter(field_name="source_ts", lookup_expr="gte")
    to_date   = django_filters.DateTimeFilter(field_name="source_ts", lookup_expr="lte")

    class Meta:
        model  = OPCNodeHistory
        fields = ["node", "from_date", "to_date"]

class OPCConnectionFilter(django_filters.FilterSet):
    name       = django_filters.CharFilter(field_name="name", lookup_expr="icontains")
    enabled    = django_filters.BooleanFilter(field_name="enabled")
    is_deleted = django_filters.BooleanFilter(field_name="is_deleted")

    class Meta:
        model  = OPCConnection
        fields = []

    def filter_queryset(self, queryset):
        queryset = super().filter_queryset(queryset)
        # Default: hide soft-deleted connections unless ?is_deleted=... is passed
        if "is_deleted" not in self.data:
            queryset = queryset.filter(is_deleted=False)
        return queryset


class OPCAlarmRuleFilter(django_filters.FilterSet):
    is_deleted = django_filters.BooleanFilter(field_name="is_deleted")
    site_id    = django_filters.NumberFilter(field_name="node__object__asset__ets_site_id")

    class Meta:
        model  = OPCAlarmRule
        fields = ["node", "alarm_type", "severity", "enabled", "site_id"]

    def filter_queryset(self, queryset):
        queryset = super().filter_queryset(queryset)
        # Default: hide soft-deleted rules unless ?is_deleted=... is passed
        if "is_deleted" not in self.data:
            queryset = queryset.filter(is_deleted=False)
        return queryset


class OPCSiteBaseAlarmRuleFilter(django_filters.FilterSet):
    is_deleted = django_filters.BooleanFilter(field_name="is_deleted")

    class Meta:
        model  = OPCSiteBaseAlarmRule
        fields = ["node", "alarm_type", "severity", "enabled"]

    def filter_queryset(self, queryset):
        queryset = super().filter_queryset(queryset)
        # Default: hide soft-deleted rules unless ?is_deleted=... is passed
        if "is_deleted" not in self.data:
            queryset = queryset.filter(is_deleted=False)
        return queryset

class OPCAlarmLiveFilter(django_filters.FilterSet):
    # Date range filters
    from_date    = django_filters.DateTimeFilter(field_name="activated_at", lookup_expr="gte")
    to_date      = django_filters.DateTimeFilter(field_name="activated_at", lookup_expr="lte")

    is_active    = django_filters.BooleanFilter(field_name="is_active")
    acknowledged = django_filters.BooleanFilter(field_name="acknowledged")
    message      = django_filters.CharFilter(field_name="message",          lookup_expr="icontains")
    name         = django_filters.CharFilter(field_name="rule__name",       lookup_expr="icontains")
    alarm_type = django_filters.CharFilter(field_name="rule__alarm_type")
    severity   = django_filters.CharFilter(field_name="rule__severity")
    node       = django_filters.NumberFilter(field_name="rule__node__id")
    node_name  = django_filters.CharFilter(field_name="rule__node__name", lookup_expr="icontains")
    object     = django_filters.NumberFilter(field_name="rule__node__object__id")
    site       = django_filters.NumberFilter(field_name="rule__node__object__asset__ets_site__id")

    class Meta:
        model  = OPCAlarmLive
        fields = []

    def filter_queryset(self, queryset):
        # Always hide live alarms whose rule is soft-deleted (no opt-out needed —
        # rule.is_deleted is a separate flag from any live-alarm filter)
        return super().filter_queryset(queryset).filter(rule__is_deleted=False)

class OPCAlarmEventFilter(django_filters.FilterSet):
    # Date range filters
    from_date    = django_filters.DateTimeFilter(field_name="started_at", lookup_expr="gte")
    to_date      = django_filters.DateTimeFilter(field_name="started_at", lookup_expr="lte")

    # Direct fields
    acknowledged = django_filters.BooleanFilter(field_name="acknowledged")
    message      = django_filters.CharFilter(field_name="message",          lookup_expr="icontains")

    # Via rule
    rule         = django_filters.NumberFilter(field_name="rule__id")
    name         = django_filters.CharFilter(field_name="rule__name",       lookup_expr="icontains")
    alarm_type   = django_filters.CharFilter(field_name="rule__alarm_type")
    severity     = django_filters.CharFilter(field_name="rule__severity")

    # Via rule → node
    node         = django_filters.NumberFilter(field_name="rule__node__id")
    node_name    = django_filters.CharFilter(field_name="rule__node__name", lookup_expr="icontains")

    # Via rule → node → object
    object       = django_filters.NumberFilter(field_name="rule__node__object__id")

    # Via rule → node → object → asset → ets_site
    site         = django_filters.NumberFilter(field_name="rule__node__object__asset__ets_site__id")

    class Meta:
        model  = OPCAlarmEvent
        fields = []



class OPCGeneratedSiteLinkFilter(django_filters.FilterSet):
    site       = django_filters.NumberFilter(field_name="site_id")
    is_active  = django_filters.BooleanFilter(field_name="is_active")
    is_deleted = django_filters.BooleanFilter(field_name="is_deleted")
    from_date  = django_filters.DateTimeFilter(field_name="created_at", lookup_expr="gte")
    to_date    = django_filters.DateTimeFilter(field_name="created_at", lookup_expr="lte")

    class Meta:
        model  = OPCGeneratedSiteLink
        fields = []

    def filter_queryset(self, queryset):
        queryset = super().filter_queryset(queryset)
        # Default: hide soft-deleted links unless ?is_deleted=... is passed
        if "is_deleted" not in self.data:
            queryset = queryset.filter(is_deleted=False)
        return queryset


#-----------------------------------------------------------------------------
# ──  API Views for OPC models ────────────────────────────────────────
#-----------------------------------------------------------------------------


class OPCConnectionViewSet(ModelViewSet):
    queryset         = OPCConnection.objects.all()
    serializer_class = OPCConnectionSerializer
    filterset_class  = OPCConnectionFilter

    # Override to only allow read operations
    def create(self, request, *args, **kwargs):
        return Response(
            {
                "detail": "Method 'POST' not allowed. Use /api/opc-connection-create-test/ to create connections.",
                "allowed_methods": ["GET", "HEAD", "OPTIONS", "PUT", "PATCH", "DELETE"]
            },
            status=status.HTTP_405_METHOD_NOT_ALLOWED
        )


def _extract_name(raw_name: str) -> str:
    """Extract clean name from OPC browse/display strings.
    E.g. 'QualifiedName(2:Device_1_ETS_TEST)' -> 'Device_1_ETS_TEST'
         'LocalizedText(Encoding:2, Locale:None, Text:flow_m3h_1)' -> 'flow_m3h_1'
    """
    if not raw_name:
        return raw_name or ""
    # Try QualifiedName pattern
    m = re.search(r'QualifiedName\(\d+:(.+?)\)', raw_name)
    if m:
        return m.group(1)
    # Try LocalizedText pattern
    m = re.search(r'Text:(.+?)\)', raw_name)
    if m:
        return m.group(1)
    return raw_name


def _auto_discover_connection(connection, ets_site_id=None):
    """
    Browse the OPC tree for a connection starting at FlxinDataPoints (ns=2;i=1)
    and auto-create OPCAsset, OPCObject, and OPCNode records.

    Tree structure:
      FlxinDataPoints (root, ns=2;i=1)
        └── Asset (level 1 children)  → OPCAsset
              └── Object (level 2)    → OPCObject
                    └── Node (level 3) → OPCNode

    Returns dict with counts: {assets, objects, nodes}
    """
    auth_type = connection.auth_type or 'anonymous'
    if 'username' in auth_type.lower():
        auth_type = 'username'

    client = create_opcua_client(
        endpoint_url=connection.endpoint_url,
        timeout_seconds=connection.timeout_seconds,
        security_policy=connection.security_policy,
        security_mode=connection.security_mode,
        auth_type=auth_type,
        username=connection.username,
        password=connection.password,
        client_cert_path=connection.client_cert_path,
        client_key_path=connection.client_key_path,
        server_cert_path=connection.server_cert_path,
    )
    client.connect()

    counts = {"assets": 0, "objects": 0, "nodes": 0}

    try:
        root_node = client.get_node("ns=2;i=1")  # FlxinDataPoints
        asset_nodes = root_node.get_children()

        for asset_node in asset_nodes:
            asset_address = asset_node.nodeid.to_string()
            asset_browse = str(asset_node.get_browse_name())
            asset_name = _extract_name(asset_browse)

            asset_obj, created = OPCAsset.objects.get_or_create(
                connection=connection,
                opc_name=asset_name,
                defaults={
                    "name": asset_name,
                    "opc_address": asset_address,
                    "ets_site_id": ets_site_id,
                },
            )
            
            updated_fields = []
            if not created and not asset_obj.opc_address:
                asset_obj.opc_address = asset_address
                updated_fields.append("opc_address")
                
            if ets_site_id and asset_obj.ets_site_id != ets_site_id:
                asset_obj.ets_site_id = ets_site_id
                updated_fields.append("ets_site_id")
                
            if updated_fields:
                asset_obj.save(update_fields=updated_fields)
            
            counts["assets"] += 1

            # Level 2: Objects
            try:
                object_nodes = asset_node.get_children()
            except Exception:
                object_nodes = []

            for obj_node in object_nodes:
                obj_address = obj_node.nodeid.to_string()
                obj_browse = str(obj_node.get_browse_name())
                obj_name = _extract_name(obj_browse)

                obj_obj, created = OPCObject.objects.get_or_create(
                    connection=connection,
                    opc_name=obj_name,
                    defaults={
                        "name": obj_name,
                        "asset": asset_obj,
                        "opc_address": obj_address,
                        "parent_path": asset_name,
                    },
                )
                if not created:
                    updated_fields = []
                    if obj_obj.asset_id != asset_obj.id:
                        obj_obj.asset = asset_obj
                        updated_fields.append("asset")
                    if not obj_obj.opc_address:
                        obj_obj.opc_address = obj_address
                        updated_fields.append("opc_address")
                    if updated_fields:
                        obj_obj.save(update_fields=updated_fields)
                counts["objects"] += 1

                # Level 3: Nodes
                try:
                    node_children = obj_node.get_children()
                except Exception:
                    node_children = []

                for child_node in node_children:
                    child_browse = str(child_node.get_browse_name())
                    child_name = _extract_name(child_browse)

                    # Only discover VTS nodes
                    if child_name.lower() != "vts":
                        continue

                    child_address = child_node.nodeid.to_string()
                    data_type = "json"

                    _, node_created = OPCNode.objects.get_or_create(
                        object=obj_obj,
                        opc_name=child_name,
                        defaults={
                            "name": child_name,
                            "opc_address": child_address,
                            "data_type": data_type,
                        },
                    )
                    if not node_created:
                        update_kwargs = {}
                        if not OPCNode.objects.get(object=obj_obj, opc_name=child_name).opc_address:
                            update_kwargs["opc_address"] = child_address
                        if not OPCNode.objects.get(object=obj_obj, opc_name=child_name).data_type:
                            update_kwargs["data_type"] = data_type
                        if update_kwargs:
                            OPCNode.objects.filter(object=obj_obj, opc_name=child_name).update(**update_kwargs)
                    counts["nodes"] += 1

    finally:
        client.disconnect()

    return counts


class OPCConnectionCreateTestView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = OPCConnectionSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(
                {
                    "ok": False,
                    "error": {
                        "code": "VALIDATION_ERROR",
                        "message": "Invalid payload",
                        "details": serializer.errors,
                    },
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Test connection before saving to database
        validated_data = serializer.validated_data
        
        # Normalize auth_type variants (e.g. 'username_password' → 'username')
        auth_type = validated_data.get('auth_type', 'anonymous')
        if 'username' in auth_type.lower():
            auth_type = 'username'
            
        try:
            client = create_opcua_client(
            endpoint_url=validated_data['endpoint_url'],
            timeout_seconds=validated_data.get('timeout_seconds', 10),
            security_policy=validated_data.get('security_policy'),
            security_mode=validated_data.get('security_mode'),
            auth_type=auth_type,                          # ← normalized
            username=validated_data.get('username'),
            password=validated_data.get('password'),
            client_cert_path=validated_data.get('client_cert_path'),
            client_key_path=validated_data.get('client_key_path'),
            server_cert_path=validated_data.get('server_cert_path'),
        )
            client.connect()
            client.disconnect()

            # Only save connection if test passes
            connection = serializer.save()
            connection.last_error_code = None
            connection.last_error_message = None
            connection.save(update_fields=["last_error_code", "last_error_message"])

            # Auto-discover assets, objects, and nodes
            discover_result = None
            discover_error = None
            ets_site_id = request.data.get('ets_site_id') or request.data.get('ets_site')
            try:
                discover_result = _auto_discover_connection(connection, ets_site_id=ets_site_id)
            except Exception as e:  # noqa: BLE001
                discover_error = str(e)
                logger.warning("Auto-discovery failed for connection %s: %s", connection.id, e)

            # Trigger an immediate synchronous poll so live and history data are populated
            if discover_result:
                try:
                    from .opc_polling_tasks import poll_opc_connection
                    poll_opc_connection(connection.id)
                except Exception as e:
                    logger.warning("Failed to run initial polling task for connection %s: %s", connection.id, e)

            response_data = {"ok": True, "connection": OPCConnectionSerializer(connection).data}
            if discover_result:
                response_data["discovery"] = discover_result
            if discover_error:
                response_data["discovery_error"] = discover_error

            return Response(response_data)

        except OPCError as e:
            return Response(
                {
                    "ok": False,
                    "error": e.to_dict(),
                    "message": "Connection test failed. Connection not created."
                },
                status=status.HTTP_400_BAD_REQUEST,
            )
        except Exception as e:  # noqa: BLE001
            return Response(
                {
                    "ok": False,
                    "error": {"code": "OPC_CONNECT_FAILED", "message": str(e), "details": {}},
                    "message": "Connection test failed. Connection not created."
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

class OPCConnectionTestOnlyView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        """
        Test OPC connection without creating it in the database
        """
        # Extract connection parameters from request
        endpoint_url = request.data.get('endpoint_url')
        if not endpoint_url:
            return Response(
                {
                    "ok": False,
                    "error": {
                        "code": "VALIDATION_ERROR",
                        "message": "endpoint_url is required",
                        "details": {"endpoint_url": ["This field is required."]}
                    },
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Optional parameters with defaults
        timeout_seconds = request.data.get('timeout_seconds', 10)
        security_policy = request.data.get('security_policy')
        security_mode = request.data.get('security_mode')
        auth_type = request.data.get('auth_type')
        username = request.data.get('username')
        password = request.data.get('password')
        client_cert_path = request.data.get('client_cert_path')
        client_key_path = request.data.get('client_key_path')
        server_cert_path = request.data.get('server_cert_path')

        if auth_type == "username_password":
            auth_type = "username"
        
        print(auth_type," & ", username," & ", password)
        
        if not auth_type:
            auth_type = 'username' if (username and password) else 'anonymous'
    
        try:
            # Create client and test connection
            client = create_opcua_client(
                endpoint_url=endpoint_url,
                timeout_seconds=timeout_seconds,
                security_policy=security_policy,
                security_mode=security_mode,
                auth_type=auth_type,
                username=username,
                password=password,
                client_cert_path=client_cert_path,
                client_key_path=client_key_path,
                server_cert_path=server_cert_path,
            )
            
            # Test connection
            client.connect()
            client.disconnect()

            return Response({
                "ok": True,
                "message": "Connection test successful",
                "connection_details": {
                    "endpoint_url": endpoint_url,
                    "timeout_seconds": timeout_seconds,
                    "auth_type": auth_type,
                    "security_policy": security_policy,
                    "security_mode": security_mode,
                    "username": username if username else None,
                    "has_password": bool(password)
                }
            })

        except OPCError as e:
            return Response(
                {
                    "ok": False,
                    "error": e.to_dict(),
                    "message": "Connection test failed",
                    "connection_details": {
                        "endpoint_url": endpoint_url,
                        "timeout_seconds": timeout_seconds,
                        "auth_type": auth_type
                    }
                },
                status=status.HTTP_400_BAD_REQUEST,
            )
        except Exception as e:  # noqa: BLE001
            return Response(
                {
                    "ok": False,
                    "error": {"code": "OPC_CONNECT_FAILED", "message": str(e), "details": {}},
                    "message": "Connection test failed",
                    "connection_details": {
                        "endpoint_url": endpoint_url,
                        "timeout_seconds": timeout_seconds,
                        "auth_type": auth_type
                    }
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

class OPCAssetViewSet(ModelViewSet):
    queryset         = OPCAsset.objects.all()
    serializer_class = OPCAssetSerializer
    filterset_fields = ["connection", "ets_site"]

    def get_queryset(self):
        # Cascade-hide assets that belong to a soft-deleted connection
        return super().get_queryset().filter(connection__is_deleted=False)

    @transaction.atomic
    def perform_update(self, serializer):
        old_site_id = serializer.instance.ets_site_id
        instance    = serializer.save()
        new_site_id = instance.ets_site_id

        if old_site_id == new_site_id:
            return

        OPCAlarmRule.objects.filter(
            node__object__asset=instance,
        ).delete()

        if new_site_id is None:
            return

        self._apply_base_rules(instance)

    def _apply_base_rules(self, asset):
        nodes = OPCNode.objects.filter(
            object__asset=asset,
        ).select_related('object')

        nodes_by_object_name = defaultdict(list)
        for n in nodes:
            nodes_by_object_name[n.object.opc_name].append(n)

        base_rules = OPCSiteBaseAlarmRule.objects.filter(
            is_deleted=False,
            enabled=True,
        )

        new_rules = []
        for base in base_rules:
            for node in nodes_by_object_name.get(base.node, []):
                new_rules.append(OPCAlarmRule(
                    node=node,
                    name=base.name,
                    alarm_type=base.alarm_type,
                    limit_value=base.limit_value,
                    deadband=base.deadband,
                    severity=base.severity,
                    enabled=base.enabled,
                ))

        if new_rules:
            OPCAlarmRule.objects.bulk_create(new_rules)

class OPCConnectionAutoDiscoverView(APIView):
    """
    POST /api/opc-connection-auto-discover/<connection_id>/
    Re-run auto-discovery for an existing connection.
    Browses the OPC tree and creates/updates assets, objects, and nodes.
    """
    permission_classes = [IsAuthenticated]

    def post(self, request, connection_id: int):
        try:
            connection = OPCConnection.objects.get(pk=connection_id, is_deleted=False)
        except OPCConnection.DoesNotExist:
            raise NotFound(detail=f"OPCConnection with id={connection_id} not found.")

        try:
            counts = _auto_discover_connection(connection)
            return Response({
                "ok": True,
                "connection_id": connection.id,
                "discovery": counts,
            })
        except OPCError as e:
            return Response({"ok": False, "error": e.to_dict()}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:  # noqa: BLE001
            return Response(
                {"ok": False, "error": {"code": "OPC_DISCOVER_FAILED", "message": str(e), "details": {}}},
                status=status.HTTP_400_BAD_REQUEST,
            )

class OPCObjectViewSet(ModelViewSet):
    queryset         = OPCObject.objects.all()
    serializer_class = OPCObjectSerializer
    filterset_fields = ["connection", "asset"]

    def get_queryset(self):
        # Cascade-hide objects that belong to a soft-deleted connection
        return super().get_queryset().filter(connection__is_deleted=False)


class OPCNodeViewSet(ModelViewSet):
    queryset         = OPCNode.objects.all()
    serializer_class = OPCNodeSerializer
    filterset_fields = ["object"]

    def get_queryset(self):
        # Cascade-hide nodes whose parent object's connection is soft-deleted
        return super().get_queryset().filter(object__connection__is_deleted=False)


class OPCConnectionBrowseView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, connection_id: int):
        try:
            connection = OPCConnection.objects.get(pk=connection_id, is_deleted=False)
        except OPCConnection.DoesNotExist:
            raise NotFound(detail=f"OPCConnection with id={connection_id} not found.")

        max_depth = request.query_params.get("depth")
        try:
            max_depth_int = int(max_depth) if max_depth is not None else 5
        except ValueError:
            return Response(
                {
                    "ok": False,
                    "error": {"code": "VALIDATION_ERROR", "message": "depth must be an integer", "details": {}},
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        starting_node = request.query_params.get("starting_node", "ns=2;i=1")  # Default to FlxinDataPoints

        def serialize_node(node, depth: int):
            try:
                node_id = node.nodeid.to_string()
            except Exception:  # noqa: BLE001
                node_id = str(getattr(node, "nodeid", ""))

            try:
                browse_name = str(node.get_browse_name())
            except Exception:  # noqa: BLE001
                browse_name = None

            try:
                display_name = str(node.get_display_name())
            except Exception:  # noqa: BLE001
                display_name = None

            value = None
            value_error = None
            try:
                dv = node.get_data_value()
                if dv and dv.Value:
                    raw_value = dv.Value.Value
                    # Handle complex OPC data types that aren't JSON serializable
                    if hasattr(raw_value, '__dict__'):
                        # Convert complex objects to string representation
                        value = str(raw_value)
                    elif isinstance(raw_value, (list, tuple)):
                        # Handle arrays/lists
                        try:
                            import json
                            json.dumps(raw_value)  # Test if serializable
                            value = raw_value
                        except (TypeError, ValueError):
                            value = [str(item) if hasattr(item, '__dict__') else item for item in raw_value]
                    else:
                        value = raw_value
            except Exception as e:  # noqa: BLE001
                value_error = str(e)

            item = {
                "opc_address": node_id,
                "browse_name": browse_name,
                "display_name": display_name,
                "value": value,
            }
            if value_error:
                item["value_error"] = value_error

            if depth >= max_depth_int:
                item["children"] = []
                return item

            children_items = []
            try:
                for ch in node.get_children():
                    children_items.append(serialize_node(ch, depth + 1))
            except Exception as e:  # noqa: BLE001
                item["children_error"] = str(e)
                item["children"] = []
                return item

            item["children"] = children_items
            return item

        client = None
        try:
            client = create_opcua_client(
                endpoint_url=connection.endpoint_url,
                timeout_seconds=connection.timeout_seconds,
                security_policy=connection.security_policy,
                security_mode=connection.security_mode,
                auth_type=connection.auth_type,
                username=connection.username,
                password=connection.password,
                client_cert_path=connection.client_cert_path,
                client_key_path=connection.client_key_path,
                server_cert_path=connection.server_cert_path,
            )
            client.connect()
            
            if starting_node:
                # Start from specified node
                start_node = client.get_node(starting_node)
                data = serialize_node(start_node, 0)
            else:
                # Start from root node
                root = client.get_root_node()
                data = serialize_node(root, 0)

            return Response({"ok": True, "connection_id": connection.id, "tree": data})
        except OPCError as e:
            return Response({"ok": False, "error": e.to_dict()}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:  # noqa: BLE001
            return Response(
                {"ok": False, "error": {"code": "OPC_BROWSE_FAILED", "message": str(e), "details": {}}},
                status=status.HTTP_400_BAD_REQUEST,
            )
        finally:
            if client is not None:
                try:
                    client.disconnect()
                except Exception:
                    pass

class OPCNodeLiveViewSet(ModelViewSet):
    queryset         = OPCNodeLive.objects.all()
    serializer_class = OPCNodeLiveSerializer
    filterset_fields = ["node"]


class OPCPollingScheduleView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        result = poll_due_opc_connections.delay()
        return Response({"ok": True, "task_id": result.id})


class OPCPollingRunConnectionView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, connection_id: int):
        if not OPCConnection.objects.filter(pk=connection_id, is_deleted=False).exists():
            raise NotFound(detail=f"OPCConnection with id={connection_id} not found.")
        result = poll_opc_connection.delay(connection_id)
        return Response({"ok": True, "task_id": result.id, "connection_id": connection_id})

class OPCConnectionLatestValuesView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, connection_id: int):
        if not OPCConnection.objects.filter(pk=connection_id, is_deleted=False).exists():
            raise NotFound(detail=f"OPCConnection with id={connection_id} not found.")
        live_tags = (
            OPCNodeLive.objects
            .filter(node__object__connection_id=connection_id)
            .select_related("node")
            .all()
        )
        now = timezone.now()
        data = []
        for lt in live_tags:
            data.append(
                {
                    "node_id": lt.node_id,
                    "node_name": lt.node.name,
                    "opc_address": lt.node.opc_address,
                    "value": lt.value,
                    "actual_value": lt.actual_value,
                    "actual_timestamp": lt.actual_timestamp,
                    "status": lt.status,
                    "server_ts": lt.server_ts,
                    "timestamp": lt.source_ts or lt.server_ts or now,
                }
            )
        return Response({"ok": True, "connection_id": connection_id, "results": data})

class OPCNodeHistoryViewSet(ModelViewSet):
    queryset         = OPCNodeHistory.objects.all()
    serializer_class = OPCNodeHistorySerializer
    filterset_class  = OPCNodeHistoryFilter

class OPCAlarmRuleViewSet(ModelViewSet):
    queryset         = OPCAlarmRule.objects.all()
    serializer_class = OPCAlarmRuleSerializer
    filterset_class  = OPCAlarmRuleFilter

class OPCSiteBaseAlarmRuleViewSet(ModelViewSet):
    queryset         = OPCSiteBaseAlarmRule.objects.all()
    serializer_class = OPCSiteBaseAlarmRuleSerializer
    filterset_class  = OPCSiteBaseAlarmRuleFilter


    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)
        return Response(
            {"detail": "OPCSiteBaseAlarmRule created.", "data": serializer.data},
            status=status.HTTP_201_CREATED,
        )

    def update(self, request, *args, **kwargs):
        partial  = kwargs.pop("partial", False)   
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=partial)
        serializer.is_valid(raise_exception=True)
        self.perform_update(serializer)
        return Response(
            {"detail": "OPCSiteBaseAlarmRule updated.", "data": serializer.data},
            status=status.HTTP_200_OK,
        )
    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        rule_id = instance.id
        self.perform_destroy(instance)
        return Response(
            {"detail": "OPCSiteBaseAlarmRule deleted.", "rule_id": rule_id},
            status=status.HTTP_200_OK,
        )


class OPCNodeHistoryViewSet2(ModelViewSet):
    queryset         = OPCNodeHistory.objects.all()
    serializer_class = OPCNodeHistorySerializer
    filterset_class  = OPCNodeHistoryFilter
    pagination_class = None  # disables pagination

class OPCAlarmRuleViewSet2(ModelViewSet):
    queryset         = OPCAlarmRule.objects.all()
    serializer_class = OPCAlarmRuleSerializer
    filterset_fields = ["node", "alarm_type", "severity", "enabled"]
    pagination_class = None  # disables pagination

class OPCSiteBaseAlarmRuleViewSet2(ModelViewSet):
    queryset         = OPCSiteBaseAlarmRule.objects.all()
    serializer_class = OPCSiteBaseAlarmRuleSerializer
    filterset_fields = ["node", "alarm_type", "severity", "enabled"]
    pagination_class = None  # disables pagination

class OPCAlarmLiveViewSet(ModelViewSet):
    queryset         = OPCAlarmLive.objects.all()
    serializer_class = OPCAlarmLiveSerializer
    filterset_class  = OPCAlarmLiveFilter


class AcknowledgeAlarmView(APIView):
    """
    POST /api/alarms/<alarm_id>/acknowledge/

    Acknowledges an active live alarm by its ID.
    (OPCAlarmLive uses rule as its primary key, so alarm_id == rule_id.)

    Updates both:
      - OPCAlarmLive (current state)
      - OPCAlarmEvent (currently-active event with ended_at IS NULL)
    """
    permission_classes = [IsAuthenticated]

    def post(self, request, alarm_id):
        try:
            live = OPCAlarmLive.objects.select_related("rule").get(
                pk=alarm_id,
                rule__is_deleted=False,
            )
        except OPCAlarmLive.DoesNotExist:
            raise NotFound(detail=f"Active alarm with id={alarm_id} not found.")

        if not live.is_active:
            return Response(
                {"detail": "Alarm is not active."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        if live.acknowledged:
            return Response(
                {"detail": "Alarm already acknowledged."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        now  = timezone.now()
        user = request.user

        with transaction.atomic():
            live.acknowledged    = True
            live.acknowledged_at = now
            live.acknowledged_by = user
            live.save(update_fields=[
                "acknowledged", "acknowledged_at", "acknowledged_by", "updated_at"
            ])

            OPCAlarmEvent.objects.filter(
                rule_id=live.rule_id,
                ended_at__isnull=True,
                acknowledged=False,
            ).update(
                acknowledged=True,
                acknowledged_at=now,
                acknowledged_by=user,
            )

        return Response(OPCAlarmLiveSerializer(live).data)


class OPCAlarmEventViewSet(ModelViewSet):
    queryset         = OPCAlarmEvent.objects.all()
    serializer_class = OPCAlarmEventSerializer
    filterset_class  = OPCAlarmEventFilter

class OPCAlarmEventViewSet2(ModelViewSet):
    queryset         = OPCAlarmEvent.objects.all()
    serializer_class = OPCAlarmEventSerializer
    filterset_class  = OPCAlarmEventFilter
    pagination_class = None  # disables pagination

class OPCLastActiveAlarmsView(APIView):
    """
    GET /api/opc-active-alarms/
    Returns the last 10 active alarms ordered by activation time (newest first).
    Inputs: ?rows_count=10 (optional, default is 10)
    Output: [
        {
            "rule": 1,
            "value": 123.45,
            "status": "Good",
            "message": "Alarm message",
            "activated_at": "2024-01-01T12:00:00Z",
            ...
        },
        ...    ]
    """
    permission_classes = [IsAuthenticated]

    def get(self, request ):
        rows_count   = request.query_params.get("rows_count")
        rows_count = int(rows_count) if rows_count and rows_count.isdigit() else 10

        active = (
            OPCAlarmLive.objects
            .filter(is_active=True, rule__is_deleted=False)
            .select_related("rule", "rule__node")
            .order_by("-activated_at")[:rows_count]
        )
        serializer = OPCAlarmLiveSerializer(active, many=True)
        return Response(serializer.data)

class OPCLastAlarmEventsView(APIView):
    """
    GET /api/opc-alarm-daily-count/
    Returns alarm event count per day for the last N days.
    Inputs: ?days_count=5 (optional, default is 5)
    Output: [
        {"day": "2024-01-01", "count": 5},
        {"day": "2024-01-02", "count": 3},
        ...
    ]
    """
    permission_classes = [IsAuthenticated]

    def get(self, request):


        days_count = request.query_params.get("days_count")
        days_count = int(days_count) if days_count and days_count.isdigit() else 5

        today = timezone.localdate()
        start_date = today - datetime.timedelta(days=days_count - 1)

        since = timezone.make_aware(
            datetime.datetime.combine(start_date, datetime.time.min)
        )

        data = (
            OPCAlarmEvent.objects
            .filter(started_at__gte=since, rule__is_deleted=False)
            .annotate(day=TruncDate("started_at"))
            .values("day")
            .annotate(count=Count("id"))
            .order_by("day")
        )

        counts_by_day = {
            item["day"]: item["count"]
            for item in data
        }

        result = []
        for i in range(days_count):
            day = start_date + datetime.timedelta(days=i)
            result.append({
                "day": day,
                "count": counts_by_day.get(day, 0)
            })

        return Response(result)

class OPCNodeValueHistoryView(APIView):
    """
    GET /api/opc-node-value-history/
    Returns paginated value history for a specific node.
    Pass EITHER date range OR number of days — not both.

    ?node=1
    ?node=1&from_date=2026-01-01&to_date=2026-01-31
    ?node=1&days=7|30|90|365
    ?ascending=true
    ?page=1&page_size=100
    """
    permission_classes = [IsAuthenticated]

    def get(self, request):
        node_id   = request.query_params.get("node")
        from_date = request.query_params.get("from_date")
        to_date   = request.query_params.get("to_date")
        days      = request.query_params.get("days")
        ascending = request.query_params.get("ascending", "false").lower() == "true"

        if not node_id:
            return Response({"error": "node parameter is required."}, status=400)

        try:
            page      = max(1, int(request.query_params.get("page", 1)))
            page_size = max(1, int(request.query_params.get("page_size", 100)))
        except ValueError:
            return Response({"error": "page and page_size must be numbers."}, status=400)

        has_range = from_date or to_date
        has_days  = days

        if has_range and has_days:
            return Response(
                {"error": "Use either date range (from_date/to_date) or days — not both."},
                status=400,
            )

        order = "source_ts" if ascending else "-source_ts"
        qs    = OPCNodeHistory.objects.filter(node__id=node_id).order_by(order)

        if has_days:
            try:
                days_int = int(days)
                if days_int not in (7, 30, 90, 365):
                    return Response({"error": "days must be 7, 30, 90, or 365."}, status=400)
            except ValueError:
                return Response({"error": "days must be a number."}, status=400)
            since = timezone.now() - datetime.timedelta(days=days_int)
            qs = qs.filter(source_ts__gte=since)

        elif has_range:
            if from_date:
                qs = qs.filter(source_ts__date__gte=from_date)
            if to_date:
                qs = qs.filter(source_ts__date__lte=to_date)

        # ── Pagination ───────────────────────────────────────
        total  = qs.count()
        offset = (page - 1) * page_size
        data   = list(qs[offset: offset + page_size].values(
            "id", "node", "source_ts", "value", 
            "actual_value", "actual_timestamp", "status", 
            "server_ts", "created_at"
        ))

        return Response({
            "count":     total,
            "page":      page,
            "page_size": page_size,
            "pages":     (total + page_size - 1) // page_size,
            "results":   data,
        })

class OPCAlarmSeverityCountView(APIView):
    """
    GET /api/opc-alarm-severity-count/
    Returns count of currently active alarms grouped by severity.
    """
    permission_classes = [IsAuthenticated]

    def get(self, request):
        active = (
            OPCAlarmLive.objects
            .filter(is_active=True, rule__is_deleted=False)
            .values(severity=F("rule__severity"))
            .annotate(count=Count("pk"))
            .order_by("severity")
        )
        return Response(list(active))

class EnergyMWH4DailyAccumulatedView(APIView):
    """
    GET /api/energy-mwh-4-daily-accumulated/

    Energy Example:

    /api/energy-mwh-4-daily-accumulated/?node_object_opc_name=energy_mwh_4&node_name=value

    Calculates daily energy consumption from cumulative (accumulated) readings.
    For each day:  daily_energy = last_reading_of_day - first_reading_of_day  (per node)
    Then sums across all matching nodes.

    Query params:
      ?node_opc_name=energy_mwh_4          filter by OPCNode.opc_name  (preferred)
      ?node_object_opc_name=SomeObject     filter by parent OPCObject.opc_name
      ?node_name=energy_mwh_4              fallback — matches OPCNode.name or OPCNode.opc_name
      ?ets_site=1                          optional — filter by site id
      ?days_count=7                        default: 7
    """
    permission_classes = [IsAuthenticated]

    def get(self, request):
        

        node_opc_name        = request.query_params.get("node_opc_name")
        node_object_opc_name = request.query_params.get("node_object_opc_name" ,"energy_mwh_4")
        node_name            = request.query_params.get("node_name", "value")
        ets_site             = request.query_params.get("ets_site")

        try:
            days = int(request.query_params.get("days_count", 7))
            if days <= 0:
                return Response({"error": "days_count must be greater than 0."}, status=400)
        except ValueError:
            return Response({"error": "days_count must be a number."}, status=400)

        today      = timezone.localdate()
        start_date = today - datetime.timedelta(days=days - 1)
        start_dt   = timezone.make_aware(datetime.datetime.combine(start_date, datetime.time.min))
        end_dt     = timezone.make_aware(datetime.datetime.combine(today + datetime.timedelta(days=1), datetime.time.min))

        # Build node queryset based on which params were provided
        nodes = OPCNode.objects.all()

        if node_opc_name and node_object_opc_name:
            # Most specific: match both node opc_name AND parent object opc_name
            nodes = nodes.filter(
                opc_name__iexact=node_opc_name,
                object__opc_name__iexact=node_object_opc_name,
            )
        elif node_opc_name:
            # Filter by node opc_name only
            nodes = nodes.filter(opc_name__iexact=node_opc_name)
        elif node_object_opc_name:
            # Filter by parent object opc_name only
            nodes = nodes.filter(object__opc_name__iexact=node_object_opc_name)
        else:
            # Fallback: match node_name against both name and opc_name
            nodes = nodes.filter(
                Q(name__iexact=node_name) | Q(opc_name__iexact=node_name)
            )

        if ets_site:
            nodes = nodes.filter(object__asset__ets_site_id=ets_site)

        node_ids = list(nodes.values_list("id", flat=True))

        if not node_ids:
            return Response({
                "node_opc_name":        node_opc_name,
                "node_object_opc_name": node_object_opc_name,
                "node_name":            node_name,
                "ets_site":             ets_site,
                "nodes_count":          0,
                "results":              [],
            })

        # First reading per node per day (earliest source_ts)
        first_readings = {
            (r["node_id"], r["day"]): r["value"]
            for r in (
                OPCNodeHistory.objects
                .filter(node_id__in=node_ids, source_ts__gte=start_dt, source_ts__lt=end_dt)
                .annotate(day=TruncDate("source_ts"))
                .order_by("node_id", "day", "source_ts")
                .distinct("node_id", "day")
                .values("node_id", "day", "value")
            )
        }

        # Last reading per node per day (latest source_ts)
        last_readings = {
            (r["node_id"], r["day"]): r["value"]
            for r in (
                OPCNodeHistory.objects
                .filter(node_id__in=node_ids, source_ts__gte=start_dt, source_ts__lt=end_dt)
                .annotate(day=TruncDate("source_ts"))
                .order_by("node_id", "day", "-source_ts")
                .distinct("node_id", "day")
                .values("node_id", "day", "value")
            )
        }

        result = []
        for i in range(days):
            day          = start_date + datetime.timedelta(days=i)
            daily_energy = 0.0

            for node_id in node_ids:
                first = first_readings.get((node_id, day))
                last  = last_readings.get((node_id, day))
                if first is not None and last is not None:
                    daily_energy += max(float(last or 0) - float(first or 0), 0)

            result.append({
                "day":          day.isoformat(),
                "daily_energy": round(daily_energy, 4),
            })

        return Response({
            "node_opc_name":        node_opc_name,
            "node_object_opc_name": node_object_opc_name,
            "node_name":            node_name,
            "ets_site":             ets_site,
            "nodes_count":          len(node_ids),
            "results":              result,
        })

class OPCSiteNodesHistoryView(APIView):
    """
    GET /api/opc-site-node-history/{site_id}/
    Returns readings for each of the 6 fixed node types for a site.

    Pass EITHER date range OR number of days — not both.
    If nothing is passed, defaults to current billing cycle (billing_day → now).

    ?days=7|30|90|365
    ?from_date=2026-01-01&to_date=2026-01-31
    ?points=30   (max records per node, default 30)
    
    """
    permission_classes = [IsAuthenticated]

    def get(self, request, site_id: int):
        try:
            site = ETSSite.objects.select_related("billing_config").get(pk=site_id, is_deleted=False)
        except ETSSite.DoesNotExist:
            raise NotFound(detail=f"ETSSite with id={site_id} not found.")

        from_date = request.query_params.get("from_date")
        to_date   = request.query_params.get("to_date")
        days      = request.query_params.get("days")

        try:
            points = int(request.query_params.get("points", 50))
            if points <= 0:
                return Response({"error": "points must be greater than 0."}, status=400)
        except ValueError:
            return Response({"error": "points must be a number."}, status=400)

        has_range = from_date or to_date
        has_days  = days

        if has_range and has_days:
            return Response(
                {"error": "Use either date range (from_date/to_date) or days — not both."},
                status=400,
            )

        # ── Build date filter kwargs ─────────────────────────
        date_filter = {}

        if has_days:
            try:
                days_int = int(days)
                if days_int not in (7, 30, 90, 365):
                    return Response({"error": "days must be 7, 30, 90, or 365."}, status=400)
            except ValueError:
                return Response({"error": "days must be a number."}, status=400)
            since = timezone.now() - datetime.timedelta(days=days_int)
            date_filter["actual_timestamp__gte"] = since

        elif has_range:
            if from_date:
                date_filter["actual_timestamp__date__gte"] = from_date
            if to_date:
                date_filter["actual_timestamp__date__lte"] = to_date

        else:
            # ── Default: current billing cycle ───────────────
            today       = timezone.localdate()
            billing_day = None
            try:
                billing_day = site.billing_config.billing_day
            except Exception:
                pass

            if billing_day:
                if today.day >= billing_day:
                    default_from = today.replace(day=billing_day)
                else:
                    first_of_month  = today.replace(day=1)
                    prev_month_last = first_of_month - datetime.timedelta(days=1)
                    default_from    = prev_month_last.replace(day=billing_day)
            else:
                default_from = today.replace(day=1)

            date_filter["actual_timestamp__date__gte"] = default_from

        # ── Fetch helper with downsampling ───────────────────
        # Uses actual_value / actual_timestamp consistently (the parsed numeric
        # value and the timestamp from the VTS JSON payload). Rows where either
        # field is NULL are filtered out so they don't poison the downsample
        # buckets or the average.
        def fetch(object_opc_name):
            all_data = list(
                OPCNodeHistory.objects
                .filter(
                    node__object__asset__ets_site_id=site_id,
                    node__object__opc_name__iexact=object_opc_name,
                    node__opc_name__in=["VTS", "vts", "Value", "value"],
                    actual_value__isnull=False,
                    actual_timestamp__isnull=False,
                    **date_filter,
                )
                .order_by("actual_timestamp")
                .values("node_id", "actual_timestamp", "actual_value")
            )

            total = len(all_data)

            # If within limit, return as-is
            if total <= points:
                return all_data

            # Downsample: divide into `points` buckets, average each
            result      = []
            bucket_size = total / points

            for i in range(points):
                start  = int(i * bucket_size)
                end    = int((i + 1) * bucket_size)
                bucket = all_data[start:end]

                if not bucket:
                    continue

                valid_values = [
                    r["actual_value"] for r in bucket
                    if r["actual_value"] is not None and r["actual_value"] > -99998
                ]
                avg_value    = round(sum(valid_values) / len(valid_values), 4) if valid_values else None
                mid_ts       = bucket[len(bucket) // 2]["actual_timestamp"]
                node_id      = bucket[0]["node_id"]

                result.append({
                    "node_id":          node_id,
                    "actual_timestamp": mid_ts,
                    "actual_value":     avg_value,
                })

            return result

        # ── Average helper (skip None and sentinel -99998 values) ─────────────
        def calc_average(series):
            valid = [
                r["actual_value"] for r in series
                if r["actual_value"] is not None and r["actual_value"] > -99998
            ]
            if not valid:
                return None
            return round(sum(valid) / len(valid), 4)

        # Compute series once, reuse for both response payload and averages
        energy_mwh_4    = fetch("energy_mwh_4")
        power_kw_5      = fetch("power_kw_5")
        temp_supply_c_2 = fetch("temp_supply_c_2")
        temp_return_c_3 = fetch("temp_return_c_3")
        flow_m3h_1      = fetch("flow_m3h_1")
        temp_diff_k_7   = fetch("temp_diff_k_7")

        return Response({
            "energy_mwh_4":    energy_mwh_4,
            "power_kw_5":      power_kw_5,
            "temp_supply_c_2": temp_supply_c_2,
            "temp_return_c_3": temp_return_c_3,
            "flow_m3h_1":      flow_m3h_1,
            "temp_diff_k_7":   temp_diff_k_7,
            "averages": {
                "energy_mwh_4":    calc_average(energy_mwh_4),
                "power_kw_5":      calc_average(power_kw_5),
                "temp_supply_c_2": calc_average(temp_supply_c_2),
                "temp_return_c_3": calc_average(temp_return_c_3),
                "flow_m3h_1":      calc_average(flow_m3h_1),
                "temp_diff_k_7":   calc_average(temp_diff_k_7),
            },
        })

class OPCSiteDashboardView(APIView):
    """
    GET /api/site-dashboard/{site_id}/

    Returns a full dashboard for a single ETS site:
      - site          : full site info
      - active_alarms : currently active alarms (excluding soft-deleted rules)
      - objects       : OPC objects with their nodes and current live values
      - node_history  : 6 fixed metrics + their averages over the date range
      - billing_data  : current billing-cycle preview (computed, not saved)
    """
    permission_classes = [IsAuthenticated]

    def get(self, request, site_id: int):

        # ── Site ──────────────────────────────────────────────────────────────
        try:
            site = ETSSite.objects.select_related("billing_config").get(
                pk=site_id, is_deleted=False
            )
        except ETSSite.DoesNotExist:
            raise NotFound(detail=f"ETSSite with id={site_id} not found.")

        # ── Filters ───────────────────────────────────────────────────────────
        from_date = request.query_params.get("from_date")
        to_date   = request.query_params.get("to_date")

        # =====================================================================
        # Helper functions (closures over site, site_id, from_date, to_date)
        # =====================================================================

        # ── Active alarms ────────────────────────────────────────────────────
        def get_active_alarms():
            qs = (
                OPCAlarmLive.objects
                .filter(
                    rule__node__object__asset__ets_site_id=site_id,
                    rule__is_deleted=False,
                    is_active=True,
                    acknowledged=False,
                )
                .select_related(
                    "rule",
                    "rule__node",
                    "rule__node__object",
                    "rule__node__object__asset",
                )
                .order_by("-activated_at")
            )

            return [
                {
                    "rule_id":          alarm.rule_id,
                    "rule_name":        alarm.rule.name,
                    "alarm_type":       alarm.rule.alarm_type,
                    "severity":         alarm.rule.severity,
                    "limit_value":      alarm.rule.limit_value,
                    "node_name":        alarm.rule.node.name,
                    "object_name":      alarm.rule.node.object.name,
                    "value":            alarm.value,
                    "message":          alarm.message,
                    "activated_at":     alarm.activated_at,
                    "activation_count": alarm.activation_count,
                    "acknowledged":     alarm.acknowledged,
                }
                for alarm in qs
            ]

        # ── Objects + nodes + live values ────────────────────────────────────
        def get_objects_with_live():
            qs = (
                OPCObject.objects
                .filter(asset__ets_site_id=site_id)
                .select_related("connection", "asset")
                .prefetch_related(
                    Prefetch(
                        "opcnode_set",
                        queryset=OPCNode.objects.select_related("opcnodelive"),
                        to_attr="nodes_list",
                    )
                )
                .order_by("opc_name")
            )

            result = []
            for obj in qs:
                nodes_data = []
                for node in obj.nodes_list:
                    live = getattr(node, "opcnodelive", None)
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
                    })
                result.append({
                    "id":              obj.id,
                    "name":            obj.name,
                    "opc_name":        obj.opc_name,
                    "connection_name": obj.connection.name,
                    "nodes":           nodes_data,
                })
            return result

        # ── Node History fetch helper ────────────────────────────────────────
        def fetch(object_opc_name):
            qs = OPCNodeHistory.objects.filter(
                node__object__asset__ets_site_id=site_id,
                node__object__opc_name__iexact=object_opc_name,
                node__opc_name__in=["VTS", "vts", "Value", "value"],
                actual_value__isnull=False,
                actual_timestamp__isnull=False,
            )
            if from_date:
                qs = qs.filter(actual_timestamp__date__gte=from_date)
            if to_date:
                qs = qs.filter(actual_timestamp__date__lte=to_date)

            return list(
                qs.order_by("-actual_timestamp")
                .values("actual_value", "actual_timestamp")
            )

        # ── Average helper (skip None and sentinel -99998 values) ────────────
        def calc_average(series):
            valid = [
                r["actual_value"] for r in series
                if r["actual_value"] is not None and r["actual_value"] > -99998
            ]
            if not valid:
                return None
            return round(sum(valid) / len(valid), 4)

        # ── Node History block (series + averages) ───────────────────────────
        def get_node_history():
            energy_mwh_4    = fetch("energy_mwh_4")
            power_kw_5      = fetch("power_kw_5")
            temp_supply_c_2 = fetch("temp_supply_c_2")
            temp_return_c_3 = fetch("temp_return_c_3")
            flow_m3h_1      = fetch("flow_m3h_1")
            temp_diff_k_7   = fetch("temp_diff_k_7")

            return {
                "energy_mwh_4":    energy_mwh_4,
                "power_kw_5":      power_kw_5,
                "temp_supply_c_2": temp_supply_c_2,
                "temp_return_c_3": temp_return_c_3,
                "flow_m3h_1":      flow_m3h_1,
                "temp_diff_k_7":   temp_diff_k_7,
                "averages": {
                    "energy_mwh_4":    calc_average(energy_mwh_4),
                    "power_kw_5":      calc_average(power_kw_5),
                    "temp_supply_c_2": calc_average(temp_supply_c_2),
                    "temp_return_c_3": calc_average(temp_return_c_3),
                    "flow_m3h_1":      calc_average(flow_m3h_1),
                    "temp_diff_k_7":   calc_average(temp_diff_k_7),
                },
            }

        # ── Billing period helper ────────────────────────────────────────────
        def compute_billing_period(billing_day):
            today = timezone.localdate()

            if billing_day:
                if today.day >= billing_day:
                    period_from = today.replace(day=billing_day)
                else:
                    first_of_month     = today.replace(day=1)
                    last_of_prev_month = first_of_month - datetime.timedelta(days=1)
                    period_from        = last_of_prev_month.replace(day=billing_day)
            else:
                period_from = today.replace(day=1)

            period_to = today
            start_dt  = timezone.make_aware(datetime.datetime.combine(period_from, datetime.time.min))
            end_dt    = timezone.make_aware(datetime.datetime.combine(period_to + datetime.timedelta(days=1), datetime.time.min))
            return period_from, period_to, start_dt, end_dt

        # ── Billing Data (always current cycle, never affected by filter) ───────
        def get_billing_data():
            config = getattr(site, "billing_config", None)
            if config is None:
                return None

            # Always use the current billing cycle — ignore from_date / to_date
            period_from, period_to, _, _ = compute_billing_period(config.billing_day)

            # Already billed? frontend fetches from /api/ets-billing/
            if ETSSiteBilling.objects.filter(
                ets_site=site, from_date=period_from, to_date=period_to
            ).exists():
                return None

            data = calculate_site_billing(site, period_from, period_to)
            if data is None:
                return None

            return {
                "period_from":        period_from,
                "period_to":          period_to,
                "avg_delta_t":        round(data["average_delta_t"], 4) if data["average_delta_t"] is not None else None,
                "consumption":        round(data["consumption"], 4),
                "declared_load":      round(data["declared_load_fee"], 2),
                "delta_t_fees":       round(data["delta_t_fees"], 4),
                "consumption_fee":    round(data["consumption_fee"], 4),
                "total":              round(data["total"], 4),
                "energy_start":       data["energy_start"],
                "energy_end":         data["energy_end"],
                "avg_supply_temp":    data["avg_supply_temp"],
                "avg_return_temp":    data["avg_return_temp"],
                "avg_flow":           data["avg_flow"],
                "avg_power":          data["avg_power"],
                "contracted_delta_t":          data["contracted_delta_t"],
                "delta_t_drop":                data["delta_t_drop"],
                "is_low_delta_t":              data["is_low_delta_t"],
                "delta_t_fees_formula":               data["delta_t_fees_formula"],
                "delta_t_fees_formula_values":        data["delta_t_fees_formula_values"],
                "consumption_fee_formula":            data["consumption_fee_formula"],
                "consumption_fee_formula_values":     data["consumption_fee_formula_values"],
                "declared_load_fee_formula":          data["declared_load_fee_formula"],
                "declared_load_fee_formula_values":   data["declared_load_fee_formula_values"],
                "other_fees":                         data["other_fees"],
                "other_fees_formula":                 data["other_fees_formula"],
                "other_fees_formula_values":          data["other_fees_formula_values"],
                "period_days":                        data["period_days"],
                "readings_count":                     data["readings_count"],
                "billing_date":                       data["billing_date"],
            }

        # ── Filtered Billing (complete months only within from_date / to_date) ─
        def get_filtered_billing():
            if not from_date or not to_date:
                return []

            # Robust parse — handles "2026-5-28" (no zero-padding)
            def _parse(s):
                try:
                    parts = s.split("-")
                    return datetime.date(int(parts[0]), int(parts[1]), int(parts[2]))
                except Exception:
                    return None

            fd = _parse(from_date)
            td = _parse(to_date)
            if fd is None or td is None or fd > td:
                return []

            import calendar
            results = []

            # If fd is not the 1st, skip to next month (partial first month = skip)
            if fd.day == 1:
                cursor = fd
            elif fd.month == 12:
                cursor = fd.replace(year=fd.year + 1, month=1, day=1)
            else:
                cursor = fd.replace(month=fd.month + 1, day=1)

            while True:
                last_day  = calendar.monthrange(cursor.year, cursor.month)[1]
                month_end = cursor.replace(day=last_day)

                # Stop when month_end goes beyond td (incomplete month at end)
                if month_end > td:
                    break

                # Full month is within range — calculate
                data = calculate_site_billing(site, cursor, month_end)
                if data is not None:
                    results.append({
                        "period_from":        cursor,
                        "period_to":          month_end,
                        "avg_delta_t":        round(data["average_delta_t"], 4) if data["average_delta_t"] is not None else None,
                        "consumption":        round(data["consumption"], 4),
                        "declared_load":      round(data["declared_load_fee"], 2),
                        "delta_t_fees":       round(data["delta_t_fees"], 4),
                        "consumption_fee":    round(data["consumption_fee"], 4),
                        "total":              round(data["total"], 4),
                        "energy_start":       data["energy_start"],
                        "energy_end":         data["energy_end"],
                        "avg_supply_temp":    data["avg_supply_temp"],
                        "avg_return_temp":    data["avg_return_temp"],
                        "avg_flow":           data["avg_flow"],
                        "avg_power":          data["avg_power"],
                        "contracted_delta_t":          data["contracted_delta_t"],
                        "delta_t_drop":                data["delta_t_drop"],
                        "is_low_delta_t":              data["is_low_delta_t"],
                        "delta_t_fees_formula":        data["delta_t_fees_formula"],
                        "delta_t_fees_formula_values": data["delta_t_fees_formula_values"],
                        "period_days":                 data["period_days"],
                        "readings_count":              data["readings_count"],
                        "billing_date":                data["billing_date"],
                    })

                # Advance to next month
                if cursor.month == 12:
                    cursor = cursor.replace(year=cursor.year + 1, month=1, day=1)
                else:
                    cursor = cursor.replace(month=cursor.month + 1, day=1)

            return results

        # =====================================================================
        # Final response
        # =====================================================================
        return Response({
            "site":             ETSSiteSerializer(site).data,
            "active_alarms":    get_active_alarms(),
            "objects":          get_objects_with_live(),
            "node_history":     get_node_history(),
            "billing_data":     get_billing_data(),
            "filtered_billing": get_filtered_billing(),
        })

class OPCSiteObjectsLiveView(APIView):
    """
    GET /api/opc-site-live/{site_id}/

    Returns all OPC objects and their nodes with current live values for a site.
    Lightweight — no site info, no alarms, just objects → nodes → live.

    Optional query params:
      ?object_opc_name=energy_mwh_4   filter by a specific object
      ?node_opc_name=Value             filter by node opc_name (e.g. only Value nodes)
    """
    permission_classes = [IsAuthenticated]

    def get(self, request, site_id: int):
        

        if not ETSSite.objects.filter(pk=site_id, is_deleted=False).exists():
            raise NotFound(detail=f"ETSSite with id={site_id} not found.")

        object_opc_name = request.query_params.get("object_opc_name")
        node_opc_name   = request.query_params.get("node_opc_name")

        # Build node queryset with optional filter
        node_qs = OPCNode.objects.select_related("opcnodelive")

        if node_opc_name:
            node_qs = node_qs.filter(opc_name__iexact=node_opc_name)

        # Build object queryset
        obj_qs = (
            OPCObject.objects
            .filter(asset__ets_site_id=site_id)
            .select_related("connection", "asset")
            .prefetch_related(
                Prefetch("opcnode_set", queryset=node_qs, to_attr="nodes_list")
            )
            .order_by("opc_name")
        )

        if object_opc_name:
            obj_qs = obj_qs.filter(opc_name__iexact=object_opc_name)

        objects_data = []
        for obj in obj_qs:
            nodes_data = []
            for node in obj.nodes_list:
                live = getattr(node, "opcnodelive", None)
                nodes_data.append({
                    "id":        node.id,
                    "name":      node.name,
                    "opc_name":  node.opc_name,
                    "unit":      node.unit,
                    "data_type": node.data_type,
                    "value":            live.value            if live else None,
                    "actual_value":     live.actual_value     if live else None,
                    "actual_timestamp": live.actual_timestamp if live else None,
                    "status":           live.status           if live else None,
                    "source_ts":        live.source_ts        if live else None,
                    "server_ts":        live.server_ts        if live else None,
                    "updated_at":       live.updated_at       if live else None,
                    
                })
            objects_data.append({
                "id":              obj.id,
                "name":            obj.name,
                "opc_name":        obj.opc_name,
                "connection_name": obj.connection.name,
                "nodes":           nodes_data,
            })

        return Response({
            "site_id":       site_id,
            "objects_count": len(objects_data),
            "objects":       objects_data,
           })

class SiteBillingDataView(APIView):
    """
    GET /api/ets-sites/<site_id>/billing-data/?start_date=YYYY-MM-DD&end_date=YYYY-MM-DD

    Returns calculated billing data for a single site over a custom date range.
    This is a preview/calculation endpoint — it does NOT save a billing row.

    Query params:
        start_date : YYYY-MM-DD (inclusive)
        end_date   : YYYY-MM-DD (inclusive)

    Returns 400 if dates are missing/invalid or start > end.
    Returns 404 if site doesn't exist or is soft-deleted.
    Returns 400 if site has no billing_config.
    """
    permission_classes = [IsAuthenticated]

    def get(self, request, site_id: int):
        # ── Parse query params ─────────────────────────────────────────
        start_date_str = request.query_params.get("start_date")
        end_date_str   = request.query_params.get("end_date")

        if not start_date_str or not end_date_str:
            return Response(
                {"detail": "Both start_date and end_date query params are required."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            start_date = datetime.date.fromisoformat(start_date_str)
            end_date   = datetime.date.fromisoformat(end_date_str)
        except ValueError:
            return Response(
                {"detail": "Dates must be in YYYY-MM-DD format."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        if start_date > end_date:
            return Response(
                {"detail": "start_date must be on or before end_date."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # ── Fetch the site ─────────────────────────────────────────────
        try:
            site = ETSSite.objects.select_related("billing_config").get(
                pk=site_id, is_deleted=False
            )
        except ETSSite.DoesNotExist:
            raise NotFound(detail=f"ETSSite with id={site_id} not found.")

        # ── Compute billing via helper ─────────────────────────────────
        data = calculate_site_billing(site, start_date, end_date)
        if data is None:
            return Response(
                {"detail": "Site has no billing_config — cannot compute billing."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        return Response({
            "site_id":    site.id,
            "site_name":  site.name,
            "start_date": start_date,
            "end_date":   end_date,
            "average_delta_t": data["average_delta_t"],
            "delta_t_fees":    round(data["delta_t_fees"], 2),
            "consumption":     round(data["consumption"], 4),
            "consumption_fee": round(data["consumption_fee"], 2),
            "declared_load_fee": round(data["declared_load_fee"], 2),
            "total":             round(data["total"], 2),
        })

#-----------------------------------------------------------------------------
# ── Fetch historical data from external historian API and store in OPCNodeHistory ──
#-----------------------------------------------------------------------------


def _extract_opc_node_id(opc_name: str) -> int | None:
    if not opc_name:
        return None
    parts = opc_name.rsplit("_", 1)
    if len(parts) == 2 and parts[1].isdigit():
        return int(parts[1])
    return None


def _derive_http_base(endpoint_url: str) -> str:
    host = urlparse(endpoint_url).hostname or "localhost"
    return f"http://{host}"


class OPCHistorianFetchView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        api_token = getattr(settings, "OPC_HISTORIAN_API_TOKEN", "")
        hours = getattr(settings, "OPC_HISTORIAN_HOURS", 24)

        if not api_token:
            return Response(
                {"ok": False, "error": "OPC_HISTORIAN_API_TOKEN is not configured in settings."},
                status=400,
            )

        objects = OPCObject.objects.select_related(
            "asset__connection"
        ).prefetch_related(
            "opcnode_set"
        ).iterator(chunk_size=2000)

        results = {"total_objects": 0, "success": 0, "skipped": 0, "errors": []}

        for obj in objects:
            results["total_objects"] += 1

            vts_node = next((n for n in obj.opcnode_set.all() if n.opc_name.lower() == "vts"), None)
            if vts_node is None:
                results["skipped"] += 1
                logger.debug("Skipped object %d (opc_name='%s'): no VTS child node", obj.id, obj.opc_name)
                continue

            node_id = _extract_opc_node_id(obj.opc_name)
            if node_id is None:
                results["skipped"] += 1
                logger.debug("Skipped object %d (opc_name='%s'): no numeric ID found", obj.id, obj.opc_name)
                continue

            connection = obj.asset.connection
            base_url = _derive_http_base(connection.endpoint_url)
            historian_url = (
                f"{base_url}/api/data-points/{node_id}/historian"
                f"?hours={hours}&api_token={api_token}"
            )

            try:
                req = URLRequest(historian_url, method="GET")
                with urlopen(req, timeout=30) as resp:
                    body = _json.loads(resp.read().decode())

                if not body.get("success"):
                    results["errors"].append({
                        "object_id": obj.id,
                        "opc_name": obj.opc_name,
                        "error": body.get("error", "API returned success=false"),
                    })
                    continue

                historian_data = body.get("historian_data", [])
                if not historian_data:
                    results["skipped"] += 1
                    continue

                timestamps_to_insert = []
                for entry in historian_data:
                    ts = entry.get("timestamp")
                    if ts:
                        timestamps_to_insert.append(ts)

                if timestamps_to_insert:
                    existing_ts = set(
                        OPCNodeHistory.objects
                        .filter(node=vts_node, actual_timestamp__in=timestamps_to_insert)
                        .values_list("actual_timestamp", flat=True)
                    )
                else:
                    existing_ts = set()

                new_records = [
                    OPCNodeHistory(
                        node=vts_node,
                        actual_value=entry.get("value"),
                        actual_timestamp=ts,
                        source_ts=ts,
                        value=entry,
                    )
                    for entry, ts in zip(historian_data, timestamps_to_insert)
                    if ts and ts not in existing_ts
                ]

                if new_records:
                    OPCNodeHistory.objects.bulk_create(new_records)
                    results["success"] += 1
                else:
                    results["skipped"] += 1

            except (URLError, HTTPError, OSError, _json.JSONDecodeError) as e:
                results["errors"].append({
                    "object_id": obj.id,
                    "opc_name": obj.opc_name,
                    "error": str(e),
                })
                logger.warning("Failed to fetch historian for object %d (%s): %s", obj.id, obj.opc_name, e)

        return Response({"ok": True, "results": results})

#-----------------------------------------------------------------------------
# ── Soft delete / restore for OPCConnection and OPCAlarmRule ───────────────
#-----------------------------------------------------------------------------
class OPCConnectionSoftDeleteView(APIView):
    """
    POST /api/opc-connections/<id>/soft-delete/
    Restricted to super admins. Marks the connection as deleted so polling,
    list endpoints, and connection-specific endpoints stop seeing it.
    """
    permission_classes = [IsSuperAdmin]

    def post(self, request, pk: int):
        try:
            conn = OPCConnection.objects.get(pk=pk)
        except OPCConnection.DoesNotExist:
            return Response({"detail": "OPCConnection not found."}, status=status.HTTP_404_NOT_FOUND)
        if conn.is_deleted:
            return Response({"detail": "OPCConnection is already soft-deleted."}, status=status.HTTP_400_BAD_REQUEST)
        conn.is_deleted = True
        conn.save(update_fields=["is_deleted"])
        return Response({"detail": "OPCConnection soft-deleted.", "connection_id": conn.id})

class OPCConnectionRestoreView(APIView):
    """
    POST /api/opc-connections/<id>/restore/
    Restricted to super admins.
    """
    permission_classes = [IsSuperAdmin]

    def post(self, request, pk: int):
        try:
            conn = OPCConnection.objects.get(pk=pk)
        except OPCConnection.DoesNotExist:
            return Response({"detail": "OPCConnection not found."}, status=status.HTTP_404_NOT_FOUND)
        if not conn.is_deleted:
            return Response({"detail": "OPCConnection is not deleted."}, status=status.HTTP_400_BAD_REQUEST)
        conn.is_deleted = False
        conn.save(update_fields=["is_deleted"])
        return Response({"detail": "OPCConnection restored.", "connection_id": conn.id})

class OPCAlarmRuleSoftDeleteView(APIView):
    """
    POST /api/opc-alarm-rules/<id>/soft-delete/
    Restricted to super admins. After soft delete the rule is skipped in
    check_alarms() and hidden from live alarm / dashboard endpoints.
    """
    permission_classes = [IsSuperAdmin]

    def post(self, request, pk: int):
        try:
            rule = OPCAlarmRule.objects.get(pk=pk)
        except OPCAlarmRule.DoesNotExist:
            return Response({"detail": "OPCAlarmRule not found."}, status=status.HTTP_404_NOT_FOUND)
        if rule.is_deleted:
            return Response({"detail": "OPCAlarmRule is already soft-deleted."}, status=status.HTTP_400_BAD_REQUEST)
        rule.is_deleted = True
        rule.save(update_fields=["is_deleted"])
        return Response({"detail": "OPCAlarmRule soft-deleted.", "rule_id": rule.id})

class OPCAlarmRuleRestoreView(APIView):
    """
    POST /api/opc-alarm-rules/<id>/restore/
    Restricted to super admins.
    """
    permission_classes = [IsSuperAdmin]

    def post(self, request, pk: int):
        try:
            rule = OPCAlarmRule.objects.get(pk=pk)
        except OPCAlarmRule.DoesNotExist:
            return Response({"detail": "OPCAlarmRule not found."}, status=status.HTTP_404_NOT_FOUND)
        if not rule.is_deleted:
            return Response({"detail": "OPCAlarmRule is not deleted."}, status=status.HTTP_400_BAD_REQUEST)
        rule.is_deleted = False
        rule.save(update_fields=["is_deleted"])
        return Response({"detail": "OPCAlarmRule restored.", "rule_id": rule.id})

class OPCSiteBaseAlarmRuleSoftDeleteView(APIView):
    """
    POST /api/opc-alarm-base-rules/<id>/soft-delete/
    Restricted to super admins. After soft delete the rule is skipped in
    check_alarms() and hidden from live alarm / dashboard endpoints.
    """
    permission_classes = [IsSuperAdmin]

    def post(self, request, pk: int):
        try:
            rule = OPCSiteBaseAlarmRule.objects.get(pk=pk)
        except OPCSiteBaseAlarmRule.DoesNotExist:
            return Response({"detail": "OPCSiteBaseAlarmRule not found."}, status=status.HTTP_404_NOT_FOUND)
        if rule.is_deleted:
            return Response({"detail": "OPCSiteBaseAlarmRule is already soft-deleted."}, status=status.HTTP_400_BAD_REQUEST)
        # soft delete
        rule.is_deleted = True
        rule.deleted_at = timezone.now()
        rule.deleted_by = request.user
        rule.save(update_fields=["is_deleted", "deleted_at", "deleted_by"])
        return Response({"detail": "OPCSiteBaseAlarmRule soft-deleted.", "rule_id": rule.id})

class OPCSiteBaseAlarmRuleRestoreView(APIView):
    """
    POST /api/opc-alarm-base-rules/<id>/restore/
    Restricted to super admins.
    """
    permission_classes = [IsSuperAdmin]

    def post(self, request, pk: int):
        try:
            rule = OPCSiteBaseAlarmRule.objects.get(pk=pk)
        except OPCSiteBaseAlarmRule.DoesNotExist:
            return Response({"detail": "OPCSiteBaseAlarmRule not found."}, status=status.HTTP_404_NOT_FOUND)
        if not rule.is_deleted:
            return Response({"detail": "OPCSiteBaseAlarmRule is not deleted."}, status=status.HTTP_400_BAD_REQUEST)
        # restore
        rule.is_deleted = False
        rule.deleted_at = None
        rule.deleted_by = None
        rule.save(update_fields=["is_deleted", "deleted_at", "deleted_by"])
        return Response({"detail": "OPCSiteBaseAlarmRule restored.", "rule_id": rule.id})

class OPCGeneratedSiteLinkSoftDeleteView(APIView):
    """
    POST /api/opc-site-links/<uuid:pk>/soft-delete/
    Restricted to super admins. After soft delete the link is hidden from the
    default list and rejected by the public read endpoint.
    """
    permission_classes = [IsSuperAdmin]

    def post(self, request, pk):
        try:
            link = OPCGeneratedSiteLink.objects.get(pk=pk)
        except OPCGeneratedSiteLink.DoesNotExist:
            return Response({"detail": "OPCGeneratedSiteLink not found."}, status=status.HTTP_404_NOT_FOUND)
        if link.is_deleted:
            return Response({"detail": "OPCGeneratedSiteLink is already soft-deleted."},
                            status=status.HTTP_400_BAD_REQUEST)
        link.is_deleted = True
        link.updated_by = request.user if request.user.is_authenticated else None
        link.save(update_fields=["is_deleted", "updated_by", "updated_at"])
        return Response({"detail": "OPCGeneratedSiteLink soft-deleted.", "id": str(link.id)})

class OPCGeneratedSiteLinkRestoreView(APIView):
    """
    POST /api/opc-site-links/<uuid:pk>/restore/
    Restricted to super admins.
    """
    permission_classes = [IsSuperAdmin]

    def post(self, request, pk):
        try:
            link = OPCGeneratedSiteLink.objects.get(pk=pk)
        except OPCGeneratedSiteLink.DoesNotExist:
            return Response({"detail": "OPCGeneratedSiteLink not found."}, status=status.HTTP_404_NOT_FOUND)
        if not link.is_deleted:
            return Response({"detail": "OPCGeneratedSiteLink is not deleted."},
                            status=status.HTTP_400_BAD_REQUEST)
        link.is_deleted = False
        link.updated_by = request.user if request.user.is_authenticated else None
        link.save(update_fields=["is_deleted", "updated_by", "updated_at"])
        return Response({"detail": "OPCGeneratedSiteLink restored.", "id": str(link.id)})

# -------------------------------------------------------------------------------
# ── CRUD for OPCGeneratedSiteLink and link generation endpoint ───────────────
# -------------------------------------------------------------------------------

class OPCGeneratedSiteLinkViewSet(ModelViewSet):
    """
    /api/opc-site-links/
    Full CRUD for generated site links. Uses the standard ModelViewSet so the
    """
    queryset         = OPCGeneratedSiteLink.objects.all().select_related("site", "created_by", "updated_by")
    serializer_class = OPCGeneratedSiteLinkSerializer
    filterset_class  = OPCGeneratedSiteLinkFilter
    permission_classes = [IsAuthenticated]

    def perform_update(self, serializer):
        serializer.save(updated_by=self.request.user if self.request.user.is_authenticated else None)

class OPCGeneratedSiteLinkGenerateView(APIView):
    """
    POST /api/opc-site-links/generate/

    Create a new shareable link for an ETS site.

    Body (JSON):
        {
            "site_id":        <int>,                          required
            "username":       <str>,                          required — admin-chosen
            "date_from":      "YYYY-MM-DD" | ISO datetime,    required — start of history filter
            "date_to":        "YYYY-MM-DD" | ISO datetime,    required — end of history filter
            "expire_date":    ISO datetime,                   required — link expiry
            "selected_nodes": [<int>, ...]                    required — OPCNode IDs
        }

    Returns:
        {
            "ok":          true,
            "id":          "<uuid>",
            "url":         "<EXTERNAL_DASHBOARD_BASE_URL>?id=<uuid>",
            "username":    "<as supplied>",
            "password":    "<plaintext — ONE TIME ONLY>",
            "expire_date": "...",
            "state":       "active"
        }

    The plaintext password is returned exactly once. It is never stored
    plaintext anywhere — only the hash. If lost, generate a new link.
    """
    permission_classes = [IsAuthenticated]

    def post(self, request):
        site_id        = request.data.get("site_id")
        username       = request.data.get("username")
        date_from      = request.data.get("date_from")
        date_to        = request.data.get("date_to")
        expire_date    = request.data.get("expire_date")
        selected_nodes = request.data.get("selected_nodes")

        # ── Validate required fields ─────────────────────────────────────────
        missing = [
            name for name, value in (
                ("site_id",        site_id),
                ("username",       username),
                ("date_from",      date_from),
                ("date_to",        date_to),
                ("expire_date",    expire_date),
                ("selected_nodes", selected_nodes),
            ) if value in (None, "", [])
        ]
        if missing:
            return Response(
                {
                    "ok": False,
                    "error": {
                        "code": "VALIDATION_ERROR",
                        "message": f"Missing required field(s): {', '.join(missing)}",
                        "details": {field: ["This field is required."] for field in missing},
                    },
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        # ── Validate username ────────────────────────────────────────────────
        username = str(username).strip()
        if not username or len(username) > 64:
            return Response(
                {"ok": False, "error": {"code": "VALIDATION_ERROR",
                                        "message": "username must be a non-empty string up to 64 chars.",
                                        "details": {}}},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # ── Parse dates (date-only OR full ISO datetime) ─────────────────────
        def _parse_dt(raw, field_name):
            if isinstance(raw, datetime.datetime):
                value = raw
            else:
                value = None
                # Try datetime first, then date
                try:
                    value = datetime.datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
                except ValueError:
                    try:
                        d = datetime.date.fromisoformat(str(raw))
                        value = datetime.datetime.combine(d, datetime.time.min)
                    except ValueError:
                        return None, f"{field_name} must be YYYY-MM-DD or ISO datetime."
            if timezone.is_naive(value):
                value = timezone.make_aware(value)
            return value, None

        filter_start, err = _parse_dt(date_from, "date_from")
        if err:
            return Response({"ok": False, "error": {"code": "VALIDATION_ERROR", "message": err, "details": {}}},
                            status=status.HTTP_400_BAD_REQUEST)
        filter_end, err = _parse_dt(date_to, "date_to")
        if err:
            return Response({"ok": False, "error": {"code": "VALIDATION_ERROR", "message": err, "details": {}}},
                            status=status.HTTP_400_BAD_REQUEST)
        expire_dt, err = _parse_dt(expire_date, "expire_date")
        if err:
            return Response({"ok": False, "error": {"code": "VALIDATION_ERROR", "message": err, "details": {}}},
                            status=status.HTTP_400_BAD_REQUEST)

        if filter_start > filter_end:
            return Response(
                {"ok": False, "error": {"code": "VALIDATION_ERROR",
                                        "message": "date_from must be on or before date_to.", "details": {}}},
                status=status.HTTP_400_BAD_REQUEST,
            )
        if expire_dt <= timezone.now():
            return Response(
                {"ok": False, "error": {"code": "VALIDATION_ERROR",
                                        "message": "expire_date must be in the future.", "details": {}}},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # ── Validate site ────────────────────────────────────────────────────
        try:
            site = ETSSite.objects.get(pk=site_id, is_deleted=False)
        except ETSSite.DoesNotExist:
            return Response(
                {"ok": False, "error": {"code": "NOT_FOUND",
                                        "message": f"ETSSite with id={site_id} not found.", "details": {}}},
                status=status.HTTP_404_NOT_FOUND,
            )

        # ── Validate selected_nodes ──────────────────────────────────────────
        if not isinstance(selected_nodes, list) or not all(isinstance(n, int) for n in selected_nodes):
            return Response(
                {"ok": False, "error": {"code": "VALIDATION_ERROR",
                                        "message": "selected_nodes must be a list of OPCNode IDs (integers).",
                                        "details": {}}},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Make sure every selected node actually belongs to this site (via asset)
        valid_node_ids = list(
            OPCNode.objects
            .filter(id__in=selected_nodes, object__asset__ets_site_id=site.id)
            .values_list("id", flat=True)
        )
        invalid = sorted(set(selected_nodes) - set(valid_node_ids))
        if invalid:
            return Response(
                {"ok": False, "error": {"code": "VALIDATION_ERROR",
                                        "message": "Some selected_nodes do not belong to this site.",
                                        "details": {"invalid_node_ids": invalid}}},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # ── Generate credentials ─────────────────────────────────────────────
        password      = secrets.token_urlsafe(16)
        password_hash = make_password(password)

        # ── Build the snapshot payload (site + selected nodes with live +
        #    history + average, minus alarms and billing_data) ───────────────
        snapshot = build_site_link_snapshot(
            site=site,
            selected_node_ids=valid_node_ids,
            filter_start=filter_start,
            filter_end=filter_end,
        )
        snapshot["meta"] = {
            "site_id":        site.id,
            "username":       username,
            "selected_nodes": valid_node_ids,
            "date_from":      filter_start.isoformat(),
            "date_to":        filter_end.isoformat(),
            "expire_date":    expire_dt.isoformat(),
        }

        # ── Create the link (UUID PK auto-generated) ────────────────────────
        link = OPCGeneratedSiteLink(
            site=site,
            url="",  # filled in right after, once we have the UUID
            username=username,
            password_hash=password_hash,
            json_data=snapshot,
            is_active=True,
            is_deleted=False,
            expire_date=expire_dt,
            filter_start_date=filter_start,
            filter_end_date=filter_end,
            created_by=request.user if request.user.is_authenticated else None,
            updated_by=request.user if request.user.is_authenticated else None,
        )
        link.save()

        base_url = getattr(settings, "EXTERNAL_SERVER_UI_BASE_URL", "").rstrip("/")
        link.url = f"{base_url}?id={link.id}"
        link.save(update_fields=["url"])

        state = "active" if (link.is_active and not link.is_deleted and link.expire_date > timezone.now()) else "inactive"
        # Requst to post the data
        data={
        "id":link.id,
        "site": site.id,
        "username": username,
        "url":         link.url,
        "expire_date": expire_dt.isoformat(),
        "filter_start_date": filter_start.isoformat(),
        "filter_end_date": filter_end.isoformat(),
        "password_hash": password_hash,
        "json_data": snapshot,
        }

        send_post_to_external_api(base_url=None, url_path="api/opc-generated-site-links/", data=data)
        
        return Response(
            {
                "ok":          True,
                "id":          str(link.id),
                "url":         link.url,
                "username":    username,
                "password":    password,        # plaintext - one-time only
                "expire_date": link.expire_date,
                "state":       state,
            },
            status=status.HTTP_201_CREATED,
        )
