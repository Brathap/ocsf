"""Coverage and Normalization Fixture Test Suite.

Verifies detection, extraction, OCSF mapping, unmapped passthrough, and byte-span
lineage for all vendor source packs (FortiGate, Check Point, Juniper SRX, Suricata,
Zeek conn, Squid, pfSense filterlog, SonicWall, generic CEF, generic LEEF).
"""

import os
import sys
import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))
from source_packs.registry import SourcePackRegistry
from lineage_engine import LineageEngine

SOURCES_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "sources"))
REGISTRY = SourcePackRegistry(SOURCES_DIR)


def test_fortigate_kv_pack():
    raw = 'date=2026-10-06 time=09:30:00 devname="FG-500E" devid="FG500E4Q18000001" eventtime=1696584600123456789 type=traffic srcip=192.168.1.100 srcport=54321 dstip=198.51.100.25 dstport=443 proto=6 action=accept custom_tag=corp_net'
    routed = REGISTRY.route_and_parse(raw)
    assert routed is not None
    pack, extracted, ocsf = routed
    assert pack.vendor == "Fortinet"
    assert ocsf["src_endpoint"]["ip"] == "192.168.1.100"
    assert ocsf["dst_endpoint"]["ip"] == "198.51.100.25"
    assert ocsf["activity_name"] == "accept"
    assert ocsf["time"] == "1696584600123456789"
    # Unmapped passthrough check
    assert "custom_tag" in ocsf["unmapped"]
    assert ocsf["unmapped"]["custom_tag"] == "corp_net"
    # Byte-span lineage
    envelope = LineageEngine.build_envelope(raw, ocsf, pack.pack_id, pack.version, extracted)
    fields = envelope["normalized_data"]["lineage"]["fields"]
    assert "srcip" in fields or "src_endpoint.ip" in fields
    pos = fields.get("src_endpoint.ip", fields.get("srcip"))
    assert raw[pos["start"]:pos["end"]] == "192.168.1.100"


def test_checkpoint_log_exporter_pack():
    raw = 'time=1696584600|hostname=cp-gw01|product=VPN-1 & FireWall-1|cp_severity=High|src=10.0.1.50|spt=43210|dst=198.51.100.77|dpt=80|proto=tcp|action=drop|rule=default_deny'
    routed = REGISTRY.route_and_parse(raw)
    assert routed is not None
    pack, extracted, ocsf = routed
    assert pack.vendor == "Check Point"
    assert ocsf["src_endpoint"]["ip"] == "10.0.1.50"
    assert ocsf["dst_endpoint"]["ip"] == "198.51.100.77"
    assert ocsf["activity_name"] == "drop"
    assert "rule" in ocsf["unmapped"]


def test_juniper_srx_rfc5424_pack():
    raw = '<14>1 2026-10-06T09:30:00.000Z srx-edge01 RT_FLOW - RT_FLOW_SESSION_CREATE: [junos@2636.1.1.1.2.40] 192.168.10.5/51234 -> 203.0.113.80/443'
    routed = REGISTRY.route_and_parse(raw)
    assert routed is not None
    pack, extracted, ocsf = routed
    assert pack.vendor == "Juniper"
    assert ocsf["src_endpoint"]["ip"] == "192.168.10.5"
    assert ocsf["dst_endpoint"]["ip"] == "203.0.113.80"
    assert ocsf["src_endpoint"]["port"] == "51234"
    assert ocsf["dst_endpoint"]["port"] == "443"
    assert ocsf["activity_name"] == "CREATE"


def test_suricata_eve_json_pack():
    raw = '{"timestamp":"2026-10-06T09:30:00.000123+0000","event_type":"alert","src_ip":"192.0.2.15","src_port":41234,"dest_ip":"198.51.100.99","dest_port":80,"proto":"TCP","alert":{"action":"blocked","signature":"ET SCAN Potential SSH Scan"}}'
    routed = REGISTRY.route_and_parse(raw)
    assert routed is not None
    pack, extracted, ocsf = routed
    assert pack.vendor == "OISF"
    assert ocsf["src_endpoint"]["ip"] == "192.0.2.15"
    assert ocsf["dst_endpoint"]["ip"] == "198.51.100.99"
    assert ocsf["class_uid"] == 2001
    assert "alert" in ocsf["unmapped"]


def test_zeek_conn_tsv_pack():
    raw = "1696584600.123456\tC1234567890abcdef\t10.10.1.20\t49152\t198.51.100.12\t443\ttcp\tssl\t1.234\t1500\t4200\tSF"
    routed = REGISTRY.route_and_parse(raw)
    assert routed is not None
    pack, extracted, ocsf = routed
    assert pack.vendor == "Zeek Project"
    assert ocsf["src_endpoint"]["ip"] == "10.10.1.20"
    assert ocsf["dst_endpoint"]["ip"] == "198.51.100.12"
    assert ocsf["src_endpoint"]["port"] == "49152"
    assert ocsf["connection_info"]["protocol_name"] == "tcp"


def test_squid_access_pack():
    raw = "1696584600.456    120 192.168.1.42 TCP_MISS/200 4521 GET http://example.com/test secuser"
    routed = REGISTRY.route_and_parse(raw)
    assert routed is not None
    pack, extracted, ocsf = routed
    assert pack.vendor == "Squid"
    assert ocsf["src_endpoint"]["ip"] == "192.168.1.42"
    assert ocsf["http_request"]["method"] == "GET"
    assert ocsf["http_request"]["url"] == "http://example.com/test"
    assert ocsf["http_response"]["status_code"] == "200"
    assert ocsf["user"]["name"] == "secuser"


def test_pfsense_filterlog_pack():
    raw = "filterlog[12345]: 100,1,,1000000100,em0,match,block,in,4,0x0,,64,12345,0,none,6,tcp,60,192.168.2.10,198.51.100.30,55123,443"
    routed = REGISTRY.route_and_parse(raw)
    assert routed is not None
    pack, extracted, ocsf = routed
    assert pack.vendor == "Netgate"
    assert ocsf["src_endpoint"]["ip"] == "192.168.2.10"
    assert ocsf["dst_endpoint"]["ip"] == "198.51.100.30"
    assert ocsf["activity_name"] == "block"


def test_sonicwall_sonicos_pack():
    raw = 'sn=C0EAE4800001 time="2026-10-06 09:30:00" fw=192.168.1.1 pri=6 c=1024 m=537 msg="Connection Opened" src=10.0.0.15:52000 dst=198.51.100.8:80 proto=tcp/http'
    routed = REGISTRY.route_and_parse(raw)
    assert routed is not None
    pack, extracted, ocsf = routed
    assert pack.vendor == "SonicWall"
    assert ocsf["device"]["name"] == "192.168.1.1"
    assert ocsf["activity_name"] == "Connection Opened"


def test_generic_leef_pack():
    raw = "LEEF:1.0|GenericSecurity|Appliance|2.0|AuthFailure|src=198.51.100.99\tdst=10.0.0.1\tsrcPort=45123\tdstPort=22\tproto=tcp\tdevAction=blocked"
    routed = REGISTRY.route_and_parse(raw)
    assert routed is not None
    pack, extracted, ocsf = routed
    assert pack.vendor == "Generic"
    assert ocsf["src_endpoint"]["ip"] == "198.51.100.99"
    assert ocsf["dst_endpoint"]["ip"] == "10.0.0.1"
    assert ocsf["activity_name"] == "blocked"


def test_hdfs_cluster_file_system_activity_class_1001():
    raw = "081109 203615 148 INFO dfs.DataNode$PacketResponder: PacketResponder 1 for block blk_38865049064139660 terminating"
    routed = REGISTRY.route_and_parse(raw)
    assert routed is not None
    pack, extracted, ocsf = routed
    assert pack.vendor == "Apache"
    assert pack.product == "Hadoop HDFS"
    assert ocsf["class_uid"] == 1001
    assert ocsf["category_name"] == "System Activity"
    assert ocsf["file"]["name"] == "dfs.DataNode$PacketResponder"
    assert ocsf["severity"] == "INFO"


def test_apache_http_application_activity_class_6001():
    raw = "[Sun Dec 04 04:47:44 2005] [notice] workerEnv.init() ok /etc/httpd/conf/workers2.properties"
    routed = REGISTRY.route_and_parse(raw)
    assert routed is not None
    pack, extracted, ocsf = routed
    assert pack.vendor == "Apache"
    assert pack.product == "HTTP Server"
    assert ocsf["class_uid"] == 6001
    assert ocsf["category_name"] == "Application Activity"
    assert ocsf["severity"] == "notice"

