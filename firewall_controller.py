import json
import ipaddress
import time
import math

from os_ken.base import app_manager
from os_ken.controller import ofp_event
from os_ken.controller.handler import (
    CONFIG_DISPATCHER,
    MAIN_DISPATCHER,
    DEAD_DISPATCHER,
    set_ev_cls
)
from os_ken.ofproto import ofproto_v1_3
from os_ken.lib.packet import packet, ethernet, ipv4, tcp
from os_ken.lib import hub
from event_sender import EventSender


# TCP protocol number
TCP_PROTOCOL = 6
FIREWALL_PRIORITY = 100
FIREWALL_COOKIE = 0xF1
AUTO_COOKIE = 0xF2
AUTO_PRIORITY = 200
# Deliberately small classroom values: type five separate connections by hand.
ATTEMPT_LIMIT = 5
ATTEMPT_WINDOW = 30
BLOCK_SECONDS = 20


class FirewallController(app_manager.OSKenApp):

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(FirewallController, self).__init__(*args, **kwargs)

        # D1 integration: logging runs in a separate background worker.
        self.event_sender = EventSender(self.logger)

        # MAC address learning table
        self.mac_to_port = {}
        self.datapaths = {}
        self.auto_enabled = True
        self.attempts = {}      # service tuple -> {(source port, SYN sequence): time}
        self.auto_blocks = {}   # service tuple -> monotonic expiry time
        self.pending_flows = {} # (switch object, barrier xid) -> confirmation data

        # Default TCP firewall rule
        self.firewall_rules = [
            {
                "src": "10.0.0.1",
                "dst": "10.0.0.4",
                "dst_port": 5000,
                "protocol": "TCP",
                "action": "BLOCK"
            }
        ]

        self.event_sender.publish("CONTROLLER_STARTED",
            reason="TCP firewall; default block h1 to h4 port 5000",
            automatic=True, limit=ATTEMPT_LIMIT, window_seconds=ATTEMPT_WINDOW,
            block_seconds=BLOCK_SECONDS)

        # TCP configuration server
        self.rule_server = hub.listen(("127.0.0.1", 9999))
        hub.spawn(self.rule_server_loop)
        hub.spawn(self.maintenance_loop)

        self.logger.info("TCP Firewall Controller started")
        self.logger.info("Configuration server listening on port 9999")
        self.logger.info(
            "Default rule: BLOCK TCP 10.0.0.1 -> 10.0.0.4:5000"
        )

    # ==========================================
    # FIREWALL CONFIGURATION SERVER
    # ==========================================

    def rule_server_loop(self):

        while True:
            try:
                conn, address = self.rule_server.accept()
                hub.spawn(self.handle_rule_client, conn)

            except Exception as e:
                self.logger.error("Rule server error: %s", str(e))

    def handle_rule_client(self, conn):

        try:
            conn.settimeout(3)
            data = b""

            while b"\n" not in data:
                chunk = conn.recv(4096)

                if not chunk:
                    return

                data += chunk
                if len(data) > 8192:
                    raise ValueError("Configuration request too large")

            request = json.loads(
                data.split(b"\n", 1)[0].decode()
            )

            if not isinstance(request, dict):
                raise ValueError("Request must be a JSON object")

            command = request.get("command")

            src = request.get("src")
            dst = request.get("dst")
            dst_port = request.get("dst_port")
            protocol = request.get("protocol")
            action = request.get("action")

            if command in ("ADD", "REMOVE"):
                src = str(ipaddress.IPv4Address(src))
                dst = str(ipaddress.IPv4Address(dst))
                if protocol != "TCP":
                    raise ValueError("Only TCP rules are supported")
                if type(dst_port) is not int or not 1 <= dst_port <= 65535:
                    raise ValueError("Destination TCP port must be an integer from 1 to 65535")

            # ADD TCP RULE
            if command == "ADD":

                if protocol != "TCP":
                    response = {
                        "status": "error",
                        "message": "Only TCP rules are supported"
                    }

                elif action not in ["BLOCK", "ALLOW"]:
                    response = {
                        "status": "error",
                        "message": "Action must be BLOCK or ALLOW"
                    }

                else:
                    new_rule = {
                        "src": src,
                        "dst": dst,
                        "dst_port": dst_port,
                        "protocol": "TCP",
                        "action": action
                    }

                    # Replace an existing matching rule
                    self.firewall_rules = [
                        r for r in self.firewall_rules
                        if not (
                            r["src"] == src
                            and r["dst"] == dst
                            and r["dst_port"] == dst_port
                            and r["protocol"] == "TCP"
                        )
                    ]

                    self.firewall_rules.append(new_rule)
                    # A manual edit also resets the automatic block for this service.
                    self.clear_auto_block((src, dst, dst_port), "Manual rule change")
                    # Invalidate the old switch entries; the next packet uses this policy.
                    for datapath in list(self.datapaths.values()):
                        self.delete_firewall_flow(datapath, new_rule)
                    self.event_sender.publish("RULE_ADDED", src=src, dst=dst,
                                        dst_port=dst_port, action=action, reason="Manual CLI change")

                    response = {
                        "status": "success",
                        "message": "TCP rule added"
                    }

                    self.logger.info(
                        "Added firewall rule: %s", new_rule
                    )

            # REMOVE TCP RULE
            elif command == "REMOVE":

                old_count = len(self.firewall_rules)

                self.firewall_rules = [
                    r for r in self.firewall_rules
                    if not (
                        r["src"] == src
                        and r["dst"] == dst
                        and r["dst_port"] == dst_port
                        and r["protocol"] == "TCP"
                    )
                ]

                if len(self.firewall_rules) < old_count:
                    self.clear_auto_block((src, dst, dst_port), "Manual rule removal")
                    removed_rule = {"src": src, "dst": dst, "dst_port": dst_port}
                    for datapath in list(self.datapaths.values()):
                        self.delete_firewall_flow(datapath, removed_rule)
                    self.event_sender.publish("RULE_REMOVED", src=src, dst=dst,
                                        dst_port=dst_port, reason="Manual CLI change")
                    response = {
                        "status": "success",
                        "message": "TCP rule removed"
                    }
                else:
                    response = {
                        "status": "error",
                        "message": "Rule not found"
                    }

                self.logger.info(
                    "Remove rule request: %s -> %s:%s",
                    src, dst, dst_port
                )

            # VIEW RULES
            elif command == "LIST":

                response = {
                    "status": "success",
                    "rules": self.firewall_rules,
                    "automatic": self.auto_enabled,
                    "limit": ATTEMPT_LIMIT,
                    "window_seconds": ATTEMPT_WINDOW,
                    "block_seconds": BLOCK_SECONDS,
                    "auto_blocks": [dict(self.service_rule(key),
                                         remaining_seconds=max(0, math.ceil(until - time.monotonic())))
                                    for key, until in self.auto_blocks.items()]
                }

            elif command == "AUTO":
                enabled = request.get("enabled")
                if type(enabled) is not bool:
                    raise ValueError("enabled must be true or false")
                self.auto_enabled = enabled
                self.attempts.clear()
                if not enabled:
                    for key in list(self.auto_blocks):
                        self.clear_auto_block(key, "Automatic protection disabled")
                self.event_sender.publish("AUTO_MODE", enabled=enabled)
                response = {"status": "success", "automatic": enabled}

            else:

                response = {
                    "status": "error",
                    "message": "Unknown command"
                }

            conn.sendall(
                (json.dumps(response) + "\n").encode()
            )

        except Exception as e:

            self.logger.error(
                "Configuration error: %s", str(e)
            )

            try:
                conn.sendall(
                    (json.dumps({
                        "status": "error",
                        "message": str(e)
                    }) + "\n").encode()
                )
            except Exception:
                pass

        finally:
            conn.close()

    # ==========================================
    # OPENFLOW SWITCH CONNECTION
    # ==========================================

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            self.datapaths[datapath.id] = datapath
        elif self.datapaths.get(datapath.id) is datapath:
            del self.datapaths[datapath.id]
            self.mac_to_port.pop(datapath.id, None)

    @set_ev_cls(
        ofp_event.EventOFPSwitchFeatures,
        CONFIG_DISPATCHER
    )
    def switch_features_handler(self, ev):

        datapath = ev.msg.datapath
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        # A reconnected switch may still hold entries from an earlier session.
        self.mac_to_port[datapath.id] = {}
        self.delete_firewall_flow(datapath)
        self.delete_firewall_flow(datapath, automatic=True)

        # Send unmatched packets to the controller
        match = parser.OFPMatch()

        actions = [
            parser.OFPActionOutput(
                ofproto.OFPP_CONTROLLER,
                ofproto.OFPCML_NO_BUFFER
            )
        ]

        self.add_flow(
            datapath,
            0,
            match,
            actions
        )

        self.logger.info(
            "Switch connected: %s", datapath.id
        )

    def add_flow(self, datapath, priority, match, actions, cookie=0,
                 hard_timeout=0, idle_timeout=0):

        parser = datapath.ofproto_parser

        instructions = [
            parser.OFPInstructionActions(
                datapath.ofproto.OFPIT_APPLY_ACTIONS,
                actions
            )
        ]

        flow_mod = parser.OFPFlowMod(
            datapath=datapath,
            cookie=cookie,
            priority=priority,
            hard_timeout=hard_timeout,
            idle_timeout=idle_timeout,
            match=match,
            instructions=instructions
        )

        datapath.send_msg(flow_mod)
        return flow_mod

    def firewall_match(self, datapath, rule, src_port=None):
        fields = dict(
            eth_type=0x0800,
            ip_proto=TCP_PROTOCOL,
            ipv4_src=rule["src"],
            ipv4_dst=rule["dst"],
            tcp_dst=rule["dst_port"]
        )
        if src_port is not None:
            fields["tcp_src"] = src_port
        return datapath.ofproto_parser.OFPMatch(**fields)

    def install_firewall_flow(self, datapath, rule, actions, started,
                              src_port=None, automatic=False, hard_timeout=0):
        # ALLOW caches one connection, so each NEW connection is still monitored.
        # BLOCK covers every source port for the selected destination service.
        flow = self.add_flow(
            datapath, AUTO_PRIORITY if automatic else FIREWALL_PRIORITY,
            self.firewall_match(datapath, rule, src_port), actions,
            cookie=AUTO_COOKIE if automatic else FIREWALL_COOKIE,
            hard_timeout=hard_timeout, idle_timeout=30 if actions else 0)
        fields = dict(src=rule["src"], dst=rule["dst"], dst_port=rule["dst_port"],
                      action=rule["action"], automatic=automatic, switch_id=datapath.id)
        self.event_sender.publish("FLOW_RULE_SENT", **fields)
        # Barrier confirms that preceding OpenFlow operations were processed.
        barrier = datapath.ofproto_parser.OFPBarrierRequest(datapath)
        datapath.set_xid(barrier)
        self.pending_flows[(datapath, barrier.xid)] = {
            "started": started, "flow_xid": flow.xid, "fields": fields, "failed": False}
        datapath.send_msg(barrier)

    def delete_firewall_flow(self, datapath, rule=None, automatic=False):
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        match = self.firewall_match(datapath, rule) if rule else parser.OFPMatch()
        # Non-strict deletion also removes narrower per-connection ALLOW entries.
        # The cookie restricts deletion to our own manual or automatic entries.
        datapath.send_msg(parser.OFPFlowMod(
            datapath=datapath,
            cookie=AUTO_COOKIE if automatic else FIREWALL_COOKIE,
            cookie_mask=0xFFFFFFFFFFFFFFFF,
            table_id=0,
            command=ofproto.OFPFC_DELETE,
            out_port=ofproto.OFPP_ANY,
            out_group=ofproto.OFPG_ANY,
            match=match
        ))

    @set_ev_cls(ofp_event.EventOFPBarrierReply, MAIN_DISPATCHER)
    def barrier_reply_handler(self, ev):
        item = self.pending_flows.pop((ev.msg.datapath, ev.msg.xid), None)
        if item is not None:
            event = "FLOW_FAILED" if item["failed"] else "FLOW_APPLIED"
            self.event_sender.publish(event, **item["fields"],
                response_ms=round((time.monotonic() - item["started"]) * 1000, 3))

    @set_ev_cls(ofp_event.EventOFPErrorMsg, [CONFIG_DISPATCHER, MAIN_DISPATCHER])
    def flow_error_handler(self, ev):
        msg = ev.msg
        for (datapath, _), item in self.pending_flows.items():
            if datapath is msg.datapath and item["flow_xid"] == msg.xid:
                item["failed"] = True
        self.logger.error("OpenFlow error: type=%s code=%s", msg.type, msg.code)
        self.event_sender.publish("OPENFLOW_ERROR", switch_id=msg.datapath.id,
                                  error_type=msg.type, code=msg.code, xid=msg.xid)

    # ==========================================
    # AUTOMATIC BLOCKING AND RECOVERY
    # ==========================================

    @staticmethod
    def service_rule(key):
        return dict(src=key[0], dst=key[1], dst_port=key[2],
                    protocol="TCP", action="BLOCK")

    def clear_auto_block(self, key, reason):
        self.attempts.pop(key, None)
        if self.auto_blocks.pop(key, None) is not None:
            for datapath in list(self.datapaths.values()):
                self.delete_firewall_flow(datapath, self.service_rule(key), automatic=True)
            self.event_sender.publish("AUTO_RECOVER",
                **dict(self.service_rule(key), action="REMOVE"), reason=reason)

    def check_attempt(self, key, tcp_pkt, now):
        attempts = self.attempts.setdefault(key, {})
        for identity, when in list(attempts.items()):
            if now - when >= ATTEMPT_WINDOW:
                del attempts[identity]
        # A retransmitted SYN has the same port and sequence number.
        identity = (tcp_pkt.src_port, tcp_pkt.seq)
        if identity in attempts:
            return False
        attempts[identity] = now
        if len(attempts) < ATTEMPT_LIMIT:
            return False
        self.auto_blocks[key] = now + BLOCK_SECONDS
        self.attempts.pop(key, None)
        # Remove older cached ALLOW flows before applying the higher-priority block.
        for datapath in list(self.datapaths.values()):
            self.delete_firewall_flow(datapath, self.service_rule(key))
        self.event_sender.publish("AUTO_BLOCK", **self.service_rule(key),
            attempts=ATTEMPT_LIMIT, window_seconds=ATTEMPT_WINDOW,
            duration_seconds=BLOCK_SECONDS, reason="New connection threshold reached")
        return True

    def maintain(self, now):
        for key, until in list(self.auto_blocks.items()):
            if now >= until:
                self.clear_auto_block(key, "Cooldown expired")
        for key, attempts in list(self.attempts.items()):
            recent = {identity: when for identity, when in attempts.items()
                      if now - when < ATTEMPT_WINDOW}
            if recent:
                self.attempts[key] = recent
            else:
                del self.attempts[key]
        for key, item in list(self.pending_flows.items()):
            if now - item["started"] >= 3:
                del self.pending_flows[key]
                self.event_sender.publish("FLOW_CONFIRM_TIMEOUT", **item["fields"])

    def maintenance_loop(self):
        while True:
            self.maintain(time.monotonic())
            hub.sleep(0.5)

    # ==========================================
    # PACKET HANDLING AND TCP FIREWALL
    # ==========================================

    @set_ev_cls(
        ofp_event.EventOFPPacketIn,
        MAIN_DISPATCHER
    )
    def packet_in_handler(self, ev):

        started = time.monotonic()
        msg = ev.msg
        datapath = msg.datapath

        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        in_port = msg.match["in_port"]

        pkt = packet.Packet(msg.data)

        eth_pkt = pkt.get_protocol(
            ethernet.ethernet
        )

        if eth_pkt is None:
            return

        src_mac = eth_pkt.src
        dst_mac = eth_pkt.dst

        dpid = datapath.id

        if dpid not in self.mac_to_port:
            self.mac_to_port[dpid] = {}

        # Learn source MAC address
        self.mac_to_port[dpid][src_mac] = in_port

        # --------------------------------------
        # CHECK TCP FIREWALL RULES
        # --------------------------------------

        matched_rule = None
        tcp_pkt = None
        ip_pkt = pkt.get_protocol(ipv4.ipv4)

        if ip_pkt and ip_pkt.proto == TCP_PROTOCOL:
            tcp_pkt = pkt.get_protocol(tcp.tcp)
            # Fragmented TCP cannot be safely classified by port in this simple firewall.
            if tcp_pkt is None or ip_pkt.offset or (ip_pkt.flags & 1):
                return
            key = (ip_pkt.src, ip_pkt.dst, tcp_pkt.dst_port)
            if key in self.auto_blocks and started >= self.auto_blocks[key]:
                self.clear_auto_block(key, "Cooldown expired")
            matched_rule = next((rule for rule in self.firewall_rules
                                 if (rule["src"], rule["dst"], rule["dst_port"]) == key), None)
            manual_block = matched_rule is not None and matched_rule["action"] == "BLOCK"
            syn = bool(tcp_pkt.bits & 0x02) and not bool(tcp_pkt.bits & 0x10)
            if (self.auto_enabled and syn and not manual_block
                    and key not in self.auto_blocks):
                self.check_attempt(key, tcp_pkt, started)
            automatic = key in self.auto_blocks
            action = "BLOCK" if manual_block or automatic else "ALLOW"
            if syn:
                self.event_sender.publish("TCP_SYN", src=key[0], dst=key[1],
                    src_port=tcp_pkt.src_port, dst_port=key[2], action=action,
                    reason="Automatic cooldown" if automatic else
                           "Configured rule" if manual_block else "Explicit or default allow")
            if action == "BLOCK":
                rule = self.service_rule(key)
                remaining = max(1, math.ceil(self.auto_blocks[key] - started)) if automatic else 0
                self.install_firewall_flow(datapath, rule, [], started,
                                          automatic=automatic, hard_timeout=remaining)
                return

        # --------------------------------------
        # LEARNING SWITCH FORWARDING
        # --------------------------------------

        if dst_mac in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst_mac]

        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [
            parser.OFPActionOutput(out_port)
        ]

        # Cache explicit ALLOW rules only after learning the destination's port.
        if matched_rule is not None and out_port != ofproto.OFPP_FLOOD:
            self.install_firewall_flow(datapath, matched_rule, actions, started,
                                       src_port=tcp_pkt.src_port)

        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=ofproto.OFP_NO_BUFFER,
            in_port=in_port,
            actions=actions,
            data=msg.data
        )

        datapath.send_msg(out)
