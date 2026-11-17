# Dynamic Firewall with Security Event Logger — D2

An interactive IPv4/TCP echo application in Mininet. Type messages in the client and change firewall rules in the CLI. There is no traffic generator. The controller automatically reacts to repeated new connections and sends security events to a separate TCP logger.

## Files and responsibilities

| File | Responsibility |
|---|---|
| `client.py` | TCP member: typed messages, replies, connection/echo timings, CSV measurements |
| `server.py` | TCP member: one thread per connected client, framed echo, idle timeout |
| `protocol.py` | TCP member: `send_msg` / `rcv_msg`, UTF-8 newline framing and size limit |
| `firewall_controller.py` | SDN member: classification, manual/automatic policies, OpenFlow rules and confirmations |
| `firewall_cli.py` | SDN member: add/remove/list policies and enable/disable automatic protection |
| `event_sender.py` | Logging member: bounded background queue and TCP delivery of JSON events |
| `logger_server.py` | Logging member: acknowledge events and append them to `security.log` |
| `run.sh` | Start logger, OS-Ken and the four-host Mininet topology |

Only this README is an additional project file. Runtime logs and CSV files are generated while using the programs.

## Architecture

All four hosts connect to one Open vSwitch, `s1`. The controller programs `s1` using OpenFlow 1.3. Host programs use ordinary TCP sockets; they do not call OpenFlow themselves.

| Component | Address / role |
|---|---|
| h1 | 10.0.0.1 — manual-block test client |
| h2 | 10.0.0.2 — automatic-block test client |
| h3 | 10.0.0.3 — unaffected comparison client |
| h4 | 10.0.0.4 — echo server, TCP 5000; optionally also 5001 |
| Controller | Main Linux namespace, OpenFlow 127.0.0.1:6653 |
| Firewall CLI → controller | JSON over TCP 127.0.0.1:9999 |
| Controller → logger | JSON over TCP 127.0.0.1:9000 |

Mininet hosts have separate network namespaces and share the filesystem. The logger runs on the main Linux host; h3 is available for testing unaffected traffic.

Unmatched packets go to the controller. It learns MAC addresses, checks IPv4 source/destination/TCP destination port, then drops or forwards the packet. A policy match installs an OpenFlow entry so subsequent matching packets can be handled by the switch.

## Policies and automatic behaviour

- Initial manual policy: BLOCK `10.0.0.1 -> 10.0.0.4:5000`.
- Other IPv4/TCP traffic is allowed unless a manual or temporary automatic block applies.
- CLI rules use source IPv4, destination IPv4 and destination TCP port. ADD replaces an existing rule for that exact tuple. REMOVE removes that manual policy.
- With automatic protection ON, **five distinct connection-opening SYNs from the same source to the same destination service within 30 seconds** trigger a **20-second temporary block**. The fifth connection is blocked.
- `(source port, TCP sequence number)` distinguishes attempts within the window, so retransmitted SYNs do not count again. Echo messages on one connection do not increase the connection count.
- The automatic block applies only to that source/destination/port tuple. Other hosts and services remain usable.
- Automatic entries use cookie `0xf2`, priority 200 and a finite hard timeout. Manual entries use cookie `0xf1`, priority 100. A background check removes expired automatic policy state and logs recovery.
- Manual BLOCK rules remain until removed. Automatic protection can temporarily override an explicit ALLOW rule.
- A manual edit clears the temporary block and attempt history for the edited tuple. Turning automatic protection OFF clears temporary blocks and counts, while retaining manual rules.
- Explicit ALLOW entries additionally match the TCP source port, and expire after 30 seconds idle. New connections therefore reach the controller for monitoring. Default-allowed traffic continues through the learning/PacketOut path.
- Manual rule changes delete matching cached entries, including narrower ALLOW entries. The next matching packet gets the updated policy. On switch reconnection, this app's stale entries are cleared.

These are deliberately low classroom demonstration thresholds, not a production attack detector. The firewall does not inspect message text or decide whether the words are malicious.

## Setup and startup

Requires Linux, Bash, Mininet, Open vSwitch and Python. A Bash shell alone is not sufficient. The tested controller environment is Ubuntu 26.04.1 in VirtualBox, using Python 3.14.4 with OS-Ken 4.2.2 and Eventlet 0.41.3. Socket programs use the Python standard library; `fcntl` provides Linux CSV locking.

From the project directory, create the controller environment once if needed:

```bash
uv venv --python 3.14.4 .venv
uv pip install --python .venv/bin/python os-ken==4.2.2 eventlet==0.41.3
```

On the Ubuntu VirtualBox environment used for this project, start/check Open vSwitch:

```bash
sudo systemctl start ovs-vswitchd.service
sudo ovs-vsctl show
```

Other distributions may use a different service name. Keep the project's existing working Mininet/OVS installation.

Start from a normal terminal:

```bash
cd ~/dynamic-firewall
bash run.sh
```

At the resulting `mininet>` prompt:

```text
h4 python3 -u server.py -H 0.0.0.0 -p 5000 > server.log 2>&1 &
h4 python3 -u server.py -H 0.0.0.0 -p 5001 > server5001.log 2>&1 &
h4 cat server.log server5001.log
```

In another normal terminal:

```bash
cd ~/dynamic-firewall
python3 firewall_cli.py
```

The CLI menu retains 1 Add, 2 Remove, 3 View and 4 Exit. **5** sets automatic protection ON/OFF. Option 3 also displays automatic settings and active temporary blocks.

The server's client idle timeout defaults to 120 seconds. Set another value with server `-t SECONDS`. Client `-t SECONDS` sets its network operation timeout, not the time allowed to type at `Message:`.

## Separate terminals for interactive clients

In Mininet, obtain current host process IDs:

```text
py h1.pid
py h2.pid
py h3.pid
```

In a normal terminal in the project directory, attach to the chosen host. This asks for the actual numeric PID, so no placeholder needs to be pasted into a command:

```bash
read -rp 'Paste the h2 PID shown by Mininet: ' host_pid
sudo mnexec -a "$host_pid" python3 client.py -H 10.0.0.4 -p 5000 --label dynamic
```

Use the corresponding PID in another terminal for h3. Fetch fresh IDs after every Mininet restart. Separate terminals avoid the awkward arrow/backspace input relay seen when running interactive clients directly inside the Mininet CLI.

At `Message:`, type application text or `:q`. Shell and Mininet commands entered there are just message text.

## Manual test checklist for the final version

Stop/restart `run.sh` after replacing the files. Keep one controller/network instance running. After a normal `mininet> exit`, the script stops its controller and logger. For leftover state following a crash, exit other project sessions before running `sudo mn -c`.

1. **Allowed and concurrent clients:** h2 and h3 connect to h4:5000 in separate terminals and exchange typed messages. At Mininet, `h4 ss -tn state established` should show both peers.
2. **Port filtering:** h1:5000 times out; h1:5001 echoes. For a quick test at Mininet use `h1 python3 client.py -H 10.0.0.4 -p 5000 -t 5`, then repeat with port 5001.
3. **Switch enforcement:** after a blocked attempt, run `sh ovs-ofctl -O OpenFlow13 dump-flows s1`. Find priority 100, cookie 0xf1, TCP destination port 5000 and `actions=drop`. The priority-0 table-miss entry remains. Use CLI ADD to replace that tuple with ALLOW, reconnect and echo, then inspect its output action. REMOVE the policy and confirm its entry disappears. Test ADD BLOCK again while an established client is sending messages; its later sends should fail/timeout while h3 still works.
4. **Automatic block/recovery:** use CLI option 5 OFF then ON to clear earlier counts. Leave h2 without a manual BLOCK. From h2, manually start a client, send a short message, enter `:q`, and repeat. Complete five connection attempts within 30 seconds. The first four should work; the fifth should time out. CLI option 3 should show the temporary block. The switch should contain a priority-200 drop with a hard timeout. Keep h3 connected and send messages during the block. Wait about 21 seconds from the trigger, then start a fresh h2 client: it should work. Look for `AUTO_BLOCK`, `FLOW_APPLIED` and `AUTO_RECOVER` in `security.log`.
5. **Static comparison:** CLI option 5 OFF retains only manual policies. Repeat the same h2/h3 test with `--label static`; all five h2 connections should be allowed unless you added a manual rule. Repeat with ON and `--label dynamic`. Use the same topology, payload size, number/timing of attempts and client timeouts. Turning OFF then ON resets the automatic experiment.
6. **Robustness:** invalid CLI addresses/ports/actions must be rejected without stopping the controller. Stop an echo server using its actual PID shown by `h4 ps -o pid,args -C python3`, then try a fresh connection and confirm a recorded error; restart it and reconnect. For logger-outage testing, stop only the actual `logger_server.py` process, check that CLI changes/traffic still work, restart it with `python3 -u logger_server.py > logger.log 2>&1 &` in a normal project terminal, and confirm new events arrive. Stop that manually restarted logger when finished.

Read logs at Mininet with `sh tail -n 15 security.log` or `h4 tail -n 15 server.log`. Exit the client with `:q` first if it occupies the Mininet prompt.

## Measurements and how to report them

Every client appends to `client_metrics.csv`; `--csv PATH` selects a different file. A file lock keeps concurrent Mininet clients' header and rows intact. `--label static` / `--label dynamic` labels experiments; it does not itself change the firewall mode.

| Metric | Source and meaning |
|---|---|
| Connection time | `operation=connect`, `elapsed_ms`: socket connection attempt duration; failed attempts have their own status |
| Application RTT | Successful `operation=echo` rows: elapsed time from sending a framed message to receiving/validating its echo; typing time excluded |
| Success rate | Successful connect rows / all connect rows, multiplied by 100; calculate echo success separately |
| Blocking response | `FLOW_APPLIED` events where `automatic=true` and `action=BLOCK`, field `response_ms`: triggering PacketIn handler entry to the switch BarrierReply |
| Network impact | Compare h3's successful echo mean/max RTT and connect/echo failure counts between static and dynamic runs, while h2 causes the challenge |
| Switch enforcement | `ovs-ofctl dump-flows` packet/byte counters and actions; the initial blocked packet is handled by the controller and is not in the installed entry's counter |
| Recovery | Automatic block/recovery event timestamps, plus the first successful fresh connection after cooldown |

The barrier metric includes controller processing, queuing and OpenFlow round-trip time. It is a switch-processing confirmation bound, not a wire-level measurement of the exact instant the first packet was dropped. OpenFlow errors produce `OPENFLOW_ERROR`/`FLOW_FAILED`; missing confirmation produces `FLOW_CONFIRM_TIMEOUT`. Exclude those cases from successful application-latency averages and report them separately.

A client's five-second timeout is **not** the controller's blocking response time. Do not average connection and echo durations together. Use only h3 rows for the unaffected-host comparison. Keep successful RTTs and timeout/failure counts separate. Runtime CSVs/logs append across runs: use fresh filenames/labels or archive old results before comparing.

Record actual Mininet results after testing; none are invented here:

| Condition | h2 connect successes/attempts | h3 mean/max echo RTT | h3 failures | Auto-block response | Recovery confirmed |
|---|---|---|---|---|---|
| Static, automatic OFF | pending | pending | pending | not applicable | not applicable |
| Dynamic, automatic ON | pending | pending | pending | pending | pending |

## Changes from the checkpoint-2/3 files

- **Controller:** retains the existing configuration socket and learning switch. Adds timed automatic rules, retransmission-aware counts, cleanup, baseline toggle, per-connection ALLOW caching, OpenFlow confirmation timing and error events. Rule deletion now covers narrower cached connection entries. This supersedes the earlier checkpoint-3 controller.
- **Firewall CLI:** keeps existing options, adds option 5, displays automatic state/cooldowns, bounds response size and handles Ctrl-C/EOF.
- **Client:** retains interactive echo and `:q`; adds connect/echo timing, reply validation, experiment labels and locked CSV output. No generated application traffic.
- **Server:** retains threaded echo; makes its idle timeout configurable and changes the default from 30 to 120 seconds for the interactive demo.
- **Protocol:** only fixes two unclear error strings; framing behaviour and function names are unchanged.
- **Event sender:** replaces one worker per event with one worker and a bounded queue of 256 events. Sending remains separate from forwarding.
- **Logger server and run.sh:** unchanged.

## Verification status and limits

The final D2 implementation has been tested in the Ubuntu VirtualBox environment using Mininet, Open vSwitch and OS-Ken.

Verified functionality:

- Controller, firewall CLI and security logger startup.
- TCP client/server communication and message echo.
- Manual firewall rule addition, enforcement and removal.
- Selective blocking of h2 while allowing unaffected traffic from h3.
- Automatic detection of five distinct connection attempts within 30 seconds.
- Temporary 20-second blocking and automatic recovery.
- OpenFlow rule installation and confirmation.
- Port-specific filtering: blocking TCP port 5000 does not prevent access to TCP port 5001.
- Python syntax, Bash syntax and OS-Ken import checks.

Recorded measurements from the functional test session:

- TCP connection attempts: 16 successful out of 19 (84.21%).
- Average successful connection time: 25.56 ms.
- Maximum successful connection time: 127.797 ms.
- Average successful application echo RTT: 12.33 ms.
- Maximum successful application echo RTT: 39.663 ms.
- Automatic flow application response: 33.77 ms.
- Observed automatic block duration: approximately 20.214 seconds.

A controlled static-versus-dynamic performance comparison has not yet been completed. The recorded client measurements include deliberate firewall blocks, timeouts and other functional tests; they should not be interpreted as a controlled benchmark.

This is a single-switch IPv4/TCP classroom firewall, not a general security product. Non-TCP traffic follows the original learning-switch path. Fragmented TCP is unsupported. Policies are kept in memory and reset on controller restart. Cached output ports assume fixed host attachment. The threshold detects repeated connections, not malicious content; normal rapid reconnects can trigger it. Logging is best effort: failed deliveries and full-queue drops are reported in controller.log but are not durably retried. App/network timeouts remain possible during an active block; reconnect after recovery.

Code/configuration references: [OS-Ken OpenFlow 1.3](https://docs.openstack.org/os-ken/latest/ofproto_v1_3_ref.html), [Mininet walkthrough](https://mininet.org/walkthrough/), and the supplied Project 1 spreadsheet and D2 rubric.
