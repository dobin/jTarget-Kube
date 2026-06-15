#!/usr/bin/env python3
"""
iTarget Cube Controller

Re-implementation of the iTarget Pro Android app protocol in Python.
Discovers cubes on the local network and runs training games.

Based on reverse engineering of iTarget Pro v1.5.1 Android app.
See PROTOCOL.md for detailed protocol documentation.
"""

import socket
import time
import threading
import logging
import argparse
import sys
import select
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Callable
from enum import IntEnum
import random

# Protocol constants
UDP_CUBE_PORT = 7042      # Cube listens on this port
UDP_LISTEN_PORT = 4587    # App listens for cube responses
TCP_PORT = 4586           # App runs TCP server, cubes connect

HEARTBEAT_TIMEOUT = 20    # Seconds before cube is considered disconnected
DISCOVERY_SLEEP = 0.005   # Sleep between discovery packets (5ms)
ALREADY_COUNT = 5         # Number of ALREADY packets to send
ALREADY_INTERVAL = 0.1    # Sleep between ALREADY sends (100ms)

# Game constants
DEFAULT_COUNTDOWN = 3
DEFAULT_TIMEOUT = 10
DEFAULT_START_DELAY = 1


class GameType(IntEnum):
    """Game types from Android app"""
    SEQUENTIAL = 0    # Sequential Drill
    RANDOM = 1        # Random Drill
    CLEARING = 2      # Clearing Drill (all at once)
    LOOP = 3          # Random Loop (continuous)


class CubeStatus(IntEnum):
    """Cube status values"""
    READY = 0         # Ready / Not yet played
    FLASHING = 1      # Active / Flashing (waiting for hit)
    HIT = 2           # Hit / Completed
    FAILED = 3        # Disconnected / Timed out


@dataclass
class Cube:
    """Represents an iTarget cube"""
    id: str
    ip: str
    connected: bool = False
    battery: int = 0
    status: CubeStatus = CubeStatus.READY
    last_heartbeat: Optional[datetime] = None
    begin_time: Optional[datetime] = None
    reaction_time: float = 0.0
    tcp_socket: Optional[socket.socket] = None

    def is_connected(self) -> bool:
        """Check if cube is connected (has recent heartbeat)"""
        if not self.connected or self.last_heartbeat is None:
            return False
        age = datetime.now() - self.last_heartbeat
        return age.total_seconds() < HEARTBEAT_TIMEOUT

    def update_heartbeat(self, battery: int):
        """Update heartbeat timestamp and battery"""
        self.last_heartbeat = datetime.now()
        self.battery = battery
        self.connected = True


class ProtocolMessage:
    """Helper for building and parsing protocol messages"""
    
    @staticmethod
    def build(**kwargs) -> str:
        """Build a protocol message: KEY=VALUE,KEY=VALUE,"""
        return ",".join(f"{k}={v}" for k, v in kwargs.items()) + ","
    
    @staticmethod
    def parse(data: bytes) -> Dict[str, str]:
        """Parse a protocol message"""
        try:
            text = data.decode("utf-8").strip().rstrip("\r\n")
            result = {}
            for token in text.split(","):
                if "=" in token:
                    key, value = token.split("=", 1)
                    result[key.strip()] = value.strip().strip('"')
            return result
        except Exception as e:
            logging.error(f"Failed to parse message: {data!r} - {e}")
            return {}


class ITargetController:
    """Main controller for iTarget cubes"""
    
    def __init__(self, debug: bool = False):
        self.debug = debug
        self.local_ip = self._get_local_ip()
        self.subnet = ".".join(self.local_ip.split(".")[:3])
        
        self.cubes: Dict[str, Cube] = {}  # ID -> Cube
        self.tcp_clients: Dict[str, socket.socket] = {}  # IP -> socket
        
        self.udp_socket: Optional[socket.socket] = None
        self.tcp_server: Optional[socket.socket] = None
        
        self.running = False
        self.udp_thread: Optional[threading.Thread] = None
        self.tcp_thread: Optional[threading.Thread] = None
        self.game_thread: Optional[threading.Thread] = None
        
        # Setup logging
        level = logging.DEBUG if debug else logging.INFO
        logging.basicConfig(
            level=level,
            format='%(asctime)s [%(levelname)s] %(message)s',
            datefmt='%H:%M:%S'
        )
        self.logger = logging.getLogger(__name__)
    
    def _get_local_ip(self) -> str:
        """Get local IP address"""
        try:
            # Connect to external host to determine local IP
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "192.168.1.100"  # Fallback
    
    def _log_packet(self, direction: str, dest: str, message: str, protocol: str = "UDP"):
        """Log packet details if debug is enabled"""
        if self.debug:
            self.logger.debug(f"{protocol} {direction} {dest}: {message}")
    
    def start(self):
        """Start UDP listener and TCP server"""
        self.running = True
        
        # Start UDP listener on port 4587
        self.udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.udp_socket.bind(("0.0.0.0", UDP_LISTEN_PORT))
        self.logger.info(f"UDP listener started on port {UDP_LISTEN_PORT}")
        
        # Start UDP listener thread
        self.udp_thread = threading.Thread(target=self._udp_listener, daemon=True)
        self.udp_thread.start()
        
        # Start TCP server on port 4586
        self.tcp_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.tcp_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.tcp_server.bind(("0.0.0.0", TCP_PORT))
        self.tcp_server.listen(10)
        self.logger.info(f"TCP server started on port {TCP_PORT}")
        
        # Start TCP server thread
        self.tcp_thread = threading.Thread(target=self._tcp_server, daemon=True)
        self.tcp_thread.start()
    
    def stop(self):
        """Stop all threads and close sockets"""
        self.logger.info("Stopping controller...")
        self.running = False
        
        # Close all TCP client connections
        for sock in self.tcp_clients.values():
            try:
                sock.close()
            except:
                pass
        
        # Close UDP socket
        if self.udp_socket:
            try:
                self.udp_socket.close()
            except:
                pass
        
        # Close TCP server
        if self.tcp_server:
            try:
                self.tcp_server.close()
            except:
                pass
        
        # Wait for threads
        if self.udp_thread and self.udp_thread.is_alive():
            self.udp_thread.join(timeout=1)
        if self.tcp_thread and self.tcp_thread.is_alive():
            self.tcp_thread.join(timeout=1)
    
    def _send_udp(self, ip: str, port: int, message: str):
        """Send UDP message to specific IP"""
        self._log_packet("→", f"{ip}:{port}", message, "UDP")
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.sendto(message.encode(), (ip, port))
            sock.close()
        except Exception as e:
            self.logger.error(f"Failed to send UDP to {ip}:{port} - {e}")
    
    def _send_tcp(self, ip: str, message: str):
        """Send TCP message to specific cube"""
        self._log_packet("→", f"{ip}:{TCP_PORT}", message, "TCP")
        sock = self.tcp_clients.get(ip)
        if sock:
            try:
                sock.send(message.encode())
                time.sleep(0.1)  # Match Android app's post-send sleep
            except Exception as e:
                self.logger.error(f"Failed to send TCP to {ip} - {e}")
                # Remove failed socket
                self.tcp_clients.pop(ip, None)
        else:
            self.logger.warning(f"No TCP connection to {ip}")
    
    def _send_tcp_all(self, message: str):
        """Send TCP message to all connected cubes"""
        for ip in list(self.tcp_clients.keys()):
            self._send_tcp(ip, message)
    
    def _udp_listener(self):
        """UDP listener thread - receives IPGET, POWER, FINDWIFI"""
        self.logger.debug("UDP listener thread started")
        
        while self.running:
            try:
                # Use select for timeout so we can check self.running
                ready = select.select([self.udp_socket], [], [], 1.0)
                if not ready[0]:
                    continue
                
                data, addr = self.udp_socket.recvfrom(1024)
                ip = addr[0]
                
                msg = ProtocolMessage.parse(data)
                self._log_packet("←", f"{ip}:{addr[1]}", str(msg), "UDP")
                
                msg_type = msg.get("TYPE")
                
                if msg_type == "IPGET":
                    # Cube discovery response
                    cube_id = msg.get("ID")
                    if cube_id and cube_id.startswith("iTarget"):
                        self._handle_ipget(ip, cube_id)
                
                elif msg_type == "POWER":
                    # UDP heartbeat during discovery
                    cube_id = msg.get("ID")
                    battery = msg.get("VALUE", "0")
                    if cube_id and cube_id in self.cubes:
                        try:
                            self.cubes[cube_id].update_heartbeat(int(battery))
                        except ValueError:
                            pass
                
                elif msg_type == "FINDWIFI":
                    # Cube looking for WiFi config (not implemented)
                    self.logger.info(f"Cube at {ip} looking for WiFi config")
            
            except Exception as e:
                if self.running:
                    self.logger.error(f"UDP listener error: {e}")
        
        self.logger.debug("UDP listener thread stopped")
    
    def _tcp_server(self):
        """TCP server thread - accepts cube connections"""
        self.logger.debug("TCP server thread started")
        
        while self.running:
            try:
                # Use select for timeout
                ready = select.select([self.tcp_server], [], [], 1.0)
                if not ready[0]:
                    continue
                
                client_sock, client_addr = self.tcp_server.accept()
                ip = client_addr[0]
                
                self.logger.info(f"TCP connection from {ip}")
                self.tcp_clients[ip] = client_sock
                
                # Start client handler thread
                thread = threading.Thread(
                    target=self._tcp_client_handler,
                    args=(client_sock, ip),
                    daemon=True
                )
                thread.start()
            
            except Exception as e:
                if self.running:
                    self.logger.error(f"TCP server error: {e}")
        
        self.logger.debug("TCP server thread stopped")
    
    def _tcp_client_handler(self, sock: socket.socket, ip: str):
        """Handle TCP messages from a cube"""
        self.logger.debug(f"TCP handler started for {ip}")
        
        buffer = b""
        
        while self.running:
            try:
                # Read with timeout
                sock.settimeout(1.0)
                data = sock.recv(4096)
                
                if not data:
                    # Connection closed
                    break
                
                buffer += data
                
                # Try to parse messages from buffer
                # Messages may arrive concatenated or split across reads
                while b"," in buffer:
                    # Find a complete message (ends with comma)
                    text = buffer.decode("utf-8", errors="ignore")
                    
                    # Simple heuristic: look for TYPE= to start of message
                    if "TYPE=" in text:
                        # Extract first complete message
                        parts = text.split(",")
                        # Find how many parts make a complete message
                        msg_parts = []
                        for part in parts:
                            msg_parts.append(part)
                            if "=" in part:
                                # This looks like a field, keep going
                                continue
                            else:
                                # Empty part after comma = end of message
                                break
                        
                        msg_text = ",".join(msg_parts)
                        if msg_text.endswith(","):
                            msg_text = msg_text[:-1]
                        
                        # Parse it
                        msg = ProtocolMessage.parse((msg_text + ",").encode())
                        if msg:
                            self._log_packet("←", f"{ip}:{TCP_PORT}", str(msg), "TCP")
                            self._handle_tcp_message(ip, msg)
                        
                        # Remove processed message from buffer
                        consumed = len(msg_text.encode()) + 1
                        buffer = buffer[consumed:]
                    else:
                        # No TYPE= found, might be incomplete
                        break
            
            except socket.timeout:
                continue
            except Exception as e:
                if self.running:
                    self.logger.error(f"TCP handler error for {ip}: {e}")
                break
        
        # Clean up
        self.tcp_clients.pop(ip, None)
        try:
            sock.close()
        except:
            pass
        
        self.logger.debug(f"TCP handler stopped for {ip}")
    
    def _handle_ipget(self, ip: str, cube_id: str):
        """Handle IPGET response from cube"""
        self.logger.info(f"Discovered cube: {cube_id} at {ip}")
        
        # Create or update cube
        if cube_id not in self.cubes:
            self.cubes[cube_id] = Cube(id=cube_id, ip=ip)
        else:
            self.cubes[cube_id].ip = ip
        
        # Send targeted INVITATION (with quoted IP)
        msg = ProtocolMessage.build(TYPE="INVITATION", IP=f'"{self.local_ip}"')
        self._send_udp(ip, UDP_CUBE_PORT, msg)
        
        time.sleep(0.5)
        
        # Send ALREADY to trigger TCP connection
        msg = ProtocolMessage.build(TYPE="ALREADY")
        for _ in range(ALREADY_COUNT):
            self._send_udp(ip, UDP_CUBE_PORT, msg)
            time.sleep(ALREADY_INTERVAL)
    
    def _handle_tcp_message(self, ip: str, msg: Dict[str, str]):
        """Handle TCP message from cube"""
        msg_type = msg.get("TYPE")
        
        if msg_type == "POWER":
            # Heartbeat
            cube_id = msg.get("ID")
            battery = msg.get("VALUE", "0")
            
            if cube_id:
                if cube_id in self.cubes:
                    try:
                        self.cubes[cube_id].update_heartbeat(int(battery))
                        self.cubes[cube_id].ip = ip
                        self.logger.debug(f"Heartbeat from {cube_id}: {battery}% battery")
                    except ValueError:
                        pass
        
        elif msg_type == "HIT":
            # Cube was hit!
            cube_id = msg.get("ID")
            battery = msg.get("VALUE", "0")
            reaction_ms = msg.get("MIS", "0")
            
            if cube_id and cube_id in self.cubes:
                cube = self.cubes[cube_id]
                try:
                    cube.update_heartbeat(int(battery))
                    cube.reaction_time = float(reaction_ms) / 1000.0
                    cube.status = CubeStatus.HIT
                    
                    self.logger.info(f"HIT! {cube_id} - {cube.reaction_time:.3f}s")
                    
                    # Send SUCCESS acknowledgment
                    success_msg = ProtocolMessage.build(TYPE="SUCCESS")
                    self._send_tcp(ip, success_msg)
                
                except ValueError:
                    pass
    
    def discover_cubes(self, timeout: float = 5.0) -> List[Cube]:
        """
        Discover cubes on the network.
        Returns list of discovered cubes.
        """
        self.logger.info(f"Discovering cubes on {self.subnet}.0/24...")
        
        # Clear previous discoveries
        self.cubes.clear()
        
        # Broadcast INVITATION to all IPs in subnet
        skip_ips = {self.local_ip}
        
        msg = ProtocolMessage.build(
            DEVICE="CUBE",
            TYPE="INVITATION",
            IP=self.local_ip
        )
        
        for i in range(2, 255):
            ip = f"{self.subnet}.{i}"
            if ip in skip_ips:
                continue
            
            self._send_udp(ip, UDP_CUBE_PORT, msg)
            time.sleep(DISCOVERY_SLEEP)
        
        # Wait for responses
        self.logger.info(f"Waiting {timeout}s for responses...")
        time.sleep(timeout)
        
        # Return list of discovered cubes
        discovered = list(self.cubes.values())
        self.logger.info(f"Found {len(discovered)} cube(s)")
        
        for cube in discovered:
            status = "connected" if cube.is_connected() else "discovered"
            self.logger.info(f"  - {cube.id} at {cube.ip} [{status}]")
        
        return discovered
    
    def wait_for_connections(self, timeout: float = 10.0) -> int:
        """
        Wait for cubes to establish TCP connections.
        Returns number of connected cubes.
        """
        self.logger.info(f"Waiting up to {timeout}s for TCP connections...")
        
        start = time.time()
        while time.time() - start < timeout:
            connected = sum(1 for c in self.cubes.values() if c.is_connected())
            if connected == len(self.cubes) and connected > 0:
                break
            time.sleep(0.5)
        
        connected = sum(1 for c in self.cubes.values() if c.is_connected())
        self.logger.info(f"{connected}/{len(self.cubes)} cube(s) connected via TCP")
        
        return connected
    
    def start_game(self, game_type: GameType, countdown: int = DEFAULT_COUNTDOWN,
                   timeout: int = DEFAULT_TIMEOUT, start_delay: int = DEFAULT_START_DELAY):
        """Start a game with the specified type"""
        
        if not self.cubes:
            self.logger.error("No cubes discovered!")
            return
        
        connected_cubes = [c for c in self.cubes.values() if c.is_connected()]
        if not connected_cubes:
            self.logger.error("No cubes connected!")
            return
        
        game_names = {
            GameType.SEQUENTIAL: "Sequential Drill",
            GameType.RANDOM: "Random Drill",
            GameType.CLEARING: "Clearing Drill",
            GameType.LOOP: "Random Loop"
        }
        
        self.logger.info(f"Starting game: {game_names[game_type]}")
        self.logger.info(f"Cubes: {len(connected_cubes)}, Timeout: {timeout}s, Delay: {start_delay}s")
        
        # Reset all cubes
        for cube in connected_cubes:
            cube.status = CubeStatus.READY
            cube.reaction_time = 0.0
            cube.begin_time = None
        
        # Send OFF twice to all cubes (reset)
        msg = ProtocolMessage.build(TYPE="OFF")
        self._send_tcp_all(msg)
        time.sleep(0.1)
        self._send_tcp_all(msg)
        
        time.sleep(0.5)
        
        # Countdown
        for i in range(countdown, 0, -1):
            self.logger.info(f"Starting in {i}...")
            time.sleep(1)
        
        self.logger.info("GO!")
        
        # Run game loop based on type
        if game_type == GameType.SEQUENTIAL:
            self._run_sequential(connected_cubes, timeout, start_delay)
        elif game_type == GameType.RANDOM:
            self._run_random(connected_cubes, timeout, start_delay)
        elif game_type == GameType.CLEARING:
            self._run_clearing(connected_cubes, timeout)
        elif game_type == GameType.LOOP:
            self._run_loop(connected_cubes, timeout, start_delay)
        
        # Game over
        self.logger.info("Game complete!")
        self._print_results(connected_cubes)
    
    def _flash_cube(self, cube: Cube):
        """Flash a cube (activate target)"""
        cube.status = CubeStatus.FLASHING
        cube.begin_time = datetime.now()
        
        msg = ProtocolMessage.build(TYPE="FLASH", COUNT="2")
        self._send_tcp(cube.ip, msg)
        
        self.logger.info(f"FLASH → {cube.id}")
    
    def _wait_for_hit(self, cube: Cube, timeout: int) -> bool:
        """
        Wait for cube to be hit or timeout.
        Returns True if hit, False if timeout.
        """
        start = time.time()
        
        while time.time() - start < timeout:
            if cube.status == CubeStatus.HIT:
                return True
            time.sleep(0.1)
        
        # Timeout
        cube.status = CubeStatus.FAILED
        
        self.logger.warning(f"TIMEOUT → {cube.id}")
        
        # Send OVER twice
        msg = ProtocolMessage.build(TYPE="OVER")
        self._send_tcp(cube.ip, msg)
        time.sleep(0.1)
        self._send_tcp(cube.ip, msg)
        
        return False
    
    def _run_sequential(self, cubes: List[Cube], timeout: int, start_delay: int):
        """Sequential Drill - cubes in order"""
        for cube in cubes:
            if not cube.is_connected():
                continue
            
            self._flash_cube(cube)
            self._wait_for_hit(cube, timeout)
            
            time.sleep(start_delay)
    
    def _run_random(self, cubes: List[Cube], timeout: int, start_delay: int):
        """Random Drill - random order"""
        remaining = [c for c in cubes if c.is_connected()]
        random.shuffle(remaining)
        
        for cube in remaining:
            # Add random delay (0.5-3.5s like Android app)
            extra_delay = random.uniform(0.5, 3.5)
            time.sleep(extra_delay)
            
            self._flash_cube(cube)
            self._wait_for_hit(cube, timeout)
            
            time.sleep(start_delay)
    
    def _run_clearing(self, cubes: List[Cube], timeout: int):
        """Clearing Drill - all at once"""
        connected = [c for c in cubes if c.is_connected()]
        
        # Flash all cubes simultaneously
        for cube in connected:
            self._flash_cube(cube)
        
        # Wait for all to be hit or timeout
        start = time.time()
        while time.time() - start < timeout:
            all_done = all(c.status in (CubeStatus.HIT, CubeStatus.FAILED) 
                          for c in connected)
            if all_done:
                break
            time.sleep(0.1)
        
        # Timeout any remaining cubes
        for cube in connected:
            if cube.status == CubeStatus.FLASHING:
                cube.status = CubeStatus.FAILED
                msg = ProtocolMessage.build(TYPE="OVER")
                self._send_tcp(cube.ip, msg)
                time.sleep(0.1)
                self._send_tcp(cube.ip, msg)
    
    def _run_loop(self, cubes: List[Cube], timeout: int, start_delay: int):
        """Random Loop - continuous until interrupted"""
        self.logger.info("Loop mode - press Ctrl+C to stop")
        
        try:
            while True:
                # Pick random connected cube
                available = [c for c in cubes if c.is_connected() and c.status != CubeStatus.FLASHING]
                if not available:
                    # Reset all
                    for c in cubes:
                        if c.is_connected():
                            c.status = CubeStatus.READY
                    continue
                
                cube = random.choice(available)
                
                # Random delay
                extra_delay = random.uniform(0.5, 3.5)
                time.sleep(extra_delay + start_delay)
                
                self._flash_cube(cube)
                self._wait_for_hit(cube, timeout)
                
        except KeyboardInterrupt:
            self.logger.info("\nLoop mode stopped by user")
    
    def _print_results(self, cubes: List[Cube]):
        """Print game results"""
        print("\n" + "="*50)
        print("RESULTS")
        print("="*50)
        
        for cube in cubes:
            if cube.status == CubeStatus.HIT:
                print(f"  {cube.id}: {cube.reaction_time:.3f}s")
            elif cube.status == CubeStatus.FAILED:
                print(f"  {cube.id}: TIMEOUT")
            else:
                print(f"  {cube.id}: NOT PLAYED")
        
        # Calculate stats
        hit_times = [c.reaction_time for c in cubes if c.status == CubeStatus.HIT]
        if hit_times:
            print(f"\nAverage: {sum(hit_times)/len(hit_times):.3f}s")
            print(f"Best: {min(hit_times):.3f}s")
        
        print("="*50 + "\n")


def main():
    parser = argparse.ArgumentParser(
        description="iTarget Cube Controller - Control iTarget training cubes",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Game Types:
  sequential  - Cubes flash in order, one at a time
  random      - One random cube at a time
  clearing    - All cubes flash at once, hit them all
  loop        - Random continuous mode (Ctrl+C to stop)

Examples:
  %(prog)s --discover
  %(prog)s --game sequential
  %(prog)s --game clearing --timeout 15 --debug
        """
    )
    
    parser.add_argument("--debug", action="store_true",
                       help="Enable debug logging (shows all packets)")
    parser.add_argument("--discover", action="store_true",
                       help="Discover cubes and exit")
    parser.add_argument("--game", choices=["sequential", "random", "clearing", "loop"],
                       help="Start a game with the specified type")
    parser.add_argument("--countdown", type=int, default=DEFAULT_COUNTDOWN,
                       help=f"Countdown seconds before game starts (default: {DEFAULT_COUNTDOWN})")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT,
                       help=f"Seconds before cube times out (default: {DEFAULT_TIMEOUT})")
    parser.add_argument("--delay", type=int, default=DEFAULT_START_DELAY,
                       help=f"Delay between shots in seconds (default: {DEFAULT_START_DELAY})")
    
    args = parser.parse_args()
    
    # Create controller
    controller = ITargetController(debug=args.debug)
    
    try:
        # Start services
        controller.start()
        time.sleep(0.5)
        
        # Discover cubes
        cubes = controller.discover_cubes(timeout=5.0)
        
        if not cubes:
            print("No cubes found!")
            return 1
        
        # Wait for TCP connections
        controller.wait_for_connections(timeout=10.0)
        
        if args.discover:
            # Just discovery mode
            return 0
        
        # Determine game type
        if args.game:
            game_type_map = {
                "sequential": GameType.SEQUENTIAL,
                "random": GameType.RANDOM,
                "clearing": GameType.CLEARING,
                "loop": GameType.LOOP
            }
            game_type = game_type_map[args.game]
        else:
            # Interactive selection
            print("\nSelect game type:")
            print("  1) Sequential Drill")
            print("  2) Random Drill")
            print("  3) Clearing Drill")
            print("  4) Random Loop")
            
            try:
                choice = int(input("\nEnter choice (1-4): "))
                if choice < 1 or choice > 4:
                    raise ValueError()
                game_type = GameType(choice - 1)
            except (ValueError, EOFError, KeyboardInterrupt):
                print("\nInvalid choice or cancelled")
                return 1
        
        # Start game
        controller.start_game(
            game_type,
            countdown=args.countdown,
            timeout=args.timeout,
            start_delay=args.delay
        )
        
        return 0
    
    except KeyboardInterrupt:
        print("\n\nInterrupted by user")
        return 1
    
    finally:
        controller.stop()


if __name__ == "__main__":
    sys.exit(main())
