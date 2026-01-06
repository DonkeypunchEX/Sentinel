#!/usr/bin/env python3
"""
Emergency Satellite Overwatch Protocol - Sentinel Node 1
Icarus Directive - Phase 1 Deployment

Monitors WiFi environments for malicious access point patterns (Abyss servers, VPN spoofing, 
grooming SSIDs) and transmits encrypted alerts via satellite communication (Iridium burst).
Designed for deployment on Pwnagotchi devices.

Author: icarus@sentinel.network
License: GPL-3.0
Version: 1.0.0
"""

import json
import time
import subprocess
import serial
import gpsd
import logging
import hashlib
import base64
from typing import Dict, List, Tuple, Optional
from cryptography.fernet import Fernet
from pwnagotchi.plugins import Plugin


class EmergencySatelliteOverwatch(Plugin):
    """
    Pwnagotchi plugin for detecting malicious WiFi access points and transmitting
    encrypted alerts via Iridium satellite modem.
    
    Features:
    - Real-time WiFi environment analysis
    - GPS-based geofencing
    - Pattern detection for known threat signatures
    - Encrypted satellite communication
    - Baseline fingerprinting for anomaly detection
    """
    
    __author__ = 'icarus@sentinel.network'
    __version__ = '1.0.0'
    __license__ = 'GPL-3.0'
    __description__ = (
        'Detects malicious WiFi access point patterns (Abyss servers, VPN spoofing, '
        'grooming SSIDs) and transmits encrypted alerts via satellite communication.'
    )
    
    def __init__(self):
        """Initialize the Sentinel overwatch system."""
        super().__init__()
        
        # Serial configuration for Iridium modem (RockBLOCK 9603)
        self.modem_port = "/dev/ttyS0"
        self.baudrate = 19200
        
        # Geofencing coordinates (lat_min, lon_min, lat_max, lon_max)
        # Update with your operational area coordinates
        self.geofence_coords: List[Tuple[float, float, float, float]] = [
            (-90.0, -180.0, 90.0, 180.0)  # Global coverage - customize for your area
        ]
        
        # Alert threshold (0.0 to 1.0)
        self.alert_threshold = 0.75
        
        # Baseline SSID fingerprints for anomaly detection
        self.baseline_fingerprints = set()
        
        # Encryption setup
        # WARNING: Generate a proper key for production use:
        #   from cryptography.fernet import Fernet
        #   key = Fernet.generate_key()
        self.encryption_key = b'your-32-byte-base64-encoded-secret-key-here=='
        self.cipher_suite = Fernet(self.encryption_key)
        
        # System state
        self.override_mode = False  # Geofence activation state
        self.last_transmission = 0  # Timestamp of last satellite burst
        self.cooldown = 300  # Minimum seconds between transmissions (5 minutes)
        
        # Known malicious SSID patterns (update from intelligence sources)
        self.threat_signatures = {
            'prometheus', 'mephi', 'pisboy', 'five', 'dirtypoptart',
            'abyss764', 'masscollector', 'goonchan', 'tccdiscord'
        }
        
        # Grooming/enticement keywords
        self.grooming_keywords = [
            'goon', '764', 'tcc', 'abyss', 'mass', 'piss', 'pop tart',
            'free', 'wifi', 'guest', 'public', 'hotspot'
        ]
        
        # Logging
        self.logger = logging.getLogger(__name__)

    # ---------------------------------------------------------------------
    # Plugin Lifecycle Methods
    # ---------------------------------------------------------------------
    
    def on_loaded(self) -> None:
        """
        Initialize the plugin when loaded by Pwnagotchi.
        Connects to GPS, loads baseline fingerprints, and starts monitoring.
        """
        self.log_info("[Sentinel] Initializing Emergency Satellite Overwatch Protocol")
        
        # Connect to GPS
        try:
            gpsd.connect()
            self.log_info("[Sentinel] GPS connected successfully")
        except Exception as e:
            self.log_warning(f"[Sentinel] GPS unavailable: {e} - Continuing without GPS")
        
        # Load baseline fingerprints
        self.load_baseline()
        
        self.log_info("[Sentinel] Sentinel Node 1 online - Geofence monitoring active")
        self.log_info(f"[Sentinel] Alert threshold: {self.alert_threshold}")
        self.log_info(f"[Sentinel] Geofence zones: {len(self.geofence_coords)}")
    
    def on_unloaded(self) -> None:
        """Clean shutdown of the plugin."""
        self.log_info("[Sentinel] Sentinel Node 1 shutting down")
    
    # ---------------------------------------------------------------------
    # Core Monitoring Functions
    # ---------------------------------------------------------------------
    
    def load_baseline(self) -> None:
        """
        Load baseline WiFi fingerprints from persistent storage.
        Creates file if it doesn't exist.
        """
        baseline_file = '/root/sentinel_baseline.json'
        
        try:
            with open(baseline_file, 'r') as f:
                data = json.load(f)
                self.baseline_fingerprints = set(data.get('ssids', []))
                self.log_info(f"[Sentinel] Loaded {len(self.baseline_fingerprints)} baseline fingerprints")
        except FileNotFoundError:
            self.log_info("[Sentinel] No baseline file found - starting fresh")
            self.baseline_fingerprints = set()
        except json.JSONDecodeError as e:
            self.log_warning(f"[Sentinel] Corrupted baseline file: {e} - Creating new baseline")
            self.baseline_fingerprints = set()
        except Exception as e:
            self.log_error(f"[Sentinel] Error loading baseline: {e}")
            self.baseline_fingerprints = set()
    
    def save_baseline(self, new_fingerprints: set) -> None:
        """
        Update and save baseline fingerprints.
        
        Args:
            new_fingerprints: Set of new SSIDs to add to baseline
        """
        if not new_fingerprints:
            return
            
        # Add new fingerprints
        previous_count = len(self.baseline_fingerprints)
        self.baseline_fingerprints.update(new_fingerprints)
        added_count = len(self.baseline_fingerprints) - previous_count
        
        if added_count > 0:
            data = {
                'ssids': list(self.baseline_fingerprints),
                'timestamp': time.time(),
                'metadata': {
                    'total_fingerprints': len(self.baseline_fingerprints),
                    'version': self.__version__
                }
            }
            
            try:
                with open('/root/sentinel_baseline.json', 'w') as f:
                    json.dump(data, f, indent=2)
                self.log_info(f"[Sentinel] Baseline updated: +{added_count} new fingerprints")
            except Exception as e:
                self.log_error(f"[Sentinel] Failed to save baseline: {e}")
    
    def get_gps_position(self) -> Dict:
        """
        Get current GPS coordinates.
        
        Returns:
            Dictionary with lat, lon, alt, and status
        """
        try:
            packet = gpsd.get_current()
            return {
                'lat': packet.lat,
                'lon': packet.lon,
                'alt': packet.alt if hasattr(packet, 'alt') else 0.0,
                'speed': packet.hspeed if hasattr(packet, 'hspeed') else 0.0,
                'time': time.time(),
                'status': 'valid',
                'mode': packet.mode if hasattr(packet, 'mode') else 0
            }
        except Exception as e:
            self.log_debug(f"[Sentinel] GPS error: {e}")
            return {
                'lat': 0.0,
                'lon': 0.0,
                'alt': 0.0,
                'time': time.time(),
                'status': 'no_gps',
                'error': str(e)
            }
    
    def check_geofence(self, lat: float, lon: float) -> bool:
        """
        Check if current position is within any configured geofence zone.
        
        Args:
            lat: Latitude
            lon: Longitude
            
        Returns:
            True if within geofence, False otherwise
        """
        if lat == 0.0 and lon == 0.0:  # GPS unavailable
            return False
            
        for lat_min, lon_min, lat_max, lon_max in self.geofence_coords:
            if lat_min <= lat <= lat_max and lon_min <= lon <= lon_max:
                return True
        return False
    
    def scan_wifi(self) -> List[str]:
        """
        Scan current WiFi environment for access points.
        
        Returns:
            List of SSIDs (lowercase)
        """
        ssids = []
        
        try:
            # Use iwlist to scan for access points
            result = subprocess.run(
                ['iwlist', 'wlan0', 'scan'],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                current_essid = None
                for line in result.stdout.split('\n'):
                    line = line.strip()
                    
                    # Extract ESSID
                    if 'ESSID:' in line:
                        try:
                            essid = line.split('"')[1]
                            if essid and essid.strip():  # Filter empty/whitespace SSIDs
                                ssids.append(essid.lower())
                        except IndexError:
                            continue
                            
            else:
                self.log_debug("[Sentinel] iwlist scan failed")
                
        except subprocess.TimeoutExpired:
            self.log_warning("[Sentinel] WiFi scan timeout")
        except FileNotFoundError:
            self.log_error("[Sentinel] iwlist command not found")
        except Exception as e:
            self.log_error(f"[Sentinel] WiFi scan error: {e}")
        
        # Deduplicate SSIDs
        return list(set(ssids))
    
    def analyze_threat_patterns(self, ssids: List[str]) -> Dict:
        """
        Analyze WiFi environment for threat patterns.
        
        Args:
            ssids: List of SSIDs detected in scan
            
        Returns:
            Dictionary with threat score and detailed analysis
        """
        if not ssids:
            return {
                'score': 0.0,
                'anomalies': [],
                'total_ssids': 0,
                'new_count': 0,
                'threat_matches': 0,
                'grooming_matches': 0
            }
        
        score = 0.0
        anomalies = []
        threat_matches = 0
        grooming_matches = 0
        
        for ssid in ssids:
            ssid_lower = ssid.lower()
            ssid_anomalies = []
            
            # Check for known threat signatures
            for signature in self.threat_signatures:
                if signature in ssid_lower:
                    score += 0.3
                    threat_matches += 1
                    ssid_anomalies.append(f"THREAT_SIG:{signature}")
            
            # Check for new SSIDs (not in baseline)
            if ssid_lower not in self.baseline_fingerprints:
                score += 0.1
                ssid_anomalies.append("NEW_SSID")
            
            # Check for grooming keywords
            for keyword in self.grooming_keywords:
                if keyword in ssid_lower:
                    score += 0.2
                    grooming_matches += 1
                    ssid_anomalies.append(f"GROOMING:{keyword}")
            
            # Check for suspicious patterns
            if self._is_suspicious_pattern(ssid_lower):
                score += 0.15
                ssid_anomalies.append("SUSPICIOUS_PATTERN")
            
            if ssid_anomalies:
                anomalies.append({
                    'ssid': ssid,
                    'anomalies': ssid_anomalies,
                    'risk_score': min(score, 1.0)
                })
        
        # Normalize score
        normalized_score = min(score, 1.0)
        
        return {
            'score': normalized_score,
            'anomalies': anomalies,
            'total_ssids': len(ssids),
            'new_count': len([s for s in ssids if s.lower() not in self.baseline_fingerprints]),
            'threat_matches': threat_matches,
            'grooming_matches': grooming_matches,
            'alert_triggered': normalized_score > self.alert_threshold
        }
    
    def _is_suspicious_pattern(self, ssid: str) -> bool:
        """
        Detect suspicious SSID patterns.
        
        Args:
            ssid: SSID to check
            
        Returns:
            True if pattern is suspicious
        """
        suspicious_patterns = [
            r'\d{3}-\d{3}-\d{4}',  # Phone number pattern
            r'admin\d*',           # Admin variants
            r'root\d*',            # Root variants
            r'config\d*',          # Configuration variants
        ]
        
        import re
        for pattern in suspicious_patterns:
            if re.search(pattern, ssid):
                return True
        
        # Check for very long or very short SSIDs
        if len(ssid) > 32 or (len(ssid) < 3 and ssid != ''):
            return True
            
        return False
    
    def build_payload(self) -> Dict:
        """
        Construct encrypted satellite transmission payload.
        
        Returns:
            Dictionary containing all monitoring data
        """
        # Gather intelligence
        ssids = self.scan_wifi()
        gps_data = self.get_gps_position()
        threat_analysis = self.analyze_threat_patterns(ssids)
        
        # Build payload
        payload = {
            'metadata': {
                'node_id': 'sentinel-1',
                'version': self.__version__,
                'timestamp': time.time(),
                'transmission_id': hashlib.md5(str(time.time()).encode()).hexdigest()[:8]
            },
            'gps': gps_data,
            'wifi_intel': {
                'environment': {
                    'total_aps': len(ssids),
                    'ssids': ssids[:50],  # Limit payload size
                    'encrypted_count': 0,  # TODO: Add encryption detection
                    'hidden_count': 0      # TODO: Add hidden AP detection
                },
                'threat_analysis': threat_analysis,
                'baseline': {
                    'fingerprint_count': len(self.baseline_fingerprints),
                    'coverage_ratio': len(ssids) / max(len(self.baseline_fingerprints), 1)
                }
            },
            'system_status': {
                'override_mode': self.override_mode,
                'last_transmission': self.last_transmission,
                'uptime': time.time() - self._start_time if hasattr(self, '_start_time') else 0,
                'geofence_active': self.check_geofence(
                    gps_data.get('lat', 0), 
                    gps_data.get('lon', 0)
                )
            },
            'alert': {
                'triggered': threat_analysis['alert_triggered'],
                'level': 'HIGH' if threat_analysis['score'] > 0.8 else 
                        'MEDIUM' if threat_analysis['score'] > 0.5 else 
                        'LOW',
                'score': threat_analysis['score'],
                'threshold': self.alert_threshold
            }
        }
        
        return payload
    
    def transmit_satellite(self, payload: Dict) -> bool:
        """
        Send encrypted burst via Iridium satellite modem.
        
        Args:
            payload: Data payload to transmit
            
        Returns:
            True if transmission successful, False otherwise
        """
        # Check cooldown
        current_time = time.time()
        if current_time - self.last_transmission < self.cooldown:
            wait_time = self.cooldown - (current_time - self.last_transmission)
            self.log_info(f"[Sentinel] Transmission cooldown: {wait_time:.0f}s remaining")
            return False
        
        try:
            # Encrypt payload
            payload_json = json.dumps(payload, separators=(',', ':'))  # Compact JSON
            encrypted_data = self.cipher_suite.encrypt(payload_json.encode())
            
            # Prepare modem packet
            packet = {
                'header': {
                    'type': 'SENTINEL_ALERT',
                    'protocol_version': '1.0',
                    'priority': 'HIGH' if payload['alert']['triggered'] else 'ROUTINE'
                },
                'payload': {
                    'data': base64.b64encode(encrypted_data).decode('ascii'),
                    'size_bytes': len(encrypted_data),
                    'compression': 'none'  # TODO: Add compression
                },
                'integrity': {
                    'checksum': hashlib.sha256(encrypted_data).hexdigest()[:16],
                    'timestamp': current_time
                }
            }
            
            # Serial transmission to Iridium modem
            self.log_info("[Sentinel] Initializing satellite transmission...")
            
            with serial.Serial(
                port=self.modem_port,
                baudrate=self.baudrate,
                timeout=10,
                bytesize=serial.EIGHTBITS,
                parity=serial.PARITY_NONE,
                stopbits=serial.STOPBITS_ONE
            ) as ser:
                
                # Send AT command to prepare modem
                ser.write(b"AT+SBDSX\r\n")
                time.sleep(1)
                
                # Send the data packet
                packet_json = json.dumps(packet) + "\r\n"
                ser.write(packet_json.encode('ascii'))
                
                # Wait for transmission confirmation
                time.sleep(2)
                
                # Read response (simplified - implement proper response parsing)
                if ser.in_waiting:
                    response = ser.read(ser.in_waiting).decode('ascii', errors='ignore')
                    if 'OK' in response or 'SBDIX' in response:
                        self.log_info("[Sentinel] Satellite transmission confirmed")
                    else:
                        self.log_warning(f"[Sentinel] Modem response: {response}")
            
            # Update transmission timestamp
            self.last_transmission = current_time
            
            # Log transmission details
            threat_score = payload['alert']['score']
            ssid_count = payload['wifi_intel']['environment']['total_aps']
            self.log_info(
                f"[Sentinel] BURST TRANSMISSION COMPLETE | "
                f"Threat Score: {threat_score:.2f} | "
                f"APs: {ssid_count} | "
                f"Alert: {'YES' if payload['alert']['triggered'] else 'NO'}"
            )
            
            return True
            
        except serial.SerialException as e:
            self.log_error(f"[Sentinel] Serial communication error: {e}")
            return False
        except Exception as e:
            self.log_error(f"[Sentinel] Transmission failed: {e}")
            return False
    
    # ---------------------------------------------------------------------
    # Pwnagotchi Event Handlers
    # ---------------------------------------------------------------------
    
    def on_loop(self) -> None:
        """
        Main monitoring loop called by Pwnagotchi.
        Executes geofence checks, threat analysis, and satellite transmission.
        """
        try:
            # Record start time on first loop
            if not hasattr(self, '_start_time'):
                self._start_time = time.time()
            
            # Get GPS position
            gps_data = self.get_gps_position()
            lat = gps_data.get('lat', 0)
            lon = gps_data.get('lon', 0)
            
            # Check geofence activation
            if not self.override_mode:
                if self.check_geofence(lat, lon):
                    self.override_mode = True
                    self.log_info("[Sentinel] GEOFENCE ACTIVATED - Overwatch protocol engaged")
                    self.log_info(f"[Sentinel] Position: {lat:.4f}, {lon:.4f}")
            
            # Only operate in override mode (within geofence)
            if self.override_mode:
                # Build and analyze payload
                payload = self.build_payload()
                
                # Update baseline with safe SSIDs (non-threatening)
                if payload['wifi_intel']['environment']['total_aps'] > 0:
                    safe_ssids = [
                        ssid for ssid in payload['wifi_intel']['environment']['ssids']
                        if not any(
                            threat['ssid'].lower() == ssid.lower() 
                            for threat in payload['wifi_intel']['threat_analysis']['anomalies']
                        )
                    ]
                    self.save_baseline(set(safe_ssids))
                
                # Transmit alert if threshold exceeded
                if payload['alert']['triggered']:
                    self.log_warning(
                        f"[Sentinel] THREAT DETECTED | "
                        f"Score: {payload['alert']['score']:.2f} | "
                        f"Level: {payload['alert']['level']}"
                    )
                    
                    transmission_success = self.transmit_satellite(payload)
                    if transmission_success:
                        self.log_warning("[Sentinel] ABYSS PATTERN DETECTED - COMMAND NOTIFIED")
                
                # Update Pwnagotchi display
                self._update_display(payload)
            
            # Sleep until next cycle
            time.sleep(30)  # 30-second scan cycle
            
        except Exception as e:
            self.log_error(f"[Sentinel] Monitoring loop error: {e}")
            time.sleep(60)  # Longer sleep on error
    
    def _update_display(self, payload: Dict) -> None:
        """
        Update Pwnagotchi display with monitoring information.
        
        Args:
            payload: Current monitoring payload
        """
        try:
            ui = self.api.ui if hasattr(self, 'api') and self.api else None
            
            if ui:
                # Format bottom text
                threat_score = payload['alert']['score']
                ap_count = payload['wifi_intel']['environment']['total_aps']
                new_aps = payload['wifi_intel']['threat_analysis']['new_count']
                alert_status = "!" if payload['alert']['triggered'] else "."
                
                display_text = (
                    f"S:{threat_score:.1f} {ap_count}AP "
                    f"N:{new_aps} {alert_status}"
                )
                
                ui.set('bottom_text', display_text)
                
                # Optional: Update face based on threat level
                if payload['alert']['triggered']:
                    ui.set('face', '(╯°□°)╯')
                elif threat_score > 0.5:
                    ui.set('face', '(•_•)')
                
        except Exception as e:
            self.log_debug(f"[Sentinel] Display update failed: {e}")
    
    # ---------------------------------------------------------------------
    # Logging Helpers
    # ---------------------------------------------------------------------
    
    def log_info(self, message: str) -> None:
        """Log informational message."""
        self.logger.info(message)
        print(f"[INFO] {message}")
    
    def log_warning(self, message: str) -> None:
        """Log warning message."""
        self.logger.warning(message)
        print(f"[WARN] {message}")
    
    def log_error(self, message: str) -> None:
        """Log error message."""
        self.logger.error(message)
        print(f"[ERROR] {message}")
    
    def log_debug(self, message: str) -> None:
        """Log debug message."""
        self.logger.debug(message)
        # Debug messages not printed by default


# Plugin registration
if __name__ == "__main__":
    print("Emergency Satellite Overwatch Protocol - Sentinel Node 1")
    print("This is a Pwnagotchi plugin and should be loaded via plugin system.")
