#!/usr/bin/env python3
"""
🔐 Security Hardened - Multi-process Mnemonic/Private Key Vanity Address Generator v3.2
"""

import multiprocessing
from multiprocessing import Value, Queue, Event
import time
import argparse
import os
import ctypes
import secrets
import shutil
import sys
import signal
import hashlib
import gc
import traceback
from typing import Dict, Any, List, Tuple

# Third-party libraries
try:
    from mnemonic import Mnemonic
    from bip_utils import (
        Bip39SeedGenerator, Bip44, Bip44Coins, Bip44Changes,
        Secp256k1PrivateKey, Ed25519PrivateKey,
        EthAddrEncoder, TrxAddrEncoder, SolAddrEncoder
    )
    LIBS_AVAILABLE = True
except ImportError as e:
    print(f"❌ Missing required dependencies: {e}")
    print("Please run: pip install mnemonic bip-utils")
    LIBS_AVAILABLE = False


# ============================================================
# Global State Management
# ============================================================

class GlobalState:
    """Global state manager"""
    def __init__(self):
        self.processes: List[Tuple] = []
        self.task_info: Dict = {}
        self.result_queue: Queue = None
        self.collected_results: Dict = {}
        self.collected_errors: List = []
        self.start_time: float = 0
        self.is_running: bool = False
        self.interrupted: bool = False
    
    def reset(self):
        self.processes = []
        self.task_info = {}
        self.result_queue = None
        self.collected_results = {}
        self.collected_errors = []
        self.start_time = 0
        self.is_running = False
        self.interrupted = False


g_state = GlobalState()


def graceful_exit_handler(signum, frame):
    """Global signal handler"""
    g_state.interrupted = True
    
    if g_state.is_running:
        print("\n\n" + "=" * 60)
        print("⏹️  Interrupt signal received, stopping safely...")
        print("=" * 60)
        
        for info in g_state.task_info.values():
            try:
                info['stop_event'].set()
            except Exception:
                pass
    else:
        print("\n\n⏹️  Program interrupted")
        sys.exit(0)


signal.signal(signal.SIGINT, graceful_exit_handler)
if hasattr(signal, 'SIGTERM'):
    signal.signal(signal.SIGTERM, graceful_exit_handler)


# ============================================================
# Constants Configuration
# ============================================================
MAX_CONSECUTIVE_ERRORS = 100
SHOW_PARTIAL_CHARS = 4

# Runtime security config (overridable via CLI args)
NETWORK_CHECK_MODE = "passive"  # passive|active|skip
ENABLE_CLIPBOARD = True
DEBUG = False


# ============================================================
# Network Detection (Windows Fixed Version)
# ============================================================

def check_network_connection() -> Tuple[bool, str]:
    """
    Detect network connection status - Cross-platform fixed version
    Defaults to passive mode (no outbound connection)
    """
    import socket
    
    mode = (NETWORK_CHECK_MODE or "passive").strip().lower()

    if mode == "skip":
        return False, "Network check skipped"

    if mode != "active":
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(0.3)
            # UDP connect does not send packets; triggers local routing selection
            sock.connect(("8.8.8.8", 80))
            local_ip = sock.getsockname()[0]

            if not local_ip or local_ip == "0.0.0.0" or local_ip.startswith("127."):
                return False, "No valid network interface detected"

            if local_ip.startswith("169.254."):
                return True, f"Link-local address detected {local_ip} (may have no internet)"

            return True, f"Network interface configured ({local_ip})"
        except OSError:
            return False, "No valid network interface detected"
        except Exception:
            return False, "No valid network interface detected"
        finally:
            try:
                if sock is not None:
                    sock.close()
            except Exception:
                pass

    # active: Test target list (DNS servers, port 53)
    test_targets = [
        ("8.8.8.8", 53),        # Google DNS
        ("1.1.1.1", 53),        # Cloudflare DNS
        ("223.5.5.5", 53),      # Alibaba DNS
        ("114.114.114.114", 53), # 114 DNS
    ]

    for host, port in test_targets:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.3)  # 300ms timeout, fails quickly when offline
            result = sock.connect_ex((host, port))
            sock.close()

            if result == 0:
                return True, f"Network connection detected (can access {host})"
        except socket.timeout:
            continue
        except OSError:
            continue
        except Exception:
            continue

    # All targets unreachable
    return False, "No network connection detected"


def check_system_entropy() -> Tuple[bool, str]:
    """Check system entropy pool status"""
    try:
        with open('/proc/sys/kernel/random/entropy_avail', 'r') as f:
            entropy = int(f.read().strip())
            if entropy < 256:
                return False, f"Insufficient system entropy: {entropy} bits"
            return True, f"System entropy pool healthy: {entropy} bits"
    except FileNotFoundError:
        pass
    
    try:
        test_bytes = secrets.token_bytes(1000)
        unique_bytes = len(set(test_bytes))
        if unique_bytes < 200:
            return False, "Abnormal random number distribution"
        return True, "Random number generator normal"
    except Exception as e:
        return False, f"Entropy check failed: {e}"


def verify_randomness(data: bytes) -> bool:
    """Verify data randomness"""
    if len(data) < 16:
        return False
    if all(b == 0 for b in data) or all(b == 255 for b in data):
        return False
    unique = len(set(data))
    min_unique = max(2, len(data) // 8)
    return unique >= min_unique


def check_environment() -> Tuple[bool, List[str]]:
    """Runtime environment security check"""
    warnings = []
    is_secure = True
    
    # Debugger check
    if hasattr(sys, 'gettrace') and sys.gettrace() is not None:
        warnings.append("⚠️  Debugger attachment detected")
        is_secure = False
    
    # Network check
    print("   Checking network status...", end="", flush=True)
    has_network, network_msg = check_network_connection()
    print("\r" + " " * 40 + "\r", end="")  # Clear detection prompt
    
    if has_network:
        warnings.append(f"💡 {network_msg}, recommend disconnecting for maximum security")
    else:
        warnings.append(f"✓ {network_msg} (offline mode, secure)")
    
    # Entropy source check
    entropy_ok, entropy_msg = check_system_entropy()
    if not entropy_ok:
        warnings.append(f"⚠️  {entropy_msg}")
        is_secure = False
    
    return is_secure, warnings


def hash_address(address: str) -> str:
    """Calculate address hash"""
    return hashlib.sha256(address.encode()).hexdigest()


# ============================================================
# Formatting Utilities
# ============================================================

def format_time(seconds: float) -> str:
    if seconds < 0:
        return "Completed"
    if seconds < 60:
        return f"{seconds:.1f}s"
    elif seconds < 3600:
        return f"{seconds/60:.1f}min"
    elif seconds < 86400:
        return f"{seconds/3600:.1f}hrs"
    elif seconds < 31536000:
        return f"{seconds/86400:.1f}days"
    else:
        return f"{seconds/31536000:.2f}yrs"


def format_number(num: float) -> str:
    if num < 1000:
        return str(int(num))
    elif num < 1000000:
        return f"{num/1000:.1f}K"
    elif num < 1000000000:
        return f"{num/1000000:.2f}M"
    else:
        return f"{num/1000000000:.2f}B"


def calculate_single_probability(target_suffix: str, chain_type: str) -> Tuple[float, int]:
    if chain_type == "ETH":
        hex_chars = "0123456789abcdef"
        suffix_lower = target_suffix.lower()
        valid_count = sum(1 for c in suffix_lower if c in hex_chars)
        if valid_count > 0:
            return 1 / (16 ** valid_count), 16 ** valid_count
    else:
        base58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
        valid_count = sum(1 for c in target_suffix if c in base58)
        if valid_count > 0:
            return 1 / (58 ** valid_count), 58 ** valid_count
    return 1, 1


def progress_bar(current: int, total: int, width: int = 20) -> str:
    if total <= 0:
        percent = 0
    else:
        percent = min(current / total, 1.0)
    filled = int(width * percent)
    bar = '█' * filled + '░' * (width - filled)
    return f"[{bar}] {percent*100:.1f}%"


# ============================================================
# Safe Input Functions
# ============================================================

def safe_input(prompt: str, default: str = "") -> str:
    try:
        return input(prompt)
    except (KeyboardInterrupt, EOFError):
        g_state.interrupted = True
        print("\n")
        return default


def safe_input_yn(prompt: str, default: bool = False) -> bool:
    try:
        result = input(prompt).strip().lower()
        return result == 'y'
    except (KeyboardInterrupt, EOFError):
        g_state.interrupted = True
        print("\n")
        return default


# ============================================================
# Key Validators
# ============================================================

def verify_mnemonic_address(mnemonic: str, chain: str, expected_address: str) -> bool:
    try:
        seed_bytes = Bip39SeedGenerator(mnemonic).Generate()
        
        if chain == "ETH":
            coin = Bip44Coins.ETHEREUM
        elif chain == "TRX":
            coin = Bip44Coins.TRON
        else:
            coin = Bip44Coins.SOLANA
        
        bip_obj = Bip44.FromSeed(seed_bytes, coin)
        derived_addr = bip_obj.Purpose().Coin().Account(0).Change(
            Bip44Changes.CHAIN_EXT).AddressIndex(0).PublicKey().ToAddress()
        
        if chain == "ETH":
            return derived_addr.lower() == expected_address.lower()
        else:
            return derived_addr == expected_address
    except Exception:
        return False


def verify_eth_keypair(privkey_bytes: bytes, expected_address: str) -> bool:
    try:
        priv_key = Secp256k1PrivateKey.FromBytes(privkey_bytes)
        derived_addr = EthAddrEncoder.EncodeKey(priv_key.PublicKey())
        return derived_addr.lower() == expected_address.lower()
    except Exception:
        return False


def verify_trx_keypair(privkey_bytes: bytes, expected_address: str) -> bool:
    try:
        priv_key = Secp256k1PrivateKey.FromBytes(privkey_bytes)
        derived_addr = TrxAddrEncoder.EncodeKey(priv_key.PublicKey())
        return derived_addr == expected_address
    except Exception:
        return False


def verify_sol_keypair(privkey_bytes: bytes, expected_address: str) -> bool:
    try:
        priv_key = Ed25519PrivateKey.FromBytes(privkey_bytes)
        derived_addr = SolAddrEncoder.EncodeKey(priv_key.PublicKey())
        return derived_addr == expected_address
    except Exception:
        return False


# ============================================================
# Worker Process Functions
# ============================================================

def worker_eth_mnemonic(target_suffix: str, stop_event, 
                        counter, lock, result_queue,
                        max_errors: int = 100) -> None:
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    if hasattr(signal, 'SIGTERM'):
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
    
    try:
        mnemo = Mnemonic("english")
        local_count = 0
        error_count = 0
        target_lower = target_suffix.lower()
        
        while not stop_event.is_set():
            try:
                words = mnemo.generate(strength=128)
                seed_bytes = Bip39SeedGenerator(words).Generate()
                bip_obj = Bip44.FromSeed(seed_bytes, Bip44Coins.ETHEREUM)
                eth_addr = bip_obj.Purpose().Coin().Account(0).Change(
                    Bip44Changes.CHAIN_EXT).AddressIndex(0).PublicKey().ToAddress()
                
                local_count += 1
                error_count = 0
                
                if local_count >= 10:
                    with lock:
                        counter.value += local_count
                    local_count = 0
                
                if eth_addr.lower().endswith(target_lower):
                    if verify_mnemonic_address(words, "ETH", eth_addr):
                        result_queue.put({
                            'chain': 'ETH',
                            'address': eth_addr,
                            'mnemonic': words,
                        })
                        stop_event.set()
                        return
                        
            except Exception as e:
                error_count += 1
                if error_count > max_errors:
                    result_queue.put({'error': True, 'chain': 'ETH', 'message': str(e)})
                    return
                continue
    except Exception as e:
        result_queue.put({'error': True, 'chain': 'ETH', 'message': f"Init: {e}"})


def worker_trx_mnemonic(target_suffix: str, stop_event,
                        counter, lock, result_queue,
                        max_errors: int = 100) -> None:
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    if hasattr(signal, 'SIGTERM'):
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
    
    try:
        mnemo = Mnemonic("english")
        local_count = 0
        error_count = 0
        
        while not stop_event.is_set():
            try:
                words = mnemo.generate(strength=128)
                seed_bytes = Bip39SeedGenerator(words).Generate()
                bip_obj = Bip44.FromSeed(seed_bytes, Bip44Coins.TRON)
                trx_addr = bip_obj.Purpose().Coin().Account(0).Change(
                    Bip44Changes.CHAIN_EXT).AddressIndex(0).PublicKey().ToAddress()
                
                local_count += 1
                error_count = 0
                
                if local_count >= 10:
                    with lock:
                        counter.value += local_count
                    local_count = 0
                
                if trx_addr.endswith(target_suffix):
                    if verify_mnemonic_address(words, "TRX", trx_addr):
                        result_queue.put({
                            'chain': 'TRX',
                            'address': trx_addr,
                            'mnemonic': words,
                        })
                        stop_event.set()
                        return
                        
            except Exception as e:
                error_count += 1
                if error_count > max_errors:
                    result_queue.put({'error': True, 'chain': 'TRX', 'message': str(e)})
                    return
                continue
    except Exception as e:
        result_queue.put({'error': True, 'chain': 'TRX', 'message': f"Init: {e}"})


def worker_sol_mnemonic(target_suffix: str, stop_event,
                        counter, lock, result_queue,
                        max_errors: int = 100) -> None:
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    if hasattr(signal, 'SIGTERM'):
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
    
    try:
        mnemo = Mnemonic("english")
        local_count = 0
        error_count = 0
        
        while not stop_event.is_set():
            try:
                words = mnemo.generate(strength=128)
                seed_bytes = Bip39SeedGenerator(words).Generate()
                bip_obj = Bip44.FromSeed(seed_bytes, Bip44Coins.SOLANA)
                sol_addr = bip_obj.Purpose().Coin().Account(0).Change(
                    Bip44Changes.CHAIN_EXT).AddressIndex(0).PublicKey().ToAddress()
                
                local_count += 1
                error_count = 0
                
                if local_count >= 10:
                    with lock:
                        counter.value += local_count
                    local_count = 0
                
                if sol_addr.endswith(target_suffix):
                    if verify_mnemonic_address(words, "SOL", sol_addr):
                        result_queue.put({
                            'chain': 'SOL',
                            'address': sol_addr,
                            'mnemonic': words,
                        })
                        stop_event.set()
                        return
                        
            except Exception as e:
                error_count += 1
                if error_count > max_errors:
                    result_queue.put({'error': True, 'chain': 'SOL', 'message': str(e)})
                    return
                continue
    except Exception as e:
        result_queue.put({'error': True, 'chain': 'SOL', 'message': f"Init: {e}"})


def worker_mnemonic_shared(target_suffix: str, stop_event,
                           counter, lock, result_queue,
                           check_eth: bool, check_trx: bool, check_sol: bool,
                           max_errors: int = 100) -> None:
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    if hasattr(signal, 'SIGTERM'):
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
    
    try:
        mnemo = Mnemonic("english")
        local_count = 0
        error_count = 0
        target_lower = target_suffix.lower()
        
        while not stop_event.is_set():
            try:
                words = mnemo.generate(strength=128)
                seed_bytes = Bip39SeedGenerator(words).Generate()
                
                match_all = True
                eth_addr = trx_addr = sol_addr = None
                
                if check_eth and match_all:
                    bip_obj = Bip44.FromSeed(seed_bytes, Bip44Coins.ETHEREUM)
                    eth_addr = bip_obj.Purpose().Coin().Account(0).Change(
                        Bip44Changes.CHAIN_EXT).AddressIndex(0).PublicKey().ToAddress()
                    if not eth_addr.lower().endswith(target_lower):
                        match_all = False
                
                if check_trx and match_all:
                    bip_obj = Bip44.FromSeed(seed_bytes, Bip44Coins.TRON)
                    trx_addr = bip_obj.Purpose().Coin().Account(0).Change(
                        Bip44Changes.CHAIN_EXT).AddressIndex(0).PublicKey().ToAddress()
                    if not trx_addr.endswith(target_suffix):
                        match_all = False
                
                if check_sol and match_all:
                    bip_obj = Bip44.FromSeed(seed_bytes, Bip44Coins.SOLANA)
                    sol_addr = bip_obj.Purpose().Coin().Account(0).Change(
                        Bip44Changes.CHAIN_EXT).AddressIndex(0).PublicKey().ToAddress()
                    if not sol_addr.endswith(target_suffix):
                        match_all = False
                
                local_count += 1
                error_count = 0
                
                if local_count >= 10:
                    with lock:
                        counter.value += local_count
                    local_count = 0
                
                if match_all:
                    result_queue.put({
                        'chain': 'SHARED_MNEMONIC',
                        'mnemonic': words,
                        'eth_address': eth_addr,
                        'trx_address': trx_addr,
                        'sol_address': sol_addr
                    })
                    stop_event.set()
                    return
                        
            except Exception as e:
                error_count += 1
                if error_count > max_errors:
                    result_queue.put({'error': True, 'chain': 'SHARED', 'message': str(e)})
                    return
                continue
    except Exception as e:
        result_queue.put({'error': True, 'chain': 'SHARED', 'message': f"Init: {e}"})


def worker_eth_privkey(target_suffix: str, stop_event,
                       counter, lock, result_queue,
                       max_errors: int = 100) -> None:
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    if hasattr(signal, 'SIGTERM'):
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
    
    try:
        local_count = 0
        error_count = 0
        target_lower = target_suffix.lower()
        
        while not stop_event.is_set():
            try:
                privkey_bytes = secrets.token_bytes(32)
                
                if not verify_randomness(privkey_bytes):
                    continue
                
                priv_key = Secp256k1PrivateKey.FromBytes(privkey_bytes)
                eth_addr = EthAddrEncoder.EncodeKey(priv_key.PublicKey())
                
                local_count += 1
                error_count = 0
                
                if local_count >= 100:
                    with lock:
                        counter.value += local_count
                    local_count = 0
                
                if eth_addr.lower().endswith(target_lower):
                    if verify_eth_keypair(privkey_bytes, eth_addr):
                        result_queue.put({
                            'chain': 'ETH',
                            'address': eth_addr,
                            'private_key': privkey_bytes.hex(),
                        })
                        stop_event.set()
                        return
                        
            except Exception as e:
                error_count += 1
                if error_count > max_errors:
                    result_queue.put({'error': True, 'chain': 'ETH', 'message': str(e)})
                    return
                continue
    except Exception as e:
        result_queue.put({'error': True, 'chain': 'ETH', 'message': f"Init: {e}"})


def worker_trx_privkey(target_suffix: str, stop_event,
                       counter, lock, result_queue,
                       max_errors: int = 100) -> None:
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    if hasattr(signal, 'SIGTERM'):
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
    
    try:
        local_count = 0
        error_count = 0
        
        while not stop_event.is_set():
            try:
                privkey_bytes = secrets.token_bytes(32)
                
                if not verify_randomness(privkey_bytes):
                    continue
                
                priv_key = Secp256k1PrivateKey.FromBytes(privkey_bytes)
                trx_addr = TrxAddrEncoder.EncodeKey(priv_key.PublicKey())
                
                local_count += 1
                error_count = 0
                
                if local_count >= 100:
                    with lock:
                        counter.value += local_count
                    local_count = 0
                
                if trx_addr.endswith(target_suffix):
                    if verify_trx_keypair(privkey_bytes, trx_addr):
                        result_queue.put({
                            'chain': 'TRX',
                            'address': trx_addr,
                            'private_key': privkey_bytes.hex(),
                        })
                        stop_event.set()
                        return
                        
            except Exception as e:
                error_count += 1
                if error_count > max_errors:
                    result_queue.put({'error': True, 'chain': 'TRX', 'message': str(e)})
                    return
                continue
    except Exception as e:
        result_queue.put({'error': True, 'chain': 'TRX', 'message': f"Init: {e}"})


def worker_sol_privkey(target_suffix: str, stop_event,
                       counter, lock, result_queue,
                       max_errors: int = 100) -> None:
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    if hasattr(signal, 'SIGTERM'):
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
    
    try:
        local_count = 0
        error_count = 0
        
        while not stop_event.is_set():
            try:
                privkey_bytes = secrets.token_bytes(32)
                
                if not verify_randomness(privkey_bytes):
                    continue
                
                priv_key = Ed25519PrivateKey.FromBytes(privkey_bytes)
                sol_addr = SolAddrEncoder.EncodeKey(priv_key.PublicKey())
                
                local_count += 1
                error_count = 0
                
                if local_count >= 100:
                    with lock:
                        counter.value += local_count
                    local_count = 0
                
                if sol_addr.endswith(target_suffix):
                    if verify_sol_keypair(privkey_bytes, sol_addr):
                        result_queue.put({
                            'chain': 'SOL',
                            'address': sol_addr,
                            'private_key': privkey_bytes.hex(),
                        })
                        stop_event.set()
                        return
                        
            except Exception as e:
                error_count += 1
                if error_count > max_errors:
                    result_queue.put({'error': True, 'chain': 'SOL', 'message': str(e)})
                    return
                continue
    except Exception as e:
        result_queue.put({'error': True, 'chain': 'SOL', 'message': f"Init: {e}"})


def worker_eth_trx_shared_privkey(target_suffix: str, stop_event,
                                   counter, lock, result_queue,
                                   check_eth: bool, check_trx: bool,
                                   max_errors: int = 100) -> None:
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    if hasattr(signal, 'SIGTERM'):
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
    
    try:
        local_count = 0
        error_count = 0
        target_lower = target_suffix.lower()
        
        while not stop_event.is_set():
            try:
                privkey_bytes = secrets.token_bytes(32)
                
                if not verify_randomness(privkey_bytes):
                    continue
                
                priv_key = Secp256k1PrivateKey.FromBytes(privkey_bytes)
                pub_key = priv_key.PublicKey()
                
                match = True
                eth_addr = trx_addr = None
                
                if check_eth:
                    eth_addr = EthAddrEncoder.EncodeKey(pub_key)
                    if not eth_addr.lower().endswith(target_lower):
                        match = False
                
                if match and check_trx:
                    trx_addr = TrxAddrEncoder.EncodeKey(pub_key)
                    if not trx_addr.endswith(target_suffix):
                        match = False
                
                local_count += 1
                error_count = 0
                
                if local_count >= 100:
                    with lock:
                        counter.value += local_count
                    local_count = 0
                
                if match:
                    result_queue.put({
                        'chain': 'ETH_TRX_SHARED',
                        'eth_address': eth_addr,
                        'trx_address': trx_addr,
                        'private_key': privkey_bytes.hex()
                    })
                    stop_event.set()
                    return
                        
            except Exception as e:
                error_count += 1
                if error_count > max_errors:
                    result_queue.put({'error': True, 'chain': 'ETH_TRX', 'message': str(e)})
                    return
                continue
    except Exception as e:
        result_queue.put({'error': True, 'chain': 'ETH_TRX', 'message': f"Init: {e}"})


# ============================================================
# Process Management
# ============================================================

def cleanup_processes(timeout: float = 5.0) -> None:
    for info in g_state.task_info.values():
        try:
            info['stop_event'].set()
        except Exception:
            pass
    
    time.sleep(0.3)
    
    for p, _ in g_state.processes:
        try:
            if p.is_alive():
                p.terminate()
        except Exception:
            pass
    
    deadline = time.time() + timeout
    while time.time() < deadline:
        if not any(p.is_alive() for p, _ in g_state.processes):
            break
        time.sleep(0.1)
    
    for p, _ in g_state.processes:
        try:
            if p.is_alive():
                p.kill()
                p.join(timeout=1)
        except Exception:
            pass
    
    gc.collect()


def collect_remaining_results() -> None:
    if g_state.result_queue is None:
        return
    
    try:
        while True:
            item = g_state.result_queue.get_nowait()
            if item.get('error'):
                g_state.collected_errors.append(item)
            else:
                chain = item.get('chain', 'UNKNOWN')
                g_state.collected_results[chain] = item
    except Exception:
        pass


# ============================================================
# Secure Display
# ============================================================

def display_sensitive(label: str, data: str, mask: bool = True) -> None:
    if mask:
        n = SHOW_PARTIAL_CHARS
        if len(data) > n * 2:
            masked = data[:n] + '*' * (len(data) - n * 2) + data[-n:]
        else:
            masked = '*' * len(data)
        print(f"   {label}: {masked}")
    else:
        print(f"   {label}: {data}")


def copy_to_clipboard(data: str) -> bool:
    if not ENABLE_CLIPBOARD:
        print("   Clipboard disabled (--no-clipboard)")
        return False

    try:
        import subprocess
        
        if sys.platform == 'darwin':
            pbcopy = shutil.which('pbcopy') or 'pbcopy'
            process = subprocess.Popen([pbcopy], stdin=subprocess.PIPE)
            process.communicate(data.encode())
        elif sys.platform == 'win32':
            system_root = os.environ.get('SystemRoot', r'C:\Windows')
            clip_exe = os.path.join(system_root, 'System32', 'clip.exe')
            cmd = [clip_exe] if os.path.exists(clip_exe) else ['clip']
            process = subprocess.Popen(cmd, stdin=subprocess.PIPE)
            process.communicate(data.encode())
        else:
            xclip = shutil.which('xclip')
            xsel = shutil.which('xsel')
            if xclip:
                process = subprocess.Popen([xclip, '-selection', 'clipboard'], stdin=subprocess.PIPE)
                process.communicate(data.encode())
            elif xsel:
                process = subprocess.Popen([xsel, '--clipboard', '--input'], stdin=subprocess.PIPE)
                process.communicate(data.encode())
            else:
                raise FileNotFoundError("xclip/xsel not found")
        return True
    except Exception as e:
        print(f"   ❌ Clipboard operation failed: {e}")
        return False


def display_results(results: Dict, errors: List, final_time: float, 
                    was_interrupted: bool = False) -> None:
    print("\n" + "=" * 60)
    print("📋 Generation Results:")
    print("=" * 60)
    
    has_result = False
    sensitive_data = []
    
    if 'SHARED_MNEMONIC' in results:
        has_result = True
        data = results['SHARED_MNEMONIC']
        print(f"\n🔗 Shared Mnemonic Mode:")
        display_sensitive("Mnemonic", data['mnemonic'])
        sensitive_data.append(('Mnemonic', data['mnemonic']))
        print(f"   ---")
        if data.get('eth_address'):
            print(f"   ETH Address: {data['eth_address']}")
        if data.get('trx_address'):
            print(f"   TRX Address: {data['trx_address']}")
        if data.get('sol_address'):
            print(f"   SOL Address: {data['sol_address']}")
    
    if 'ETH_TRX_SHARED' in results:
        has_result = True
        data = results['ETH_TRX_SHARED']
        print(f"\n🔗 ETH+TRX Shared Private Key:")
        display_sensitive("Private Key", data['private_key'])
        sensitive_data.append(('Private Key', data['private_key']))
        if data.get('eth_address'):
            print(f"   ETH Address: {data['eth_address']}")
        if data.get('trx_address'):
            print(f"   TRX Address: {data['trx_address']}")
    
    chain_icons = {'ETH': '🔷', 'TRX': '🔴', 'SOL': '🟣'}
    chain_names = {'ETH': 'Ethereum', 'TRX': 'Tron', 'SOL': 'Solana'}
    
    for chain in ['ETH', 'TRX', 'SOL']:
        if chain in results:
            has_result = True
            data = results[chain]
            print(f"\n{chain_icons[chain]} {chain_names[chain]} ({chain}):")
            print(f"   Address: {data['address']}")
            
            if 'private_key' in data:
                display_sensitive("Private Key", data['private_key'])
                sensitive_data.append((f'{chain} Private Key', data['private_key']))
            if 'mnemonic' in data:
                display_sensitive("Mnemonic", data['mnemonic'])
                sensitive_data.append((f'{chain} Mnemonic', data['mnemonic']))
    
    if not has_result:
        if was_interrupted:
            print("\n⚠️  Program interrupted, no matching result found")
        else:
            print("\n⚠️  No matching result found")
        if errors:
            print("\nErrors occurred:")
            for err in errors:
                print(f"   - {err.get('chain')}: {err.get('message')}")
    
    print("\n" + "=" * 60)
    print(f"⏱️  Total time: {format_time(final_time)}")
    
    if has_result and sensitive_data:
        print("\n" + "-" * 60)
        print("🔐 Sensitive Data Operations:")
        print("   Enter 'show' to view full content")
        print("   Enter 'copy N' to copy item N to clipboard")
        print("   Press Enter or type 'exit' to quit")
        print("-" * 60)
        
        for i, (label, _) in enumerate(sensitive_data, 1):
            print(f"   {i}. {label}")
        
        while True:
            cmd = safe_input("\nEnter command: ").strip().lower()
            if g_state.interrupted or cmd == 'exit' or cmd == '':
                break
            elif cmd == 'show':
                print("\n⚠️  Warning: About to display sensitive information, ensure surroundings are secure")
                confirm = safe_input("Confirm display? [y/N]: ").strip().lower()
                if confirm == 'y':
                    for label, value in sensitive_data:
                        print(f"   {label}: {value}")
            elif cmd.startswith('copy '):
                if not ENABLE_CLIPBOARD:
                    print("   Clipboard disabled (--no-clipboard)")
                    continue
                try:
                    idx = int(cmd.split()[1]) - 1
                    if 0 <= idx < len(sensitive_data):
                        if copy_to_clipboard(sensitive_data[idx][1]):
                            print(f"   ✓ Copied {sensitive_data[idx][0]}")
                    else:
                        print("   ❌ Invalid number")
                except (ValueError, IndexError):
                    print("   ❌ Usage: copy N (N is the item number)")
    
    print("\n" + "=" * 60)
    print("\n⚠️  Security Reminders:")
    print("   1. Immediately write down or save private key/mnemonic offline")
    print("   2. Never screenshot or transmit over network")
    print("   3. Recommend using in offline environment")
    print("   4. Verify address on testnet before using")
    print("=" * 60)


# ============================================================
# Main Program
# ============================================================

def main():
    global g_state
    global NETWORK_CHECK_MODE, ENABLE_CLIPBOARD, DEBUG

    parser = argparse.ArgumentParser(add_help=True)
    parser.add_argument(
        "--network-check",
        choices=["passive", "active", "skip"],
        default="passive",
        help="Network check mode: passive=no outbound (default), active=outbound probe, skip=disable check",
    )
    parser.add_argument(
        "--no-clipboard",
        action="store_true",
        help="Disable clipboard copy (reduces sensitive data exposure)",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Print full tracebacks (may include sensitive data)",
    )
    args = parser.parse_args()

    NETWORK_CHECK_MODE = args.network_check
    ENABLE_CLIPBOARD = not args.no_clipboard
    DEBUG = args.debug
    
    if not LIBS_AVAILABLE:
        return
    
    g_state.reset()
    
    print("\n" + "=" * 60)
    print("     🚀 Multi-process Mnemonic/Private Key Vanity Generator")
    print("=" * 60)
    
    # Environment security check
    print("\n🔍 Running environment security check...")
    is_secure, warnings = check_environment()
    
    for w in warnings:
        print(f"   {w}")
    
    if g_state.interrupted:
        return
    
    if not is_secure:
        print("\n⚠️  Security risks detected, continue?")
        if not safe_input_yn("[y/N]: "):
            print("Cancelled")
            return
    
    if g_state.interrupted:
        return
    
    # Basic configuration
    target = safe_input("\nEnter target suffix (e.g. 888, ABC): ").strip()
    if g_state.interrupted:
        return
    if not target:
        print("❌ Suffix cannot be empty")
        return
    
    hex_chars = set("0123456789abcdefABCDEF")
    base58_chars = set("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz")
    
    is_valid_hex = all(c in hex_chars for c in target)
    is_valid_base58 = all(c in base58_chars for c in target)
    
    if not is_valid_hex and not is_valid_base58:
        print("❌ Suffix contains invalid characters")
        return
    
    print("\n📋 Select generation mode:")
    print("   1. Mnemonic mode (12 words, secure & recoverable) [Default]")
    print("   2. Private key mode (random private key, faster)")
    mode = safe_input("Select [1/2] (Press Enter for 1): ").strip()
    if g_state.interrupted:
        return
    use_mnemonic = (mode != "2")
    
    print("\n📋 Select networks to generate (enter y to confirm):")
    c_eth = safe_input_yn("   1. Ethereum ETH (incl. BSC/Polygon etc.) [y/N]: ")
    if g_state.interrupted:
        return
    c_trx = safe_input_yn("   2. Tron TRX [y/N]: ")
    if g_state.interrupted:
        return
    c_sol = safe_input_yn("   3. Solana SOL [y/N]: ")
    if g_state.interrupted:
        return
    
    if not any([c_eth, c_trx, c_sol]):
        print("❌ Select at least one network!")
        return
    
    selected_count = sum([c_eth, c_trx, c_sol])
    shared_mode = False
    
    if selected_count >= 2:
        if use_mnemonic:
            print("\n📋 Select matching mode:")
            print("   1. Shared mnemonic - One mnemonic satisfies all network suffixes [Default]")
            print("   2. Independent generation - Generate mnemonic separately for each network")
            share_choice = safe_input("Select [1/2] (Press Enter for 1): ").strip()
            if g_state.interrupted:
                return
            shared_mode = (share_choice != "2")
        else:
            if c_eth and c_trx:
                print("\n📋 Select matching mode:")
                print("   1. Independent generation - Generate private key separately for each network [Default]")
                print("   2. Shared private key - ETH and TRX share one private key")
                share_choice = safe_input("Select [1/2] (Press Enter for 1): ").strip()
                if g_state.interrupted:
                    return
                shared_mode = (share_choice == "2")
    
    cpu_cores = os.cpu_count() or 4
    
    # Calculate tasks
    tasks = []
    
    if use_mnemonic:
        if shared_mode:
            combined_exp = 1
            chains = []
            if c_eth:
                _, exp = calculate_single_probability(target, "ETH")
                combined_exp *= exp
                chains.append('ETH')
            if c_trx:
                _, exp = calculate_single_probability(target, "TRX")
                combined_exp *= exp
                chains.append('TRX')
            if c_sol:
                _, exp = calculate_single_probability(target, "SOL")
                combined_exp *= exp
                chains.append('SOL')
            tasks.append({'name': '+'.join(chains), 'chains': chains, 'expected': combined_exp, 'type': 'mnemonic_shared'})
        else:
            if c_eth:
                _, exp = calculate_single_probability(target, "ETH")
                tasks.append({'name': 'ETH', 'chains': ['ETH'], 'expected': exp, 'type': 'mnemonic_single'})
            if c_trx:
                _, exp = calculate_single_probability(target, "TRX")
                tasks.append({'name': 'TRX', 'chains': ['TRX'], 'expected': exp, 'type': 'mnemonic_single'})
            if c_sol:
                _, exp = calculate_single_probability(target, "SOL")
                tasks.append({'name': 'SOL', 'chains': ['SOL'], 'expected': exp, 'type': 'mnemonic_single'})
    else:
        if shared_mode and c_eth and c_trx:
            _, exp_eth = calculate_single_probability(target, "ETH")
            _, exp_trx = calculate_single_probability(target, "TRX")
            tasks.append({'name': 'ETH+TRX', 'chains': ['ETH', 'TRX'], 'expected': exp_eth * exp_trx, 'type': 'privkey_shared'})
            if c_sol:
                _, exp = calculate_single_probability(target, "SOL")
                tasks.append({'name': 'SOL', 'chains': ['SOL'], 'expected': exp, 'type': 'privkey_single'})
        else:
            if c_eth:
                _, exp = calculate_single_probability(target, "ETH")
                tasks.append({'name': 'ETH', 'chains': ['ETH'], 'expected': exp, 'type': 'privkey_single'})
            if c_trx:
                _, exp = calculate_single_probability(target, "TRX")
                tasks.append({'name': 'TRX', 'chains': ['TRX'], 'expected': exp, 'type': 'privkey_single'})
            if c_sol:
                _, exp = calculate_single_probability(target, "SOL")
                tasks.append({'name': 'SOL', 'chains': ['SOL'], 'expected': exp, 'type': 'privkey_single'})
    
    cores_per_task = max(1, cpu_cores // len(tasks))
    
    # Display configuration
    print("\n" + "=" * 60)
    print("⚙️  Configuration Confirmation:")
    print(f"   Target suffix: {target}")
    print(f"   Generation mode: {'📝 Mnemonic' if use_mnemonic else '🔑 Private Key'}")
    print(f"   Matching mode: {'🔗 Shared' if shared_mode else '📦 Independent'}")
    print(f"   Selected networks: {'ETH ' if c_eth else ''}{'TRX ' if c_trx else ''}{'SOL ' if c_sol else ''}")
    print(f"   CPU cores: {cpu_cores} cores")
    
    print("\n📊 Task Analysis:")
    total_max_time = 0
    est_speed_base = 80 if use_mnemonic else 800
    
    for task in tasks:
        task_speed = est_speed_base * cores_per_task
        task_time = task['expected'] / task_speed
        total_max_time = max(total_max_time, task_time)
        
        exp = task['expected']
        prob_str = f"1/{exp:.2e}" if exp >= 1e12 else f"1/{exp:,}"
        
        print(f"   [{task['name']:12}] Prob {prob_str:>15} | ~{cores_per_task} cores | Est. {format_time(task_time)}")
    
    print(f"\n   ⏱️  Total estimated time: ~{format_time(total_max_time)}")
    print("=" * 60)
    
    if total_max_time > 86400 * 365:
        print("\n⚠️  Warning: Estimated time exceeds 1 year!")
        if not safe_input_yn("\nContinue? [y/N]: "):
            print("Cancelled")
            return
    
    if g_state.interrupted:
        return
    
    safe_input("\nPress Enter to start generation... (Ctrl+C to safely stop anytime)")
    if g_state.interrupted:
        return
    
    # Initialization
    g_state.result_queue = Queue()
    g_state.start_time = time.time()
    g_state.is_running = True
    
    try:
        print("\n🚀 Starting worker processes...")
        
        for task in tasks:
            task_name = task['name']
            stop_event = Event()
            counter = Value(ctypes.c_longlong, 0)
            lock = multiprocessing.Lock()
            
            g_state.task_info[task_name] = {
                'stop_event': stop_event,
                'counter': counter,
                'lock': lock,
                'expected': task['expected'],
                'done': False,
            }
            
            for _ in range(cores_per_task):
                if task['type'] == 'mnemonic_shared':
                    worker = worker_mnemonic_shared
                    args = (target, stop_event, counter, lock, g_state.result_queue, c_eth, c_trx, c_sol, MAX_CONSECUTIVE_ERRORS)
                elif task['type'] == 'mnemonic_single':
                    worker = {'ETH': worker_eth_mnemonic, 'TRX': worker_trx_mnemonic, 'SOL': worker_sol_mnemonic}[task['chains'][0]]
                    args = (target, stop_event, counter, lock, g_state.result_queue, MAX_CONSECUTIVE_ERRORS)
                elif task['type'] == 'privkey_shared':
                    worker = worker_eth_trx_shared_privkey
                    args = (target, stop_event, counter, lock, g_state.result_queue, c_eth, c_trx, MAX_CONSECUTIVE_ERRORS)
                else:
                    worker = {'ETH': worker_eth_privkey, 'TRX': worker_trx_privkey, 'SOL': worker_sol_privkey}[task['chains'][0]]
                    args = (target, stop_event, counter, lock, g_state.result_queue, MAX_CONSECUTIVE_ERRORS)
                
                p = multiprocessing.Process(target=worker, args=args)
                p.daemon = True
                p.start()
                g_state.processes.append((p, task_name))
        
        time.sleep(0.5)
        alive_count = sum(1 for p, _ in g_state.processes if p.is_alive())
        print(f"   ✓ Started {alive_count}/{len(g_state.processes)} worker processes")
        
        if alive_count == 0:
            print("\n❌ All worker processes failed to start!")
            g_state.is_running = False
            return
        
        print("\n" + "-" * 60)
        print("💡 Tip: Press Ctrl+C to safely stop and keep existing results")
        print("-" * 60 + "\n")
        
        for _ in g_state.task_info:
            print()
        
        # Monitoring loop
        last_counts = {name: 0 for name in g_state.task_info}
        last_time = g_state.start_time
        speeds = {name: [] for name in g_state.task_info}
        
        while not g_state.interrupted:
            time.sleep(0.5)
            current_time = time.time()
            elapsed = current_time - g_state.start_time
            delta_time = current_time - last_time
            
            # Collect results
            try:
                while True:
                    item = g_state.result_queue.get_nowait()
                    if item.get('error'):
                        g_state.collected_errors.append(item)
                    else:
                        chain = item.get('chain', 'UNKNOWN')
                        g_state.collected_results[chain] = item
                        for name, info in g_state.task_info.items():
                            if chain in name or chain == 'SHARED_MNEMONIC' or chain == 'ETH_TRX_SHARED':
                                info['done'] = True
                                info['finish_time'] = elapsed
                                info['stop_event'].set()
            except Exception:
                pass
            
            all_done = True
            status_lines = []
            
            for task_name, info in g_state.task_info.items():
                if info['stop_event'].is_set() or info.get('done'):
                    if not info.get('done'):
                        info['done'] = True
                        info['finish_time'] = elapsed
                    status = f"✅ Done! ({format_time(info.get('finish_time', 0))})"
                else:
                    all_done = False
                    current_count = info['counter'].value
                    delta_count = current_count - last_counts[task_name]
                    current_speed = delta_count / delta_time if delta_time > 0 else 0
                    
                    speeds[task_name].append(current_speed)
                    if len(speeds[task_name]) > 10:
                        speeds[task_name].pop(0)
                    avg_speed = sum(speeds[task_name]) / len(speeds[task_name]) if speeds[task_name] else 0
                    
                    if avg_speed > 0:
                        remaining = max(0, info['expected'] - current_count)
                        eta_str = format_time(remaining / avg_speed)
                    else:
                        eta_str = "Calculating..."
                    
                    bar = progress_bar(current_count, info['expected'], 15)
                    status = f"{bar} | {format_number(avg_speed)}/s | ETA: {eta_str}"
                    last_counts[task_name] = current_count
                
                status_lines.append(f"   {task_name[:12].ljust(12)} {status}")
            
            sys.stdout.write(f"\033[{len(status_lines)+1}A")
            print(f"⏱️  Runtime: {format_time(elapsed):<50}")
            for line in status_lines:
                print(f"{line:<75}")
            sys.stdout.flush()
            
            last_time = current_time
            
            if all_done:
                break
            
            if sum(1 for p, _ in g_state.processes if p.is_alive()) == 0:
                time.sleep(0.3)
                collect_remaining_results()
                break
    
    except Exception as e:
        print(f"\n\n❌ Error occurred: {e}")
        if DEBUG:
            traceback.print_exc()
        else:
            print("   (use --debug for traceback)")
    
    finally:
        g_state.is_running = False
        final_time = time.time() - g_state.start_time
        
        cleanup_processes()
        collect_remaining_results()
        
        if g_state.interrupted:
            print(f"\n⚠️  Program interrupted by user, ran for: {format_time(final_time)}")
        
        display_results(g_state.collected_results, g_state.collected_errors, final_time, g_state.interrupted)
        gc.collect()
        print("\n✅ Program exited safely")


if __name__ == "__main__":
    multiprocessing.freeze_support()
    
    try:
        if sys.platform == 'win32':
            multiprocessing.set_start_method('spawn', force=True)
        else:
            multiprocessing.set_start_method('fork', force=True)
    except RuntimeError:
        pass
    
    main()
