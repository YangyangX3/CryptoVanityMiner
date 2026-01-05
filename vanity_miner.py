#!/usr/bin/env python3
"""
🔐 安全加固版 - 多进程助记词/私钥靓号生成器 v3.2
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

# 第三方库
try:
    from mnemonic import Mnemonic
    from bip_utils import (
        Bip39SeedGenerator, Bip44, Bip44Coins, Bip44Changes,
        Secp256k1PrivateKey, Ed25519PrivateKey,
        EthAddrEncoder, TrxAddrEncoder, SolAddrEncoder
    )
    LIBS_AVAILABLE = True
except ImportError as e:
    print(f"❌ 缺少必要依赖: {e}")
    print("请运行: pip install mnemonic bip-utils")
    LIBS_AVAILABLE = False


# ============================================================
# 全局状态管理
# ============================================================

class GlobalState:
    """全局状态管理器"""
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
    """全局信号处理器"""
    g_state.interrupted = True
    
    if g_state.is_running:
        print("\n\n" + "=" * 60)
        print("⏹️  收到中断信号，正在安全停止...")
        print("=" * 60)
        
        for info in g_state.task_info.values():
            try:
                info['stop_event'].set()
            except Exception:
                pass
    else:
        print("\n\n⏹️  程序已中断")
        sys.exit(0)


signal.signal(signal.SIGINT, graceful_exit_handler)
if hasattr(signal, 'SIGTERM'):
    signal.signal(signal.SIGTERM, graceful_exit_handler)


# ============================================================
# 常量配置
# ============================================================
MAX_CONSECUTIVE_ERRORS = 100
SHOW_PARTIAL_CHARS = 4

# 运行时安全配置（可通过命令行参数覆盖）
NETWORK_CHECK_MODE = "passive"  # passive|active|skip
ENABLE_CLIPBOARD = True
DEBUG = False


# ============================================================
# 网络检测 (Windows 修复版)
# ============================================================

def check_network_connection() -> Tuple[bool, str]:
    """
    检测网络连接状态 - 跨平台修复版
    默认使用 passive 模式（不发起外部连接）
    """
    import socket
    
    mode = (NETWORK_CHECK_MODE or "passive").strip().lower()

    if mode == "skip":
        return False, "已跳过网络检测"

    if mode != "active":
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(0.3)
            # UDP connect 不会发送数据包，仅触发本地路由选择
            sock.connect(("8.8.8.8", 80))
            local_ip = sock.getsockname()[0]

            if not local_ip or local_ip == "0.0.0.0" or local_ip.startswith("127."):
                return False, "未检测到有效的网络接口"

            if local_ip.startswith("169.254."):
                return True, f"检测到链路本地地址 {local_ip} (可能无公网)"

            return True, f"检测到网络接口配置 ({local_ip})"
        except OSError:
            return False, "未检测到有效的网络接口"
        except Exception:
            return False, "未检测到有效的网络接口"
        finally:
            try:
                if sock is not None:
                    sock.close()
            except Exception:
                pass

    # active: 测试目标列表 (DNS 服务器，端口 53)
    test_targets = [
        ("8.8.8.8", 53),        # Google DNS
        ("1.1.1.1", 53),        # Cloudflare DNS
        ("223.5.5.5", 53),      # 阿里 DNS
        ("114.114.114.114", 53), # 114 DNS
    ]

    for host, port in test_targets:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.3)  # 300ms 超时，断网时会快速失败
            result = sock.connect_ex((host, port))
            sock.close()

            if result == 0:
                return True, f"检测到网络连接 (可访问 {host})"
        except socket.timeout:
            continue
        except OSError:
            continue
        except Exception:
            continue

    # 所有目标都无法连接
    return False, "未检测到网络连接"


def check_system_entropy() -> Tuple[bool, str]:
    """检查系统熵池状态"""
    try:
        with open('/proc/sys/kernel/random/entropy_avail', 'r') as f:
            entropy = int(f.read().strip())
            if entropy < 256:
                return False, f"系统熵不足: {entropy} bits"
            return True, f"系统熵池健康: {entropy} bits"
    except FileNotFoundError:
        pass
    
    try:
        test_bytes = secrets.token_bytes(1000)
        unique_bytes = len(set(test_bytes))
        if unique_bytes < 200:
            return False, "随机数分布异常"
        return True, "随机数生成器正常"
    except Exception as e:
        return False, f"熵检查失败: {e}"


def verify_randomness(data: bytes) -> bool:
    """验证数据的随机性"""
    if len(data) < 16:
        return False
    if all(b == 0 for b in data) or all(b == 255 for b in data):
        return False
    unique = len(set(data))
    min_unique = max(2, len(data) // 8)
    return unique >= min_unique


def check_environment() -> Tuple[bool, List[str]]:
    """运行环境安全检查"""
    warnings = []
    is_secure = True
    
    # 调试器检查
    if hasattr(sys, 'gettrace') and sys.gettrace() is not None:
        warnings.append("⚠️  检测到调试器附加")
        is_secure = False
    
    # 网络检查
    print("   正在检测网络状态...", end="", flush=True)
    has_network, network_msg = check_network_connection()
    print("\r" + " " * 40 + "\r", end="")  # 清除检测提示
    
    if has_network:
        warnings.append(f"💡 {network_msg}，建议断网后运行以获得最高安全性")
    else:
        warnings.append(f"✓ {network_msg} (离线模式，安全)")
    
    # 熵源检查
    entropy_ok, entropy_msg = check_system_entropy()
    if not entropy_ok:
        warnings.append(f"⚠️  {entropy_msg}")
        is_secure = False
    
    return is_secure, warnings


def hash_address(address: str) -> str:
    """计算地址哈希"""
    return hashlib.sha256(address.encode()).hexdigest()


# ============================================================
# 格式化工具
# ============================================================

def format_time(seconds: float) -> str:
    if seconds < 0:
        return "已完成"
    if seconds < 60:
        return f"{seconds:.1f}秒"
    elif seconds < 3600:
        return f"{seconds/60:.1f}分钟"
    elif seconds < 86400:
        return f"{seconds/3600:.1f}小时"
    elif seconds < 31536000:
        return f"{seconds/86400:.1f}天"
    else:
        return f"{seconds/31536000:.2f}年"


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
# 安全输入函数
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
# 密钥验证器
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
# 工作进程函数
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
# 进程管理
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
# 安全显示
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
        print("   ❌ 剪贴板功能已禁用 (--no-clipboard)")
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
                raise FileNotFoundError("未找到 xclip/xsel")
        return True
    except Exception as e:
        print(f"   ❌ 剪贴板操作失败: {e}")
        return False


def display_results(results: Dict, errors: List, final_time: float, 
                    was_interrupted: bool = False) -> None:
    print("\n" + "=" * 60)
    print("📋 生成结果:")
    print("=" * 60)
    
    has_result = False
    sensitive_data = []
    
    if 'SHARED_MNEMONIC' in results:
        has_result = True
        data = results['SHARED_MNEMONIC']
        print(f"\n🔗 共用助记词模式:")
        display_sensitive("助记词", data['mnemonic'])
        sensitive_data.append(('助记词', data['mnemonic']))
        print(f"   ---")
        if data.get('eth_address'):
            print(f"   ETH地址: {data['eth_address']}")
        if data.get('trx_address'):
            print(f"   TRX地址: {data['trx_address']}")
        if data.get('sol_address'):
            print(f"   SOL地址: {data['sol_address']}")
    
    if 'ETH_TRX_SHARED' in results:
        has_result = True
        data = results['ETH_TRX_SHARED']
        print(f"\n🔗 ETH+TRX共用私钥:")
        display_sensitive("私钥", data['private_key'])
        sensitive_data.append(('私钥', data['private_key']))
        if data.get('eth_address'):
            print(f"   ETH地址: {data['eth_address']}")
        if data.get('trx_address'):
            print(f"   TRX地址: {data['trx_address']}")
    
    chain_icons = {'ETH': '🔷', 'TRX': '🔴', 'SOL': '🟣'}
    chain_names = {'ETH': '以太坊', 'TRX': '波场', 'SOL': 'Solana'}
    
    for chain in ['ETH', 'TRX', 'SOL']:
        if chain in results:
            has_result = True
            data = results[chain]
            print(f"\n{chain_icons[chain]} {chain_names[chain]} ({chain}):")
            print(f"   地址: {data['address']}")
            
            if 'private_key' in data:
                display_sensitive("私钥", data['private_key'])
                sensitive_data.append((f'{chain}私钥', data['private_key']))
            if 'mnemonic' in data:
                display_sensitive("助记词", data['mnemonic'])
                sensitive_data.append((f'{chain}助记词', data['mnemonic']))
    
    if not has_result:
        if was_interrupted:
            print("\n⚠️  程序被中断，未找到匹配结果")
        else:
            print("\n⚠️  未找到匹配结果")
        if errors:
            print("\n发生的错误:")
            for err in errors:
                print(f"   - {err.get('chain')}: {err.get('message')}")
    
    print("\n" + "=" * 60)
    print(f"⏱️  总耗时: {format_time(final_time)}")
    
    if has_result and sensitive_data:
        print("\n" + "-" * 60)
        print("🔐 敏感数据操作:")
        print("   输入 'show' 查看完整内容")
        print("   输入 'copy N' 复制第N项到剪贴板")
        print("   输入回车或 'exit' 退出")
        print("-" * 60)
        
        for i, (label, _) in enumerate(sensitive_data, 1):
            print(f"   {i}. {label}")
        
        while True:
            cmd = safe_input("\n请输入命令: ").strip().lower()
            if g_state.interrupted or cmd == 'exit' or cmd == '':
                break
            elif cmd == 'show':
                print("\n⚠️  警告: 即将显示敏感信息，请确保周围安全")
                confirm = safe_input("确认显示? [y/N]: ").strip().lower()
                if confirm == 'y':
                    for label, value in sensitive_data:
                        print(f"   {label}: {value}")
            elif cmd.startswith('copy '):
                if not ENABLE_CLIPBOARD:
                    print("   ❌ 剪贴板功能已禁用 (--no-clipboard)")
                    continue
                try:
                    idx = int(cmd.split()[1]) - 1
                    if 0 <= idx < len(sensitive_data):
                        if copy_to_clipboard(sensitive_data[idx][1]):
                            print(f"   ✓ 已复制 {sensitive_data[idx][0]}")
                    else:
                        print("   ❌ 无效的序号")
                except (ValueError, IndexError):
                    print("   ❌ 使用方法: copy N (N为序号)")
    
    print("\n" + "=" * 60)
    print("\n⚠️  安全提示:")
    print("   1. 立即手抄或离线保存私钥/助记词")
    print("   2. 切勿截图或通过网络传输")
    print("   3. 建议在离线环境中使用")
    print("   4. 使用前在测试网验证地址可用")
    print("=" * 60)


# ============================================================
# 主程序
# ============================================================

def main():
    global g_state
    global NETWORK_CHECK_MODE, ENABLE_CLIPBOARD, DEBUG

    parser = argparse.ArgumentParser(add_help=True)
    parser.add_argument(
        "--network-check",
        choices=["passive", "active", "skip"],
        default="passive",
        help="网络检测模式：passive=不外联(默认)，active=主动外联探测，skip=跳过检测",
    )
    parser.add_argument(
        "--no-clipboard",
        action="store_true",
        help="禁用复制到剪贴板功能（降低敏感信息泄露面）",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="打印详细异常堆栈（可能包含敏感信息）",
    )
    args = parser.parse_args()

    NETWORK_CHECK_MODE = args.network_check
    ENABLE_CLIPBOARD = not args.no_clipboard
    DEBUG = args.debug
    
    if not LIBS_AVAILABLE:
        return
    
    g_state.reset()
    
    print("\n" + "=" * 60)
    print("     🚀 多进程助记词/私钥靓号生成器")
    print("=" * 60)
    
    # 环境安全检查
    print("\n🔍 运行环境安全检查...")
    is_secure, warnings = check_environment()
    
    for w in warnings:
        print(f"   {w}")
    
    if g_state.interrupted:
        return
    
    if not is_secure:
        print("\n⚠️  检测到安全风险，是否继续？")
        if not safe_input_yn("[y/N]: "):
            print("已取消")
            return
    
    if g_state.interrupted:
        return
    
    # 基本配置
    target = safe_input("\n请输入目标尾号 (例如 888, ABC): ").strip()
    if g_state.interrupted:
        return
    if not target:
        print("❌ 尾号不能为空")
        return
    
    hex_chars = set("0123456789abcdefABCDEF")
    base58_chars = set("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz")
    
    is_valid_hex = all(c in hex_chars for c in target)
    is_valid_base58 = all(c in base58_chars for c in target)
    
    if not is_valid_hex and not is_valid_base58:
        print("❌ 尾号包含无效字符")
        return
    
    print("\n📋 选择生成模式:")
    print("   1. 助记词模式 (12词，安全可恢复) [默认]")
    print("   2. 私钥模式   (随机私钥，速度快)")
    mode = safe_input("请选择 [1/2] (直接回车选1): ").strip()
    if g_state.interrupted:
        return
    use_mnemonic = (mode != "2")
    
    print("\n📋 选择要生成的网络 (输入 y 确认):")
    c_eth = safe_input_yn("   1. 以太坊 ETH (含BSC/Polygon等) [y/N]: ")
    if g_state.interrupted:
        return
    c_trx = safe_input_yn("   2. 波场 TRX [y/N]: ")
    if g_state.interrupted:
        return
    c_sol = safe_input_yn("   3. Solana SOL [y/N]: ")
    if g_state.interrupted:
        return
    
    if not any([c_eth, c_trx, c_sol]):
        print("❌ 至少选择一个网络！")
        return
    
    selected_count = sum([c_eth, c_trx, c_sol])
    shared_mode = False
    
    if selected_count >= 2:
        if use_mnemonic:
            print("\n📋 选择匹配模式:")
            print("   1. 共用助记词 - 一个助记词满足所有网络尾号 [默认]")
            print("   2. 独立生成   - 每个网络单独生成助记词")
            share_choice = safe_input("请选择 [1/2] (直接回车选1): ").strip()
            if g_state.interrupted:
                return
            shared_mode = (share_choice != "2")
        else:
            if c_eth and c_trx:
                print("\n📋 选择匹配模式:")
                print("   1. 独立生成   - 每个网络单独生成私钥 [默认]")
                print("   2. 共用私钥   - ETH和TRX共用一个私钥")
                share_choice = safe_input("请选择 [1/2] (直接回车选1): ").strip()
                if g_state.interrupted:
                    return
                shared_mode = (share_choice == "2")
    
    cpu_cores = os.cpu_count() or 4
    
    # 计算任务
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
    
    # 显示配置
    print("\n" + "=" * 60)
    print("⚙️  配置确认:")
    print(f"   目标尾号: {target}")
    print(f"   生成模式: {'📝 助记词' if use_mnemonic else '🔑 私钥'}")
    print(f"   匹配模式: {'🔗 共用' if shared_mode else '📦 独立'}")
    print(f"   选中网络: {'ETH ' if c_eth else ''}{'TRX ' if c_trx else ''}{'SOL ' if c_sol else ''}")
    print(f"   CPU核心: {cpu_cores} 核")
    
    print("\n📊 任务分析:")
    total_max_time = 0
    est_speed_base = 80 if use_mnemonic else 800
    
    for task in tasks:
        task_speed = est_speed_base * cores_per_task
        task_time = task['expected'] / task_speed
        total_max_time = max(total_max_time, task_time)
        
        exp = task['expected']
        prob_str = f"1/{exp:.2e}" if exp >= 1e12 else f"1/{exp:,}"
        
        print(f"   [{task['name']:12}] 概率 {prob_str:>15} | ~{cores_per_task}核 | 预计 {format_time(task_time)}")
    
    print(f"\n   ⏱️  总预计时间: ~{format_time(total_max_time)}")
    print("=" * 60)
    
    if total_max_time > 86400 * 365:
        print("\n⚠️  警告：预计时间超过1年！")
        if not safe_input_yn("\n是否继续？[y/N]: "):
            print("已取消")
            return
    
    if g_state.interrupted:
        return
    
    safe_input("\n按回车键开始生成... (Ctrl+C 可随时安全停止)")
    if g_state.interrupted:
        return
    
    # 初始化
    g_state.result_queue = Queue()
    g_state.start_time = time.time()
    g_state.is_running = True
    
    try:
        print("\n🚀 启动工作进程...")
        
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
        print(f"   ✓ 已启动 {alive_count}/{len(g_state.processes)} 个工作进程")
        
        if alive_count == 0:
            print("\n❌ 所有工作进程启动失败！")
            g_state.is_running = False
            return
        
        print("\n" + "-" * 60)
        print("💡 提示: 按 Ctrl+C 可随时安全停止并保留已有结果")
        print("-" * 60 + "\n")
        
        for _ in g_state.task_info:
            print()
        
        # 监控循环
        last_counts = {name: 0 for name in g_state.task_info}
        last_time = g_state.start_time
        speeds = {name: [] for name in g_state.task_info}
        
        while not g_state.interrupted:
            time.sleep(0.5)
            current_time = time.time()
            elapsed = current_time - g_state.start_time
            delta_time = current_time - last_time
            
            # 收集结果
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
                    status = f"✅ 完成! ({format_time(info.get('finish_time', 0))})"
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
                        eta_str = "计算中..."
                    
                    bar = progress_bar(current_count, info['expected'], 15)
                    status = f"{bar} | {format_number(avg_speed)}/s | ETA: {eta_str}"
                    last_counts[task_name] = current_count
                
                status_lines.append(f"   {task_name[:12].ljust(12)} {status}")
            
            sys.stdout.write(f"\033[{len(status_lines)+1}A")
            print(f"⏱️  运行时间: {format_time(elapsed):<50}")
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
        print(f"\n\n❌ 发生错误: {e}")
        if DEBUG:
            traceback.print_exc()
        else:
            print("   (使用 --debug 查看详细堆栈)")
    
    finally:
        g_state.is_running = False
        final_time = time.time() - g_state.start_time
        
        cleanup_processes()
        collect_remaining_results()
        
        if g_state.interrupted:
            print(f"\n⚠️  程序被用户中断，已运行: {format_time(final_time)}")
        
        display_results(g_state.collected_results, g_state.collected_errors, final_time, g_state.interrupted)
        gc.collect()
        print("\n✅ 程序已安全退出")


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
