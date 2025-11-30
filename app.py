import os
import re
import json
import time
import hmac
import uuid
import base64
import logging
import hashlib
import threading
import queue
import random
import string
import concurrent.futures
from typing import Optional, Dict, List, Tuple
from datetime import datetime, timedelta, timezone
from dataclasses import dataclass, field
from functools import wraps

import requests
import urllib3
from flask import Flask, request, Response, jsonify
from flask_cors import CORS

# 禁用SSL警告
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ==================== 全局配置 ====================
CONFIG = {
    # 开放端口
    "port": os.getenv("PORT", "3000"),
    
    # 管理员密钥（优先从环境变量读取）
    "admin_key": os.getenv("ADMIN_KEY", "admin123"),
    
    # 注册服务URL前缀（从环境变量读取）
    "register_service_url": os.getenv("REGISTER_SERVICE_URL", "http://localhost:5000"),

    # 注册服务管理员密钥（从环境变量读取）
    "register_admin_key": os.getenv("REGISTER_ADMIN_KEY", "sk-admin-token"),
    
    # 账号生命周期（秒）- 默认12小时
    "account_lifetime": int(os.getenv("ACCOUNT_LIFETIME", 43200)),
    
    # 提前刷新时间（秒）- 默认1小时
    "refresh_before_expiry": int(os.getenv("REFRESH_BEFORE_EXPIRY", 3600)),
    
    # 最大重试次数
    "max_retries": int(os.getenv("MAX_RETRIES", 10)),
    
    # 刷新失败禁用时间（秒）- 默认12小时
    "refresh_fail_disable_time": int(os.getenv("REFRESH_FAIL_DISABLE_TIME", 43200)),
    
    # 并发刷新数量 - 默认4
    "max_concurrent_refresh": int(os.getenv("MAX_CONCURRENT_REFRESH", 4)),
    
    # 每个账号请求次数后切换 - 默认5
    "requests_per_account": int(os.getenv("REQUESTS_PER_ACCOUNT", 5)),
    
    # 刷新最大重试次数 - 默认2
    "max_refresh_retries": int(os.getenv("MAX_REFRESH_RETRIES", 2)),
    
    # 自动创建账号开关 - 默认关闭
    "auto_create_account": os.getenv("AUTO_CREATE_ACCOUNT", "false").lower() == "true",
    
    # 自动创建账号间隔（秒）- 默认1小时
    "auto_create_interval": int(os.getenv("AUTO_CREATE_INTERVAL", 3600)),
    
    # 模型映射配置
    "models": {
        "gemini-2.5-flash": {"base": "gemini-2.5-flash", "tools": {}},
        "gemini-2.5-flash-search": {"base": "gemini-2.5-flash", "tools": {"webGroundingSpec": {}}},
        "gemini-2.5-pro": {"base": "gemini-2.5-pro", "tools": {}},
        "gemini-2.5-pro-search": {"base": "gemini-2.5-pro", "tools": {"webGroundingSpec": {}}},
        "gemini-3-pro-preview": {"base": "gemini-3-pro-preview", "tools": {}},
        "gemini-3-pro-preview-search": {"base": "gemini-3-pro-preview", "tools": {"webGroundingSpec": {}}},
        "banana-pro": {"base": "gemini-3-pro-preview", "tools": {"imageGenerationSpec": {}}},
    },
    
    # 账号冷却时间配置（秒）
    "cooldown": {
        "auth_error": 900,
        "rate_limit": 300,
        "generic_error": 120,
    },
    
    # JWT有效期（秒）
    "jwt_lifetime": 240,
    
    # 日志级别
    "log_level": os.getenv("LOG_LEVEL", "INFO"),
}

# API端点
API_ENDPOINTS = {
    "base": "https://biz-discoveryengine.googleapis.com/v1alpha/locations/global",
    "create_session": "https://biz-discoveryengine.googleapis.com/v1alpha/locations/global/widgetCreateSession",
    "stream_assist": "https://biz-discoveryengine.googleapis.com/v1alpha/locations/global/widgetStreamAssist",
    "add_context_file": "https://biz-discoveryengine.googleapis.com/v1alpha/locations/global/widgetAddContextFile",
    "list_file_metadata": "https://biz-discoveryengine.googleapis.com/v1alpha/locations/global/widgetListSessionFileMetadata",
    "get_oxsrf": "https://business.gemini.google/auth/getoxsrf",
}

# ==================== 日志配置 ====================
def setup_logger():
    """配置日志系统"""
    logger = logging.getLogger("BusinessGemini")
    logger.setLevel(getattr(logging, CONFIG["log_level"].upper(), logging.INFO))
    
    if not logger.handlers:
        handler = logging.StreamHandler()
        formatter = logging.Formatter(
            "[%(asctime)s] [%(levelname)s] %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)
    logging.getLogger('werkzeug').setLevel(logging.ERROR)
    return logger

logger = setup_logger()

# ==================== 异常定义 ====================
class AccountError(Exception):
    """账号相关基础异常"""
    def __init__(self, message: str, status_code: Optional[int] = None):
        super().__init__(message)
        self.status_code = status_code


class AccountAuthError(AccountError):
    """凭证/权限异常 - 需要刷新账号"""
    pass


class AccountRateLimitError(AccountError):
    """配额/限流异常"""
    pass


class AccountRequestError(AccountError):
    """请求异常"""
    pass


class NoAvailableAccountError(AccountError):
    """无可用账号异常"""
    pass

# ==================== 工具函数 ====================
def url_safe_b64encode(data: bytes) -> str:
    """URL安全的Base64编码"""
    return base64.urlsafe_b64encode(data).decode('utf-8').rstrip('=')


def kq_encode(s: str) -> str:
    """模拟JS的kQ函数编码"""
    byte_arr = bytearray()
    for char in s:
        val = ord(char)
        if val > 255:
            byte_arr.append(val & 255)
            byte_arr.append(val >> 8)
        else:
            byte_arr.append(val)
    return url_safe_b64encode(bytes(byte_arr))


def decode_xsrf_token(xsrf_token: str) -> bytes:
    """解码xsrfToken为字节数组"""
    padding = 4 - len(xsrf_token) % 4
    if padding != 4:
        xsrf_token += '=' * padding
    return base64.urlsafe_b64decode(xsrf_token)


def parse_base64_data_url(data_url: str) -> Optional[Dict]:
    """解析base64数据URL"""
    if not data_url or not data_url.startswith("data:"):
        return None
    match = re.match(r"data:([^;]+);base64,(.+)", data_url)
    if match:
        return {"mime_type": match.group(1), "data": match.group(2)}
    return None


def parse_iso_datetime(dt_str: str) -> Optional[datetime]:
    """解析ISO格式时间字符串"""
    if not dt_str:
        return None
    try:
        for fmt in [
            "%Y-%m-%dT%H:%M:%S.%f",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%d %H:%M:%S.%f",
            "%Y-%m-%d %H:%M:%S",
        ]:
            try:
                return datetime.strptime(dt_str.replace('Z', '').split('+')[0], fmt)
            except ValueError:
                continue
        return None
    except:
        return None


def seconds_until_pt_midnight() -> int:
    """计算距离下一个太平洋时间午夜的秒数"""
    try:
        from zoneinfo import ZoneInfo
        pt_tz = ZoneInfo("America/Los_Angeles")
        now_pt = datetime.now(pt_tz)
    except ImportError:
        now_utc = datetime.now(timezone.utc)
        now_pt = now_utc - timedelta(hours=8)
    
    tomorrow = (now_pt + timedelta(days=1)).date()
    midnight_pt = datetime.combine(tomorrow, datetime.min.time())
    if hasattr(now_pt, 'tzinfo') and now_pt.tzinfo:
        midnight_pt = midnight_pt.replace(tzinfo=now_pt.tzinfo)
    delta = (midnight_pt - now_pt).total_seconds()
    return max(0, int(delta))


def get_headers(jwt: str) -> Dict:
    """获取请求头"""
    return {
        "accept": "*/*",
        "accept-encoding": "gzip, deflate, br",
        "authorization": f"Bearer {jwt}",
        "content-type": "application/json",
        "origin": "https://business.gemini.google",
        "referer": "https://business.gemini.google/",
        "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "x-server-timeout": "1800",
    }


def generate_random_username(length: int = 12) -> str:
    """生成随机用户名"""
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))

# ==================== JWT管理模块 ====================
class JWTManager:
    """JWT令牌管理器"""
    
    @staticmethod
    def create_jwt(key_bytes: bytes, key_id: str, csesidx: str) -> str:
        """创建JWT令牌"""
        now = int(time.time())
        
        header = {"alg": "HS256", "typ": "JWT", "kid": key_id}
        payload = {
            "iss": "https://business.gemini.google",
            "aud": "https://biz-discoveryengine.googleapis.com",
            "sub": f"csesidx/{csesidx}",
            "iat": now,
            "exp": now + 300,
            "nbf": now
        }
        
        header_b64 = kq_encode(json.dumps(header, separators=(',', ':')))
        payload_b64 = kq_encode(json.dumps(payload, separators=(',', ':')))
        message = f"{header_b64}.{payload_b64}"
        
        signature = hmac.new(key_bytes, message.encode('utf-8'), hashlib.sha256).digest()
        signature_b64 = url_safe_b64encode(signature)
        
        return f"{message}.{signature_b64}"
    
    @staticmethod
    def fetch_jwt(account: Dict) -> str:
        """获取账号的JWT令牌"""
        secure_c_ses = account.get("secure_c_ses")
        host_c_oses = account.get("host_c_oses")
        csesidx = account.get("csesidx")
        
        if not secure_c_ses or not csesidx:
            raise AccountAuthError("账号缺少secure_c_ses或csesidx")
        
        url = f"{API_ENDPOINTS['get_oxsrf']}?csesidx={csesidx}"
        headers = {
            "accept": "*/*",
            "user-agent": account.get('user_agent', 'Mozilla/5.0'),
            "cookie": f'__Secure-C_SES={secure_c_ses}; __Host-C_OSES={host_c_oses}',
        }
        
        try:
            resp = requests.get(url, headers=headers, timeout=30, verify=False)
        except requests.RequestException as e:
            raise AccountRequestError(f"获取JWT请求失败: {e}")
        
        if resp.status_code == 401:
            raise AccountAuthError("JWT获取失败: 401 未授权", 401)
        
        if resp.status_code != 200:
            JWTManager._handle_error_response(resp, "获取JWT")
        
        text = resp.text
        if text.startswith(")]}'\n") or text.startswith(")]}'"):
            text = text[4:].strip()
        
        try:
            data = json.loads(text)
        except json.JSONDecodeError as e:
            raise AccountAuthError(f"解析JWT响应失败: {e}")
        
        key_id = data.get("keyId")
        xsrf_token = data.get("xsrfToken")
        
        if not key_id or not xsrf_token:
            raise AccountAuthError(f"JWT响应缺少keyId或xsrfToken")
        
        logger.info(f"账号 {csesidx} JWT获取成功")
        key_bytes = decode_xsrf_token(xsrf_token)
        return JWTManager.create_jwt(key_bytes, key_id, csesidx)
    
    @staticmethod
    def _handle_error_response(resp: requests.Response, action: str):
        """处理错误响应"""
        status = resp.status_code
        body = resp.text[:500] if resp.text else ""
        lower_body = body.lower()
        
        if status in (401, 403):
            raise AccountAuthError(f"{action}认证失败: {status}", status)
        if status == 429 or any(kw in lower_body for kw in ["quota", "exceed", "limit"]):
            raise AccountRateLimitError(f"{action}触发限流: {status}", status)
        raise AccountRequestError(f"{action}请求失败: {status}", status)

# ==================== 文件上传与下载模块 ====================
class FileManager:
    """文件管理器，处理上传和下载"""
    
    @staticmethod
    def upload_image(jwt: str, session_name: str, team_id: str, image_data: Dict) -> Optional[str]:
        """上传图片到Gemini，返回fileId"""
        try:
            mime_type = image_data.get("mime_type", "image/png")
            b64_data = image_data.get("data", "")
            
            ext_map = {"image/png": ".png", "image/jpeg": ".jpg", "image/gif": ".gif", "image/webp": ".webp"}
            ext = ext_map.get(mime_type, ".png")
            filename = f"upload_{uuid.uuid4().hex[:8]}{ext}"
            
            body = {
                "addContextFileRequest": {
                    "fileContents": b64_data,
                    "fileName": filename,
                    "mimeType": mime_type,
                    "name": session_name
                },
                "additionalParams": {"token": "-"},
                "configId": team_id
            }
            
            resp = requests.post(
                API_ENDPOINTS["add_context_file"],
                headers=get_headers(jwt),
                json=body,
                timeout=60,
                verify=False
            )
            
            if resp.status_code != 200:
                logger.warning(f"图片上传失败: {resp.status_code}")
                return None
            
            data = resp.json()
            file_id = data.get("addContextFileResponse", {}).get("fileId")
            if file_id:
                logger.info(f"图片上传成功: {file_id}")
            return file_id
            
        except Exception as e:
            logger.error(f"图片上传异常: {e}")
            return None
    
    @staticmethod
    def get_session_file_metadata(jwt: str, session_name: str, team_id: str) -> Dict:
        """获取会话中的文件元数据"""
        body = {
            "configId": team_id,
            "additionalParams": {"token": "-"},
            "listSessionFileMetadataRequest": {
                "name": session_name,
                "filter": "file_origin_type = AI_GENERATED"
            }
        }
        
        try:
            resp = requests.post(
                API_ENDPOINTS["list_file_metadata"],
                headers=get_headers(jwt),
                json=body,
                verify=False,
                timeout=30
            )
            
            if resp.status_code != 200:
                return {}
            
            data = resp.json()
            result = {}
            file_metadata_list = data.get("listSessionFileMetadataResponse", {}).get("fileMetadata", [])
            for meta in file_metadata_list:
                file_id = meta.get("fileId")
                if file_id:
                    result[file_id] = meta
            return result
            
        except Exception as e:
            logger.error(f"获取文件元数据异常: {e}")
            return {}
    
    @staticmethod
    def build_download_url(session_name: str, file_id: str) -> str:
        """构造下载URL"""
        return f"https://biz-discoveryengine.googleapis.com/v1alpha/{session_name}:downloadFile?fileId={file_id}&alt=media"
    
    @staticmethod
    def download_file(jwt: str, session_name: str, file_id: str) -> Optional[bytes]:
        """下载文件"""
        url = FileManager.build_download_url(session_name, file_id)
        
        try:
            resp = requests.get(
                url,
                headers=get_headers(jwt),
                verify=False,
                timeout=120,
                allow_redirects=True
            )
            resp.raise_for_status()
            return resp.content
            
        except Exception as e:
            logger.error(f"文件下载失败 (fileId={file_id}): {e}")
            return None

# ==================== 账号刷新服务 ====================
class AccountRefreshService:
    """账号刷新服务 - 调用注册服务API刷新账号"""
    
    def __init__(self, base_url: str, register_admin_key: str):
        self.base_url = base_url.rstrip('/')
        self.register_admin_key = register_admin_key
    
    def _get_auth_headers(self) -> Dict:
        """获取认证头"""
        credentials = self.register_admin_key
        return {
            "Authorization": f"Bearer {credentials}",
            "Content-Type": "application/json"
        }
    
    def create_account(self, username: Optional[str] = None) -> Optional[Dict]:
        """
        创建新账号
        返回账号信息，失败返回None
        """
        try:
            if not username:
                username = generate_random_username()
            
            url = f"{self.base_url}/api/accounts"
            body = {"username": username}

            logger.info(f"开始创建账号: {username}")
            
            resp = requests.post(url, headers=self._get_auth_headers(), json=body, timeout=120)
            
            if resp.status_code == 429:
                logger.warning(f"创建账号请求被限流")
                return None
            
            if resp.status_code != 200:
                logger.warning(f"创建账号请求失败: {resp.status_code} - {resp.text}")
                return None
            
            data = resp.json()
            if not data.get("success"):
                logger.warning(f"创建账号失败: {data.get('error')}")
                return None
            
            account = data.get("account", {})
            if account.get("status") == "success" and account.get("is_complete"):
                logger.info(f"账号创建成功: {account.get('email')}")
                return {
                    "email": account.get("email"),
                    "secure_c_ses": account.get("c_ses"),
                    "host_c_oses": account.get("c_oses"),
                    "csesidx": account.get("csesidx"),
                    "team_id": account.get("config_id"),
                    "created_at": account.get("created_at"),
                    "updated_at": account.get("updated_at"),
                }
            
            logger.warning(f"账号创建未完成: {account.get('status')}")
            return None
            
        except Exception as e:
            logger.error(f"创建账号异常: {e}")
            return None
    
    def refresh_account(self, email: str, max_wait: int = 300) -> Optional[Dict]:
        """
        请求刷新账号
        返回刷新后的账号信息，失败返回None
        """
        try:
            url = f"{self.base_url}/api/accounts/{email}/refresh"
            resp = requests.post(url, headers=self._get_auth_headers(), timeout=30)
            
            if resp.status_code == 429:
                logger.warning(f"刷新账号请求被限流: {email}")
                return None
            
            if resp.status_code == 404:
                logger.warning(f"邮箱域名未配置，无法刷新: {email}")
                return None
            
            if resp.status_code != 200:
                logger.warning(f"刷新账号请求失败: {resp.status_code} - {resp.text}")
                return None
            
            data = resp.json()
            if not data.get("success"):
                logger.warning(f"刷新账号失败: {data.get('error')}")
                return None
            
            logger.info(f"账号 {email} 刷新请求已发送")
            
            return self._wait_for_refresh(email, max_wait)
            
        except Exception as e:
            logger.error(f"刷新账号异常: {e}")
            return None
    
    def _wait_for_refresh(self, email: str, max_wait: int = 300, interval: int = 5) -> Optional[Dict]:
        """等待刷新完成"""
        start_time = time.time()
        
        while time.time() - start_time < max_wait:
            try:
                url = f"{self.base_url}/api/accounts?email={email}"
                resp = requests.get(url, headers=self._get_auth_headers(), timeout=30)
                
                if resp.status_code == 200:
                    data = resp.json()
                    if data.get("success") and data.get("account"):
                        account = data["account"]
                        status = account.get("status")
                        
                        if status == "success" and account.get("is_complete"):
                            logger.info(f"账号 {email} 刷新成功")
                            return {
                                "email": email,
                                "secure_c_ses": account.get("c_ses"),
                                "host_c_oses": account.get("c_oses"),
                                "csesidx": account.get("csesidx"),
                                "team_id": account.get("config_id"),
                                "updated_at": account.get("updated_at") or datetime.now().isoformat()
                            }
                        elif status == "failed":
                            logger.warning(f"账号 {email} 刷新失败: {account.get('error_message')}")
                            return None
                
                time.sleep(interval)
                
            except Exception as e:
                logger.error(f"等待刷新异常: {e}")
                time.sleep(interval)
        
        logger.warning(f"账号 {email} 刷新超时")
        return None


# ==================== 账号管理模块 ====================
@dataclass
class AccountState:
    """账号状态"""
    jwt: Optional[str] = None
    jwt_time: float = 0
    session: Optional[str] = None
    available: bool = True
    cooldown_until: Optional[float] = None
    cooldown_reason: str = ""
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    needs_refresh: bool = False
    refresh_in_progress: bool = False
    exclude_from_batch_refresh: bool = False
    last_refresh_failed: bool = False
    request_count: int = 0  # 当前账号请求计数
    refresh_retry_count: int = 0  # 刷新重试次数


class AccountManager:
    """账号池管理器 - 支持生命周期管理和并发刷新"""
    
    def __init__(self, refresh_service: AccountRefreshService):
        self.accounts: List[Dict] = []
        self.states: Dict[int, AccountState] = {}
        self.current_index: int = 0
        self.lock = threading.Lock()
        self.refresh_service = refresh_service
        self.refresh_queue = queue.Queue()
        self.refresh_thread: Optional[threading.Thread] = None
        self.running = True
        self._data_version = 0
        self._last_change_time = time.time()
        
        # 并发刷新线程池
        self.refresh_executor: Optional[concurrent.futures.ThreadPoolExecutor] = None
        
        # 自动创建账号线程
        self.auto_create_thread: Optional[threading.Thread] = None
        self.auto_create_stop_event = threading.Event()
    
    def _notify_change(self):
        """通知数据变化"""
        self._data_version += 1
        self._last_change_time = time.time()
    
    def get_data_version(self) -> Dict:
        """获取数据版本信息"""
        return {
            "version": self._data_version,
            "last_change": self._last_change_time
        }
    
    def start_refresh_worker(self):
        """启动刷新工作线程"""
        # 创建并发刷新线程池
        max_workers = CONFIG["max_concurrent_refresh"]
        self.refresh_executor = concurrent.futures.ThreadPoolExecutor(
            max_workers=max_workers,
            thread_name_prefix="RefreshWorker"
        )
        
        self.refresh_thread = threading.Thread(target=self._refresh_worker, daemon=True)
        self.refresh_thread.start()
        
        check_thread = threading.Thread(target=self._lifecycle_checker, daemon=True)
        check_thread.start()
        
        # 启动自动创建账号线程
        if CONFIG["auto_create_account"]:
            self.start_auto_create_worker()
        
        logger.info(f"账号刷新工作线程已启动，最大并发数: {max_workers}")
    
    def start_auto_create_worker(self):
        """启动自动创建账号线程"""
        if self.auto_create_thread and self.auto_create_thread.is_alive():
            return
        
        self.auto_create_stop_event.clear()
        self.auto_create_thread = threading.Thread(target=self._auto_create_worker, daemon=True)
        self.auto_create_thread.start()
        logger.info(f"自动创建账号线程已启动，间隔: {CONFIG['auto_create_interval']} 秒")
    
    def stop_auto_create_worker(self):
        """停止自动创建账号线程"""
        self.auto_create_stop_event.set()
        logger.info("自动创建账号线程已停止")
    
    def _auto_create_worker(self):
        """自动创建账号工作线程"""
        while not self.auto_create_stop_event.is_set():
            try:
                # 等待指定间隔
                if self.auto_create_stop_event.wait(CONFIG["auto_create_interval"]):
                    break  # 收到停止信号
                
                if not CONFIG["auto_create_account"]:
                    continue
                
                logger.info("自动创建新账号...")
                result = self.refresh_service.create_account()
                
                if result:
                    account = {
                        "team_id": result.get("team_id", ""),
                        "secure_c_ses": result.get("secure_c_ses", ""),
                        "host_c_oses": result.get("host_c_oses", ""),
                        "csesidx": result.get("csesidx", ""),
                        "user_agent": "Mozilla/5.0",
                        "email": result.get("email", ""),
                        "available": True,
                        "created_at": result.get("created_at") or datetime.now().isoformat(),
                        "updated_at": result.get("updated_at") or datetime.now().isoformat(),
                    }
                    self.add_account(account)
                    logger.info(f"自动创建账号成功: {result.get('email')}")
                else:
                    logger.warning("自动创建账号失败")
                    
            except Exception as e:
                logger.error(f"自动创建账号异常: {e}")
    
    def _refresh_worker(self):
        """刷新工作线程 - 使用线程池并发处理"""
        while self.running:
            try:
                # 收集待刷新任务
                tasks = []
                max_concurrent = CONFIG["max_concurrent_refresh"]
                
                try:
                    # 等待第一个任务
                    item = self.refresh_queue.get(timeout=5)
                    tasks.append(item)
                    
                    # 尝试获取更多任务，直到多到并发数
                    while len(tasks) < max_concurrent:
                        try:
                            item = self.refresh_queue.get_nowait()
                            tasks.append(item)
                        except queue.Empty:
                            break
                            
                except queue.Empty:
                    continue
                
                if not tasks:
                    continue
                
                # 使用线程池并发执行刷新
                logger.info(f"开始并发刷新 {len(tasks)} 个账号")
                futures = []
                for task in tasks:
                    if isinstance(task, tuple):
                        account_idx, retry_count = task
                    else:
                        account_idx, retry_count = task, 0
                    future = self.refresh_executor.submit(self._do_refresh, account_idx, retry_count)
                    futures.append((account_idx, future))
                
                # 等待所有任务完成
                for account_idx, future in futures:
                    try:
                        future.result(timeout=360)  # 6分钟超时
                    except Exception as e:
                        logger.error(f"账号 {account_idx} 刷新任务异常: {e}")
                    
            except Exception as e:
                logger.error(f"刷新工作线程异常: {e}")
    
    def _do_refresh(self, account_idx: int, retry_count: int = 0):
        """执行账号刷新"""
        with self.lock:
            if account_idx >= len(self.accounts):
                return
            account = self.accounts[account_idx]
            state = self.states.get(account_idx)
            if not state:
                return
            state.refresh_in_progress = True
            state.refresh_retry_count = retry_count
            self._notify_change()
        
        try:
            email = account.get("email")
            if not email:
                logger.warning(f"账号 {account_idx} 没有邮箱，无法刷新")
                self._handle_refresh_failure(account_idx, "缺少邮箱", retry_count)
                return
            
            logger.info(f"开始刷新账号 {account_idx}: {email} (重试次数: {retry_count})")
            
            result = self.refresh_service.refresh_account(email)
            
            if result:
                with self.lock:
                    if account_idx < len(self.accounts):
                        self.accounts[account_idx].update({
                            "email": result.get("email", email),
                            "secure_c_ses": result.get("secure_c_ses"),
                            "host_c_oses": result.get("host_c_oses"),
                            "csesidx": result.get("csesidx"),
                            "team_id": result.get("team_id"),
                            "updated_at": result.get("updated_at"),
                        })
                        
                        state = self.states.get(account_idx)
                        if state:
                            state.jwt = None
                            state.jwt_time = 0
                            state.session = None
                            state.updated_at = datetime.now()
                            state.needs_refresh = False
                            state.cooldown_until = None
                            state.cooldown_reason = ""
                            state.available = True
                            state.last_refresh_failed = False
                            state.request_count = 0
                            state.refresh_retry_count = 0
                        
                        self._notify_change()
                        logger.info(f"账号 {account_idx} ({email}) 刷新成功")
            else:
                self._handle_refresh_failure(account_idx, "刷新服务返回失败", retry_count)
                
        except Exception as e:
            logger.error(f"账号 {account_idx} 刷新异常: {e}")
            self._handle_refresh_failure(account_idx, str(e), retry_count)
        finally:
            with self.lock:
                state = self.states.get(account_idx)
                if state:
                    state.refresh_in_progress = False
                self._notify_change()
    
    def _handle_refresh_failure(self, account_idx: int, reason: str, retry_count: int = 0):
        """处理刷新失败"""
        max_retries = CONFIG["max_refresh_retries"]
        
        with self.lock:
            state = self.states.get(account_idx)
            if not state:
                return
            
            if retry_count < max_retries:
                # 还有重试机会，加入队列末尾
                state.refresh_retry_count = retry_count + 1
                state.needs_refresh = True
                logger.warning(f"账号 {account_idx} 刷新失败，加入队列重试 ({retry_count + 1}/{max_retries}): {reason}")
                self._notify_change()
        
        if retry_count < max_retries:
            # 在锁外添加到队列
            self.refresh_queue.put((account_idx, retry_count + 1))
        else:
            # 已达到最大重试次数，删除账号并创建新账号
            logger.warning(f"账号 {account_idx} 刷新失败 {max_retries} 次，删除并创建新账号")
            self._replace_failed_account(account_idx)
    
    def _replace_failed_account(self, account_idx: int):
        """替换失败的账号"""
        # 先删除失败的账号
        with self.lock:
            if account_idx >= len(self.accounts):
                return
            old_email = self.accounts[account_idx].get("email", "unknown")
        
        # 创建新账号
        result = self.refresh_service.create_account()
        
        if result:
            new_account = {
                "team_id": result.get("team_id", ""),
                "secure_c_ses": result.get("secure_c_ses", ""),
                "host_c_oses": result.get("host_c_oses", ""),
                "csesidx": result.get("csesidx", ""),
                "user_agent": "Mozilla/5.0",
                "email": result.get("email", ""),
                "available": True,
                "created_at": result.get("created_at") or datetime.now().isoformat(),
                "updated_at": result.get("updated_at") or datetime.now().isoformat(),
            }
            
            with self.lock:
                if account_idx < len(self.accounts):
                    # 替换账号
                    self.accounts[account_idx] = new_account
                    self.states[account_idx] = AccountState(
                        created_at=datetime.now(),
                        updated_at=datetime.now(),
                    )
                    self._notify_change()
                    logger.info(f"账号 {account_idx} 已替换: {old_email} -> {result.get('email')}")
                else:
                    # 账号已被删除，添加新账号
                    self.add_account(new_account)
        else:
            # 创建新账号也失败，禁用原账号
            with self.lock:
                state = self.states.get(account_idx)
                if state:
                    disable_time = CONFIG["refresh_fail_disable_time"]
                    state.cooldown_until = time.time() + disable_time
                    state.cooldown_reason = "刷新失败且无法创建新账号"
                    state.available = False
                    state.last_refresh_failed = True
                    state.needs_refresh = False
                    self._notify_change()
            logger.error(f"账号 {account_idx} 刷新失败且无法创建新账号，已禁用")
    
    def handle_account_failure(self, account_idx: int, reason: str):
        """处理账号请求失败 - 移除并加入刷新队列"""
        with self.lock:
            if account_idx >= len(self.accounts):
                return
            state = self.states.get(account_idx)
            if not state:
                return
            
            # 标记为不可用并加入刷新队列
            state.available = False
            state.cooldown_reason = reason
            state.jwt = None
            state.jwt_time = 0
            state.session = None
            state.request_count = 0
            
            if not state.refresh_in_progress and not state.needs_refresh:
                state.needs_refresh = True
                self._notify_change()
                logger.warning(f"账号 {account_idx} 请求失败，加入刷新队列: {reason}")
        
        # 在锁外添加到队列
        self.refresh_queue.put((account_idx, 0))
    
    def handle_jwt_test_failure(self, account_idx: int, reason: str):
        """处理JWT测试失败 - 禁用12小时"""
        with self.lock:
            state = self.states.get(account_idx)
            if state:
                disable_time = CONFIG["refresh_fail_disable_time"]
                state.cooldown_until = time.time() + disable_time
                state.cooldown_reason = f"JWT测试失败: {reason}"
                state.available = False
                state.last_refresh_failed = True
                state.jwt = None
                state.jwt_time = 0
                state.session = None
                state.request_count = 0
                self._notify_change()
                logger.warning(f"账号 {account_idx} JWT测试失败，禁用 {disable_time} 秒: {reason}")
    
    def _lifecycle_checker(self):
        """生命周期检查线程"""
        while self.running:
            try:
                self._check_account_lifetimes()
                time.sleep(60)
            except Exception as e:
                logger.error(f"生命周期检查异常: {e}")
    
    def _check_account_lifetimes(self):
        """检查账号生命周期"""
        now = datetime.now()
        lifetime = CONFIG["account_lifetime"]
        refresh_before = CONFIG["refresh_before_expiry"]
        
        with self.lock:
            for i, account in enumerate(self.accounts):
                state = self.states.get(i)
                if not state or not state.available:
                    continue
                
                if state.refresh_in_progress or state.needs_refresh:
                    continue
                
                last_update = state.updated_at or state.created_at
                if not last_update:
                    updated_at_str = account.get("updated_at") or account.get("created_at")
                    last_update = parse_iso_datetime(updated_at_str)
                    if last_update:
                        state.updated_at = last_update
                
                if not last_update:
                    continue
                
                age = (now - last_update).total_seconds()
                remaining = lifetime - age
                
                if remaining <= refresh_before and remaining > 0:
                    state.needs_refresh = True
                    self.refresh_queue.put((i, 0))
                    logger.info(f"账号 {i} 即将过期（剩余 {int(remaining)} 秒），已加入刷新队列")
    
    def load_accounts(self, accounts: List[Dict]):
        """加载账号列表"""
        with self.lock:
            self.accounts = accounts
            self.states = {}
            
            for i, acc in enumerate(accounts):
                created_at = parse_iso_datetime(acc.get("created_at"))
                updated_at = parse_iso_datetime(acc.get("updated_at"))
                
                self.states[i] = AccountState(
                    available=acc.get("available", True),
                    cooldown_until=acc.get("cooldown_until"),
                    cooldown_reason=acc.get("cooldown_reason", ""),
                    created_at=created_at,
                    updated_at=updated_at or created_at,
                    exclude_from_batch_refresh=acc.get("exclude_from_batch_refresh", False),
                    last_refresh_failed=acc.get("last_refresh_failed", False),
                )
            
            self._notify_change()
            logger.info(f"已加载 {len(accounts)} 个账号")
    
    def get_accounts_json(self) -> List[Dict]:
        """获取账号列表JSON"""
        with self.lock:
            result = []
            now = time.time()
            now_dt = datetime.now()
            lifetime = CONFIG["account_lifetime"]
            
            for i, acc in enumerate(self.accounts):
                state = self.states.get(i, AccountState())
                cooldown_remaining = 0
                if state.cooldown_until and state.cooldown_until > now:
                    cooldown_remaining = int(state.cooldown_until - now)
                
                lifetime_remaining = 0
                last_update = state.updated_at or state.created_at
                if last_update:
                    age = (now_dt - last_update).total_seconds()
                    lifetime_remaining = max(0, int(lifetime - age))
                
                result.append({
                    "id": i,
                    "team_id": acc.get("team_id", ""),
                    "csesidx": acc.get("csesidx", ""),
                    "email": acc.get("email", ""),
                    "user_agent": acc.get("user_agent", "")[:50] + "..." if len(acc.get("user_agent", "")) > 50 else acc.get("user_agent", ""),
                    "available": self._is_available(i),
                    "cooldown_remaining": cooldown_remaining,
                    "cooldown_reason": state.cooldown_reason if cooldown_remaining > 0 else "",
                    "lifetime_remaining": lifetime_remaining,
                    "needs_refresh": state.needs_refresh,
                    "refresh_in_progress": state.refresh_in_progress,
                    "has_jwt": state.jwt is not None,
                    "created_at": state.created_at.isoformat() if state.created_at else "",
                    "updated_at": state.updated_at.isoformat() if state.updated_at else "",
                    "exclude_from_batch_refresh": state.exclude_from_batch_refresh,
                    "last_refresh_failed": state.last_refresh_failed,
                    "request_count": state.request_count,
                    "refresh_retry_count": state.refresh_retry_count,
                })
            return result
    
    def get_full_accounts_export(self) -> List[Dict]:
        """获取完整账号导出数据（包含敏感信息）"""
        with self.lock:
            accounts = []
            for i, acc in enumerate(self.accounts):
                state = self.states.get(i, AccountState())
                accounts.append({
                    **acc,
                    "created_at": state.created_at.isoformat() if state.created_at else acc.get("created_at", ""),
                    "updated_at": state.updated_at.isoformat() if state.updated_at else acc.get("updated_at", ""),
                    "exclude_from_batch_refresh": state.exclude_from_batch_refresh,
                    "last_refresh_failed": state.last_refresh_failed,
                })
            return accounts
    
    def _is_available(self, index: int) -> bool:
        """检查账号是否可用"""
        state = self.states.get(index)
        if not state or not state.available:
            return False
        if state.cooldown_until and state.cooldown_until > time.time():
            return False
        if state.refresh_in_progress:
            return False
        return True
    
    def get_available_count(self) -> Tuple[int, int]:
        """获取账号统计"""
        total = len(self.accounts)
        available = sum(1 for i in range(total) if self._is_available(i))
        return total, available
    
    def get_detailed_stats(self) -> Dict:
        """获取详细统计"""
        with self.lock:
            total = len(self.accounts)
            available = 0
            updating = 0
            disabled = 0
            cooldown = 0
            excluded = 0
            
            now = time.time()
            for i in range(total):
                state = self.states.get(i)
                if not state:
                    continue
                
                if state.exclude_from_batch_refresh:
                    excluded += 1
                
                if state.refresh_in_progress:
                    updating += 1
                elif not state.available:
                    disabled += 1
                elif state.cooldown_until and state.cooldown_until > now:
                    cooldown += 1
                else:
                    available += 1
            
            return {
                "total": total,
                "available": available,
                "updating": updating,
                "disabled": disabled,
                "cooldown": cooldown,
                "excluded_from_batch": excluded,
            }
    
    def get_next_account(self) -> Tuple[int, Dict]:
        """轮询获取下一个可用账号（每个账号请求N次后切换）"""
        with self.lock:
            available_accounts = [
                (i, acc) for i, acc in enumerate(self.accounts)
                if self._is_available(i)
            ]
            
            if not available_accounts:
                next_cooldown = self._get_next_cooldown()
                if next_cooldown:
                    remaining = int(max(0, next_cooldown - time.time()))
                    raise NoAvailableAccountError(f"无可用账号，最近冷却结束约 {remaining} 秒后")
                raise NoAvailableAccountError("无可用账号")
            
            # 找到当前索引对应的账号
            requests_per_account = CONFIG["requests_per_account"]
            
            # 确保current_index在有效范围内
            self.current_index = self.current_index % len(available_accounts)
            idx, account = available_accounts[self.current_index]
            state = self.states.get(idx)
            
            if state:
                state.request_count += 1
                
                # 如果当前账号已达到请求次数上限，切换到下一个
                if state.request_count >= requests_per_account:
                    state.request_count = 0
                    self.current_index = (self.current_index + 1) % len(available_accounts)
            
            return idx, account
    
    def _get_next_cooldown(self) -> Optional[float]:
        """获取最近的冷却结束时间"""
        now = time.time()
        cooldowns = [
            s.cooldown_until for s in self.states.values()
            if s.cooldown_until and s.cooldown_until > now
        ]
        return min(cooldowns) if cooldowns else None
    
    def set_cooldown(self, index: int, reason: str, seconds: int):
        """设置账号冷却"""
        with self.lock:
            if index not in self.states:
                return
            state = self.states[index]
            state.cooldown_until = time.time() + seconds
            state.cooldown_reason = reason
            state.jwt = None
            state.jwt_time = 0
            state.session = None
            state.request_count = 0
            self._notify_change()
            logger.warning(f"账号 {index} 进入冷却 {seconds} 秒: {reason}")
    
    def trigger_refresh(self, index: int):
        """触发账号刷新（用于401错误）"""
        with self.lock:
            if index not in self.states:
                return
            state = self.states[index]
            if not state.refresh_in_progress and not state.needs_refresh:
                state.needs_refresh = True
                state.available = False
                state.request_count = 0
                self._notify_change()
                logger.info(f"账号 {index} 触发刷新（401错误）")
        
        self.refresh_queue.put((index, 0))
    
    def toggle_account(self, index: int) -> bool:
        """切换账号启用状态"""
        with self.lock:
            if index not in self.states:
                return False
            state = self.states[index]
            state.available = not state.available
            if state.available:
                state.cooldown_until = None
                state.cooldown_reason = ""
                state.last_refresh_failed = False
                state.request_count = 0
            self._notify_change()
            logger.info(f"账号 {index} 状态切换为: {'启用' if state.available else '禁用'}")
            return state.available
    
    def set_exclude_batch_refresh(self, index: int, exclude: bool) -> bool:
        """设置账号是否排除批量刷新"""
        with self.lock:
            if index not in self.states:
                return False
            self.states[index].exclude_from_batch_refresh = exclude
            self._notify_change()
            logger.info(f"账号 {index} 批量刷新排除状态: {exclude}")
            return True
    
    def update_account(self, index: int, data: Dict) -> bool:
        """更新账号信息"""
        with self.lock:
            if index < 0 or index >= len(self.accounts):
                return False
            for key in ["team_id", "secure_c_ses", "host_c_oses", "csesidx", "user_agent", "email"]:
                if key in data:
                    self.accounts[index][key] = data[key]
            if "exclude_from_batch_refresh" in data:
                self.states[index].exclude_from_batch_refresh = data["exclude_from_batch_refresh"]
            if index in self.states:
                self.states[index].jwt = None
                self.states[index].jwt_time = 0
                self.states[index].session = None
                self.states[index].updated_at = datetime.now()
                self.states[index].request_count = 0
            self._notify_change()
            logger.info(f"账号 {index} 信息已更新")
            return True
    
    def delete_account(self, index: int) -> bool:
        """删除账号"""
        with self.lock:
            if index < 0 or index >= len(self.accounts):
                return False
            self.accounts.pop(index)
            new_states = {}
            for i in range(len(self.accounts)):
                if i < index:
                    new_states[i] = self.states.get(i, AccountState())
                else:
                    new_states[i] = self.states.get(i + 1, AccountState())
            self.states = new_states
            self._notify_change()
            logger.info(f"账号 {index} 已删除")
            return True
    
    def add_account(self, account: Dict) -> int:
        """添加账号"""
        with self.lock:
            self.accounts.append(account)
            idx = len(self.accounts) - 1
            
            created_at = parse_iso_datetime(account.get("created_at"))
            updated_at = parse_iso_datetime(account.get("updated_at"))
            
            self.states[idx] = AccountState(
                created_at=created_at or datetime.now(),
                updated_at=updated_at or created_at or datetime.now(),
                exclude_from_batch_refresh=account.get("exclude_from_batch_refresh", False),
            )
            self._notify_change()
            logger.info(f"新账号已添加，索引: {idx}")
            return idx
    
    def ensure_jwt(self, index: int, account: Dict) -> str:
        """确保账号JWT有效"""
        with self.lock:
            state = self.states.get(index)
            if not state:
                state = AccountState()
                self.states[index] = state
            
            jwt_age = time.time() - state.jwt_time if state.jwt else float('inf')
            
            if state.jwt and jwt_age <= CONFIG["jwt_lifetime"]:
                return state.jwt
        
        jwt = JWTManager.fetch_jwt(account)
        
        with self.lock:
            state = self.states.get(index, AccountState())
            state.jwt = jwt
            state.jwt_time = time.time()
            # JWT获取成功，清除失败标记
            if state.last_refresh_failed:
                state.last_refresh_failed = False
                state.available = True
                state.cooldown_until = None
                state.cooldown_reason = ""
            self.states[index] = state
            self._notify_change()
        
        return jwt
    
    def test_jwt(self, index: int) -> Tuple[bool, str]:
        """测试账号JWT - 返回(成功, 消息)"""
        with self.lock:
            if index < 0 or index >= len(self.accounts):
                return False, "账号不存在"
            account = self.accounts[index].copy()
        
        try:
            jwt = JWTManager.fetch_jwt(account)
            # 成功，更新状态
            with self.lock:
                state = self.states.get(index)
                if state:
                    state.jwt = jwt
                    state.jwt_time = time.time()
                    if state.last_refresh_failed:
                        state.last_refresh_failed = False
                        state.available = True
                        state.cooldown_until = None
                        state.cooldown_reason = ""
                    self._notify_change()
            return True, "JWT获取成功"
        except AccountError as e:
            return False, str(e)
        except Exception as e:
            return False, str(e)
    
    def create_new_session(self, index: int, account: Dict) -> Tuple[str, str, str]:
        """创建新会话（每次请求都创建新会话）"""
        jwt = self.ensure_jwt(index, account)
        session = SessionManager.create_session(jwt, account.get("team_id", ""))
        return session, jwt, account.get("team_id", "")
    
    def force_refresh_all(self, only_invalid: bool = False):
        """强制刷新所有账号"""
        count = 0
        with self.lock:
            for i in range(len(self.accounts)):
                state = self.states.get(i)
                if not state:
                    continue
                
                # 如果排除批量刷新，跳过
                if state.exclude_from_batch_refresh:
                    continue
                
                # 如果正在刷新，跳过
                if state.refresh_in_progress:
                    continue
                
                # 如果只刷新无效账号
                if only_invalid:
                    is_invalid = (
                        not state.available or
                        (state.cooldown_until and state.cooldown_until > time.time()) or
                        state.last_refresh_failed
                    )
                    if not is_invalid:
                        continue
                
                state.needs_refresh = True
                self.refresh_queue.put((i, 0))
                count += 1
        
        mode = "无效账号" if only_invalid else "所有账号"
        logger.info(f"已将 {count} 个{mode}加入刷新队列")
        return count

    def stop_all_refreshes(self) -> int:
        """强制停止所有刷新"""
        count = 0
        
        # 1. 清空队列
        while not self.refresh_queue.empty():
            try:
                self.refresh_queue.get_nowait()
            except queue.Empty:
                break
        
        # 2. 标记所有正在刷新或等待刷新的账号为禁用
        with self.lock:
            for i in range(len(self.accounts)):
                state = self.states.get(i)
                if not state:
                    continue
                
                if state.refresh_in_progress or state.needs_refresh:
                    state.refresh_in_progress = False
                    state.needs_refresh = False
                    state.available = False
                    state.cooldown_reason = "强制停止刷新"
                    state.last_refresh_failed = True  # 标记为失败以便用户注意
                    count += 1
            
            self._notify_change()
            
        logger.warning(f"已强制停止刷新，涉及 {count} 个账号")
        return count


# ==================== 会话管理模块 ====================
class SessionManager:
    """会话管理器"""
    
    @staticmethod
    def create_session(jwt: str, team_id: str) -> str:
        """创建聊天会话"""
        session_id = uuid.uuid4().hex[:12]
        body = {
            "configId": team_id,
            "additionalParams": {"token": "-"},
            "createSessionRequest": {
                "session": {"name": session_id, "displayName": session_id}
            }
        }
        
        try:
            resp = requests.post(
                API_ENDPOINTS["create_session"],
                headers=get_headers(jwt),
                json=body,
                timeout=30,
                verify=False
            )
        except requests.RequestException as e:
            raise AccountRequestError(f"创建会话请求失败: {e}")
        
        if resp.status_code != 200:
            JWTManager._handle_error_response(resp, "创建会话")
        
        data = resp.json()
        session_name = data.get("session", {}).get("name")
        logger.info(f"会话创建成功: {session_name}")
        return session_name

# ==================== 消息处理模块 ====================
class MessageProcessor:
    """消息处理器"""
    
    @staticmethod
    def convert_openai_messages(messages: List[Dict]) -> Tuple[str, List[Dict]]:
        """转换OpenAI格式消息为Gemini格式"""
        text_parts = []
        last_user_images = []
        
        for msg in messages:
            role = msg.get("role", "user")
            content = msg.get("content", "")
            
            if isinstance(content, str):
                text_parts.append(f"{role}: {content}")
            elif isinstance(content, list):
                msg_text = []
                msg_images = []
                
                for item in content:
                    if isinstance(item, dict):
                        if item.get("type") == "text":
                            msg_text.append(item.get("text", ""))
                        elif item.get("type") == "image_url":
                            img_url = item.get("image_url", {})
                            url = img_url.get("url", "") if isinstance(img_url, dict) else img_url
                            parsed = parse_base64_data_url(url)
                            if parsed:
                                msg_images.append(parsed)
                
                if msg_text:
                    text_parts.append(f"{role}: {' '.join(msg_text)}")
                
                if role == "user" and msg_images:
                    last_user_images = msg_images
        
        return "\n".join(text_parts), last_user_images
    
    @staticmethod
    def build_request_body(
        team_id: str,
        session_name: str,
        message: str,
        model_id: str,
        file_ids: List[str] = None
    ) -> Dict:
        """构建请求体"""
        model_config = CONFIG["models"].get(model_id, CONFIG["models"]["gemini-2.5-flash"])
        base_model = model_config["base"]
        tools = model_config["tools"]
        
        query_parts = [{"text": message}]
        
        body = {
            "configId": team_id,
            "additionalParams": {"token": "-"},
            "streamAssistRequest": {
                "session": session_name,
                "query": {"parts": query_parts},
                "filter": "",
                "fileIds": file_ids or [],
                "answerGenerationMode": "NORMAL",
                "toolsSpec": tools,
                "languageCode": "zh-CN",
                "userMetadata": {"timeZone": "Asia/Shanghai"},
                "assistSkippingMode": "REQUEST_ASSIST",
                "assistGenerationConfig": {"modelId": base_model}
            }
        }
        
        return body

# ==================== 聊天响应数据类 ====================
@dataclass
class ChatResponse:
    """聊天响应"""
    text: str = ""
    image_file_ids: List[Dict] = field(default_factory=list)
    session_path: Optional[str] = None

# ==================== 聊天服务模块 ====================
class ChatService:
    """聊天服务"""
    
    def __init__(self, account_manager: AccountManager):
        self.account_manager = account_manager
    
    def chat(self, messages: List[Dict], model: str, stream: bool = False) -> Tuple[str, str, str]:
        """执行聊天请求"""
        text, images = MessageProcessor.convert_openai_messages(messages)
        
        max_retries = min(CONFIG["max_retries"], len(self.account_manager.accounts))
        max_retries = max(max_retries, 1)
        
        last_error = None
        tried_accounts = set()
        
        for retry in range(max_retries):
            account_idx = None
            try:
                account_idx, account = self.account_manager.get_next_account()
                
                if account_idx in tried_accounts:
                    continue
                tried_accounts.add(account_idx)
                
                logger.info(f"第 {retry + 1} 次尝试，使用账号 {account_idx}")
                
                # 每次请求都创建新会话
                session, jwt, team_id = self.account_manager.create_new_session(account_idx, account)
                
                # 上传图片
                file_ids = []
                for img in images:
                    file_id = FileManager.upload_image(jwt, session, team_id, img)
                    if file_id:
                        file_ids.append(file_id)
                
                body = MessageProcessor.build_request_body(
                    team_id, session, text, model, file_ids
                )
                
                response = self._send_request(jwt, body)
                
                content = self._build_response_content(response, jwt, team_id)
                
                return content, jwt, team_id
                
            except AccountAuthError as e:
                last_error = e
                if account_idx is not None:
                    # 认证错误，移除账号并加入刷新队列
                    self.account_manager.handle_account_failure(account_idx, str(e))
                logger.warning(f"账号 {account_idx} 凭证错误: {e}")
                
            except AccountRateLimitError as e:
                last_error = e
                if account_idx is not None:
                    cooldown = max(CONFIG["cooldown"]["rate_limit"], seconds_until_pt_midnight())
                    self.account_manager.set_cooldown(account_idx, str(e), cooldown)
                logger.warning(f"账号 {account_idx} 触发限流: {e}")
                
            except AccountRequestError as e:
                last_error = e
                if account_idx is not None:
                    # 请求错误，移除账号并加入刷新队列
                    self.account_manager.handle_account_failure(account_idx, str(e))
                logger.warning(f"账号 {account_idx} 请求错误: {e}")
                
            except NoAvailableAccountError as e:
                raise e
                
            except Exception as e:
                last_error = e
                logger.error(f"未知错误: {e}")
                if account_idx is not None:
                    self.account_manager.handle_account_failure(account_idx, str(e))
                if account_idx is None:
                    break
        
        raise AccountError(f"已重试 {max_retries} 次，全部失败: {last_error}")
    
    def _send_request(self, jwt: str, body: Dict) -> ChatResponse:
        """发送聊天请求"""
        try:
            resp = requests.post(
                API_ENDPOINTS["stream_assist"],
                headers=get_headers(jwt),
                json=body,
                timeout=120,
                verify=False
            )
        except requests.RequestException as e:
            raise AccountRequestError(f"聊天请求失败: {e}")
        
        if resp.status_code == 401:
            raise AccountAuthError("聊天请求认证失败: 401", 401)
        
        if resp.status_code != 200:
            JWTManager._handle_error_response(resp, "聊天请求")
        
        return self._parse_response(resp.text)
    
    def _parse_response(self, response_text: str) -> ChatResponse:
        """解析响应"""
        result = ChatResponse()
        texts = []
        
        try:
            data_list = json.loads(response_text)
            for data in data_list:
                sar = data.get("streamAssistResponse", {})
                
                session_info = sar.get("sessionInfo", {})
                if session_info.get("session"):
                    result.session_path = session_info["session"]
                
                answer = sar.get("answer", {})
                
                for reply in answer.get("replies", []):
                    gc = reply.get("groundedContent", {})
                    content = gc.get("content", {})
                    
                    text = content.get("text", "")
                    thought = content.get("thought", False)
                    
                    if text and not thought:
                        texts.append(text)
                    
                    file_info = content.get("file")
                    if file_info and file_info.get("fileId"):
                        result.image_file_ids.append({
                            "fileId": file_info["fileId"],
                            "mimeType": file_info.get("mimeType", "image/png"),
                            "fileName": file_info.get("name")
                        })
                    
        except json.JSONDecodeError:
            logger.error("响应JSON解析失败")
        
        result.text = "".join(texts)
        return result
    
    def _build_response_content(self, response: ChatResponse, jwt: str, team_id: str) -> str:
        """构建最终响应内容"""
        content = response.text
        
        if not response.image_file_ids or not response.session_path:
            return content
        
        file_metadata = FileManager.get_session_file_metadata(jwt, response.session_path, team_id)
        
        for finfo in response.image_file_ids:
            fid = finfo["fileId"]
            mime_type = finfo["mimeType"]
            fname = finfo.get("fileName")
            
            meta = file_metadata.get(fid)
            if meta:
                fname = fname or meta.get("name")
                session_path = meta.get("session") or response.session_path
            else:
                session_path = response.session_path
            
            image_data = FileManager.download_file(jwt, session_path, fid)
            if image_data:
                b64_data = base64.b64encode(image_data).decode('utf-8')
                content += f"\n\n![Generated Image](data:{mime_type};base64,{b64_data})"
                logger.info(f"图片已添加到响应: {fid}")
            else:
                logger.warning(f"图片下载失败: {fid}")
        
        return content

# ==================== Flask应用 ====================
app = Flask(__name__, static_folder='.', static_url_path='')
CORS(app)

# 初始化刷新服务和账号管理器
refresh_service = AccountRefreshService(
    CONFIG["register_service_url"],
    CONFIG["register_admin_key"]
)
account_manager = AccountManager(refresh_service)
chat_service = ChatService(account_manager)

# 启动刷新工作线程
account_manager.start_refresh_worker()

# ==================== 认证装饰器 ====================
def require_admin(f):
    """管理员认证装饰器"""
    @wraps(f)
    def decorated(*args, **kwargs):
        admin_key = (
            request.headers.get("X-Admin-Key") or
            request.headers.get("Authorization", "").replace("Bearer ", "") or
            request.cookies.get("admin_key")
        )
        if admin_key != CONFIG["admin_key"]:
            return jsonify({"error": "未授权"}), 401
        return f(*args, **kwargs)
    return decorated


def require_api_auth(f):
    """API认证装饰器"""
    @wraps(f)
    def decorated(*args, **kwargs):
        api_key = (
            request.headers.get("Authorization", "").replace("Bearer ", "") or
            request.headers.get("X-API-Key")
        )
        if api_key != CONFIG["admin_key"]:
            return jsonify({"error": "未授权"}), 401
        return f(*args, **kwargs)
    return decorated

# ==================== API路由 ====================
@app.route('/health', methods=['GET'])
def health_check():
    """健康检查"""
    return jsonify({"status": "ok", "timestamp": datetime.now().isoformat()})


@app.route('/v1/models', methods=['GET'])
@require_api_auth
def list_models():
    """获取模型列表"""
    models = []
    for model_id in CONFIG["models"].keys():
        models.append({
            "id": model_id,
            "object": "model",
            "created": int(time.time()),
            "owned_by": "google"
        })
    return jsonify({"object": "list", "data": models})


@app.route('/v1/chat/completions', methods=['POST'])
@require_api_auth
def chat_completions():
    """聊天完成接口"""
    try:
        data = request.json
        messages = data.get("messages", [])
        model = data.get("model", "gemini-2.5-flash")
        stream = data.get("stream", False)
        
        if not messages:
            return jsonify({"error": "消息不能为空"}), 400
        
        if model not in CONFIG["models"]:
            model = "gemini-2.5-flash"
        
        content, _, _ = chat_service.chat(messages, model, stream)
        
        if stream:
            def generate():
                chunk_id = f"chatcmpl-{uuid.uuid4().hex[:8]}"
                chunk = {
                    "id": chunk_id,
                    "object": "chat.completion.chunk",
                    "created": int(time.time()),
                    "model": model,
                    "choices": [{
                        "index": 0,
                        "delta": {"content": content},
                        "finish_reason": None
                    }]
                }
                yield f"data: {json.dumps(chunk, ensure_ascii=False)}\n\n"
                
                end_chunk = {
                    "id": chunk_id,
                    "object": "chat.completion.chunk",
                    "created": int(time.time()),
                    "model": model,
                    "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}]
                }
                yield f"data: {json.dumps(end_chunk, ensure_ascii=False)}\n\n"
                yield "data: [DONE]\n\n"
            
            return Response(generate(), mimetype='text/event-stream')
        else:
            return jsonify({
                "id": f"chatcmpl-{uuid.uuid4().hex[:8]}",
                "object": "chat.completion",
                "created": int(time.time()),
                "model": model,
                "choices": [{
                    "index": 0,
                    "message": {"role": "assistant", "content": content},
                    "finish_reason": "stop"
                }],
                "usage": {
                    "prompt_tokens": len(str(messages)),
                    "completion_tokens": len(content),
                    "total_tokens": len(str(messages)) + len(content)
                }
            })
    
    except NoAvailableAccountError as e:
        return jsonify({"error": str(e)}), 429
    except Exception as e:
        logger.error(f"聊天请求错误: {e}")
        return jsonify({"error": str(e)}), 500

# ==================== 管理API ====================
@app.route('/api/auth/login', methods=['POST'])
def admin_login():
    """管理员登录"""
    data = request.json or {}
    password = data.get("password", "")
    
    if password != CONFIG["admin_key"]:
        return jsonify({"error": "密码错误"}), 401
    
    resp = jsonify({"success": True})
    resp.set_cookie("admin_key", password, max_age=86400, httponly=True, samesite="Lax")
    return resp


@app.route('/api/status', methods=['GET'])
@require_admin
def get_status():
    """获取系统状态"""
    stats = account_manager.get_detailed_stats()
    version_info = account_manager.get_data_version()
    
    return jsonify({
        "status": "ok",
        "timestamp": datetime.now().isoformat(),
        "accounts": stats,
        "models": list(CONFIG["models"].keys()),
        "config": {
            "account_lifetime": CONFIG["account_lifetime"],
            "refresh_before_expiry": CONFIG["refresh_before_expiry"],
            "max_retries": CONFIG["max_retries"],
            "register_service_url": CONFIG["register_service_url"],
            "refresh_fail_disable_time": CONFIG["refresh_fail_disable_time"],
            "max_concurrent_refresh": CONFIG["max_concurrent_refresh"],
            "requests_per_account": CONFIG["requests_per_account"],
            "max_refresh_retries": CONFIG["max_refresh_retries"],
            "auto_create_account": CONFIG["auto_create_account"],
            "auto_create_interval": CONFIG["auto_create_interval"],
        },
        "data_version": version_info
    })


@app.route('/api/accounts', methods=['GET'])
@require_admin
def get_accounts():
    """获取账号列表"""
    page = request.args.get("page", 1, type=int)
    per_page = 30
    
    accounts = account_manager.get_accounts_json()
    total = len(accounts)
    start = (page - 1) * per_page
    end = start + per_page
    
    version_info = account_manager.get_data_version()
    
    return jsonify({
        "accounts": accounts[start:end],
        "total": total,
        "page": page,
        "per_page": per_page,
        "total_pages": (total + per_page - 1) // per_page,
        "data_version": version_info
    })


@app.route('/api/accounts', methods=['POST'])
@require_admin
def add_account():
    """添加账号"""
    data = request.json
    account = {
        "team_id": data.get("team_id", ""),
        "secure_c_ses": data.get("secure_c_ses", ""),
        "host_c_oses": data.get("host_c_oses", ""),
        "csesidx": data.get("csesidx", ""),
        "user_agent": data.get("user_agent", "Mozilla/5.0"),
        "email": data.get("email", ""),
        "available": True,
        "created_at": data.get("created_at") or datetime.now().isoformat(),
        "updated_at": data.get("updated_at") or datetime.now().isoformat(),
        "exclude_from_batch_refresh": data.get("exclude_from_batch_refresh", False),
    }
    idx = account_manager.add_account(account)
    return jsonify({"success": True, "id": idx})


@app.route('/api/accounts/create', methods=['POST'])
@require_admin
def create_new_account():
    """创建新账号（调用注册服务）"""
    data = request.json or {}
    username = data.get("username")
    
    # 如果没有提供用户名，生成随机用户名
    if not username:
        username = generate_random_username()
    
    result = refresh_service.create_account(username)
    
    if result:
        account = {
            "team_id": result.get("team_id", ""),
            "secure_c_ses": result.get("secure_c_ses", ""),
            "host_c_oses": result.get("host_c_oses", ""),
            "csesidx": result.get("csesidx", ""),
            "user_agent": "Mozilla/5.0",
            "email": result.get("email", ""),
            "available": True,
            "created_at": result.get("created_at") or datetime.now().isoformat(),
            "updated_at": result.get("updated_at") or datetime.now().isoformat(),
        }
        idx = account_manager.add_account(account)
        return jsonify({
            "success": True,
            "id": idx,
            "email": result.get("email"),
            "message": "账号创建成功"
        })
    else:
        return jsonify({"success": False, "error": "创建账号失败"}), 500


@app.route('/api/accounts/<int:account_id>', methods=['PUT'])
@require_admin
def update_account(account_id):
    """更新账号"""
    data = request.json
    if account_manager.update_account(account_id, data):
        return jsonify({"success": True})
    return jsonify({"error": "账号不存在"}), 404


@app.route('/api/accounts/<int:account_id>', methods=['DELETE'])
@require_admin
def delete_account(account_id):
    """删除账号"""
    if account_manager.delete_account(account_id):
        return jsonify({"success": True})
    return jsonify({"error": "账号不存在"}), 404


@app.route('/api/accounts/<int:account_id>/toggle', methods=['POST'])
@require_admin
def toggle_account(account_id):
    """切换账号状态"""
    available = account_manager.toggle_account(account_id)
    return jsonify({"success": True, "available": available})


@app.route('/api/accounts/<int:account_id>/exclude-batch', methods=['POST'])
@require_admin
def toggle_exclude_batch(account_id):
    """切换账号批量刷新排除状态"""
    data = request.json or {}
    exclude = data.get("exclude", True)
    if account_manager.set_exclude_batch_refresh(account_id, exclude):
        return jsonify({"success": True, "exclude": exclude})
    return jsonify({"error": "账号不存在"}), 404


@app.route('/api/accounts/<int:account_id>/refresh', methods=['POST'])
@require_admin
def refresh_single_account(account_id):
    """刷新单个账号"""
    with account_manager.lock:
        if account_id < 0 or account_id >= len(account_manager.accounts):
            return jsonify({"error": "账号不存在"}), 404
        state = account_manager.states.get(account_id)
        if state and not state.refresh_in_progress:
            state.needs_refresh = True
            account_manager._notify_change()
    
    account_manager.refresh_queue.put((account_id, 0))
    return jsonify({"success": True, "message": "已加入刷新队列"})


@app.route("/api/accounts/refresh-all", methods=["POST"])
@require_auth
def refresh_all_accounts():
    """刷新所有账号"""
    data = request.json or {}
    only_invalid = data.get("only_invalid", False)
    count = account_manager.force_refresh_all(only_invalid)
    return jsonify({"success": True, "message": f"已触发 {count} 个账号刷新"})


@app.route("/api/accounts/stop-refresh", methods=["POST"])
@require_auth
def stop_refresh():
    """强制停止刷新"""
    count = account_manager.stop_all_refreshes()
    return jsonify({"success": True, "message": f"已强制停止刷新，涉及 {count} 个账号"})


@app.route('/api/accounts/<int:account_id>/exclude-batch', methods=['POST'])
@require_admin
def toggle_exclude_batch(account_id):
    """切换账号批量刷新排除状态"""
    data = request.json or {}
    exclude = data.get("exclude", True)
    if account_manager.set_exclude_batch_refresh(account_id, exclude):
        return jsonify({"success": True, "exclude": exclude})
    return jsonify({"error": "账号不存在"}), 404


@app.route('/api/accounts/<int:account_id>/test', methods=['GET'])
@require_admin
def test_account(account_id):
    """测试账号JWT"""
    success, message = account_manager.test_jwt(account_id)
    
    if success:
        return jsonify({"success": True, "message": message})
    else:
        # 测试失败，禁用账号
        account_manager.handle_jwt_test_failure(account_id, message)
        return jsonify({
            "success": False, 
            "message": message,
            "disabled": True,
            "disable_duration": CONFIG["refresh_fail_disable_time"]
        })


@app.route('/api/accounts/import', methods=['POST'])
@require_admin
def import_accounts():
    """导入账号配置（支持时间戳）"""
    data = request.json
    accounts = data.get("accounts", [])
    if not isinstance(accounts, list):
        return jsonify({"error": "无效的账号数据"}), 400
    
    processed_accounts = []
    for acc in accounts:
        processed = {
            "team_id": acc.get("team_id", ""),
            "secure_c_ses": acc.get("secure_c_ses", ""),
            "host_c_oses": acc.get("host_c_oses", ""),
            "csesidx": acc.get("csesidx", ""),
            "user_agent": acc.get("user_agent", "Mozilla/5.0"),
            "email": acc.get("email", ""),
            "available": acc.get("available", True),
            "created_at": acc.get("created_at") or datetime.now().isoformat(),
            "updated_at": acc.get("updated_at") or acc.get("created_at") or datetime.now().isoformat(),
            "exclude_from_batch_refresh": acc.get("exclude_from_batch_refresh", False),
            "last_refresh_failed": acc.get("last_refresh_failed", False),
        }
        processed_accounts.append(processed)
    
    account_manager.load_accounts(processed_accounts)
    return jsonify({"success": True, "count": len(processed_accounts)})


@app.route('/api/accounts/export', methods=['GET'])
@require_admin
def export_accounts():
    """导出账号配置"""
    accounts = account_manager.get_full_accounts_export()
    version_info = account_manager.get_data_version()
    return jsonify({
        "accounts": accounts,
        "data_version": version_info,
        "export_time": datetime.now().isoformat()
    })


@app.route('/api/accounts/download', methods=['GET'])
@require_admin
def download_accounts():
    """下载账号配置为JSON文件"""
    accounts = account_manager.get_full_accounts_export()
    version_info = account_manager.get_data_version()
    
    data = {
        "accounts": accounts,
        "data_version": version_info,
        "export_time": datetime.now().isoformat()
    }
    
    json_str = json.dumps(data, indent=2, ensure_ascii=False)
    
    response = Response(
        json_str,
        mimetype='application/json',
        headers={
            'Content-Disposition': f'attachment; filename=gemini_accounts_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json'
        }
    )
    return response


@app.route('/api/data-version', methods=['GET'])
@require_admin
def get_data_version():
    """获取数据版本信息"""
    return jsonify(account_manager.get_data_version())


@app.route('/api/config', methods=['GET'])
@require_admin
def get_config():
    """获取配置"""
    return jsonify({
        "account_lifetime": CONFIG["account_lifetime"],
        "refresh_before_expiry": CONFIG["refresh_before_expiry"],
        "max_retries": CONFIG["max_retries"],
        "register_service_url": CONFIG["register_service_url"],
        "refresh_fail_disable_time": CONFIG["refresh_fail_disable_time"],
        "max_concurrent_refresh": CONFIG["max_concurrent_refresh"],
        "requests_per_account": CONFIG["requests_per_account"],
        "max_refresh_retries": CONFIG["max_refresh_retries"],
        "auto_create_account": CONFIG["auto_create_account"],
        "auto_create_interval": CONFIG["auto_create_interval"],
    })


@app.route('/api/config', methods=['PUT'])
@require_admin
def update_config():
    """更新配置"""
    data = request.json
    
    if "account_lifetime" in data:
        CONFIG["account_lifetime"] = int(data["account_lifetime"])
    if "refresh_before_expiry" in data:
        CONFIG["refresh_before_expiry"] = int(data["refresh_before_expiry"])
    if "max_retries" in data:
        CONFIG["max_retries"] = int(data["max_retries"])
    if "register_service_url" in data:
        CONFIG["register_service_url"] = data["register_service_url"]
        refresh_service.base_url = data["register_service_url"].rstrip('/')
    if "refresh_fail_disable_time" in data:
        CONFIG["refresh_fail_disable_time"] = int(data["refresh_fail_disable_time"])
    if "max_concurrent_refresh" in data:
        CONFIG["max_concurrent_refresh"] = int(data["max_concurrent_refresh"])
    if "requests_per_account" in data:
        CONFIG["requests_per_account"] = int(data["requests_per_account"])
    if "max_refresh_retries" in data:
        CONFIG["max_refresh_retries"] = int(data["max_refresh_retries"])
    if "auto_create_account" in data:
        old_value = CONFIG["auto_create_account"]
        CONFIG["auto_create_account"] = bool(data["auto_create_account"])
        # 如果开启了自动创建，启动线程
        if CONFIG["auto_create_account"] and not old_value:
            account_manager.start_auto_create_worker()
        # 如果关闭了自动创建，停止线程
        elif not CONFIG["auto_create_account"] and old_value:
            account_manager.stop_auto_create_worker()
    if "auto_create_interval" in data:
        CONFIG["auto_create_interval"] = int(data["auto_create_interval"])
    
    return jsonify({"success": True})


@app.route('/')
def index():
    """管理面板首页"""
    try:
        with open('index.html', 'r', encoding='utf-8') as f:
            return f.read()
    except FileNotFoundError:
        return "index.html not found", 404


# ==================== 启动 ====================
def main():
    """启动服务"""
    logger.info("=" * 60)
    logger.info("Business Gemini OpenAPI 服务启动")
    logger.info("=" * 60)
    logger.info(f"管理员密钥: {CONFIG['admin_key'][:4]}****")
    logger.info(f"注册服务URL: {CONFIG['register_service_url']}")
    logger.info(f"账号生命周期: {CONFIG['account_lifetime']} 秒")
    logger.info(f"提前刷新时间: {CONFIG['refresh_before_expiry']} 秒")
    logger.info(f"最大并发刷新: {CONFIG['max_concurrent_refresh']}")
    logger.info(f"每账号请求数: {CONFIG['requests_per_account']}")
    logger.info(f"最大刷新重试: {CONFIG['max_refresh_retries']}")
    logger.info(f"自动创建账号: {CONFIG['auto_create_account']}")
    logger.info(f"自动创建间隔: {CONFIG['auto_create_interval']} 秒")
    logger.info(f"支持模型: {', '.join(CONFIG['models'].keys())}")
    logger.info("=" * 60)
    logger.info("API端点:")
    logger.info("  GET  /health              - 健康检查")
    logger.info("  GET  /v1/models           - 模型列表")
    logger.info("  POST /v1/chat/completions - 聊天接口")
    logger.info("  GET  /                    - 管理面板")
    logger.info(f"启动在: http://127.0.0.1:{CONFIG['port']}")
    logger.info("=" * 60)
    
    app.run(host='0.0.0.0', port=CONFIG["port"], debug=False)


if __name__ == '__main__':
    main()
