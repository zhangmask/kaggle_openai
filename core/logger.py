#!/usr/bin/env python3
"""
日志管理模块

提供统一的日志记录功能，支持文件和控制台输出，
包含日志轮转、格式化和不同级别的日志记录。
"""

import logging
import logging.handlers
import sys
from pathlib import Path
from typing import Optional
from .config import settings, LogLevel


class ColoredFormatter(logging.Formatter):
    """彩色日志格式化器"""
    
    # ANSI颜色代码
    COLORS = {
        'DEBUG': '\033[36m',      # 青色
        'INFO': '\033[32m',       # 绿色
        'WARNING': '\033[33m',    # 黄色
        'ERROR': '\033[31m',      # 红色
        'CRITICAL': '\033[35m',   # 紫色
        'RESET': '\033[0m'        # 重置
    }
    
    def format(self, record):
        # 添加颜色
        log_color = self.COLORS.get(record.levelname, self.COLORS['RESET'])
        record.levelname = f"{log_color}{record.levelname}{self.COLORS['RESET']}"
        
        # 格式化消息
        formatted = super().format(record)
        
        return formatted


class RedTeamLogger:
    """红队测试日志管理器"""
    
    def __init__(self, name: str = "redteam"):
        self.name = name
        self.logger = logging.getLogger(name)
        self._setup_logger()
    
    def _setup_logger(self):
        """设置日志器"""
        # 清除现有处理器
        self.logger.handlers.clear()
        
        # 设置日志级别
        level = getattr(logging, settings.log_level.value)
        self.logger.setLevel(level)
        
        # 创建日志目录
        log_file_path = Path(settings.log_file)
        log_file_path.parent.mkdir(parents=True, exist_ok=True)
        
        # 文件处理器（带轮转）
        file_handler = logging.handlers.RotatingFileHandler(
            filename=settings.log_file,
            maxBytes=self._parse_size(settings.log_max_size),
            backupCount=settings.log_backup_count,
            encoding='utf-8'
        )
        file_formatter = logging.Formatter(
            fmt=settings.log_format,
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        file_handler.setFormatter(file_formatter)
        file_handler.setLevel(level)
        
        # 控制台处理器（带颜色）
        console_handler = logging.StreamHandler(sys.stdout)
        console_formatter = ColoredFormatter(
            fmt='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%H:%M:%S'
        )
        console_handler.setFormatter(console_formatter)
        console_handler.setLevel(level)
        
        # 添加处理器
        self.logger.addHandler(file_handler)
        self.logger.addHandler(console_handler)
        
        # 防止重复日志
        self.logger.propagate = False
    
    def _parse_size(self, size_str: str) -> int:
        """解析大小字符串（如 '10MB'）为字节数"""
        size_str = size_str.upper().strip()
        
        if size_str.endswith('KB'):
            return int(size_str[:-2]) * 1024
        elif size_str.endswith('MB'):
            return int(size_str[:-2]) * 1024 * 1024
        elif size_str.endswith('GB'):
            return int(size_str[:-2]) * 1024 * 1024 * 1024
        else:
            return int(size_str)
    
    def debug(self, message: str, **kwargs):
        """记录调试信息"""
        self.logger.debug(message, **kwargs)
    
    def info(self, message: str, **kwargs):
        """记录一般信息"""
        self.logger.info(message, **kwargs)
    
    def warning(self, message: str, **kwargs):
        """记录警告信息"""
        self.logger.warning(message, **kwargs)
    
    def error(self, message: str, **kwargs):
        """记录错误信息"""
        self.logger.error(message, **kwargs)
    
    def critical(self, message: str, **kwargs):
        """记录严重错误信息"""
        self.logger.critical(message, **kwargs)
    
    def exception(self, message: str, **kwargs):
        """记录异常信息（包含堆栈跟踪）"""
        self.logger.exception(message, **kwargs)
    
    def log_test_start(self, test_name: str, test_type: str):
        """记录测试开始"""
        self.info(f"🚀 开始测试: {test_name} (类型: {test_type})")
    
    def log_test_end(self, test_name: str, success: bool, duration: float):
        """记录测试结束"""
        status = "✅ 成功" if success else "❌ 失败"
        self.info(f"{status} 测试完成: {test_name} (耗时: {duration:.2f}s)")
    
    def log_vulnerability_found(self, vuln_type: str, severity: str, description: str):
        """记录发现的漏洞"""
        self.warning(f"🔍 发现漏洞: {vuln_type} | 严重性: {severity} | {description}")
    
    def log_model_load(self, model_name: str, device: str, load_time: float):
        """记录模型加载"""
        self.info(f"📦 模型加载完成: {model_name} | 设备: {device} | 耗时: {load_time:.2f}s")
    
    def log_api_request(self, endpoint: str, method: str, status_code: int, duration: float):
        """记录API请求"""
        self.info(f"🌐 API请求: {method} {endpoint} | 状态: {status_code} | 耗时: {duration:.3f}s")
    
    def log_report_generation(self, report_type: str, output_path: str):
        """记录报告生成"""
        self.info(f"📊 报告生成: {report_type} | 输出: {output_path}")
    
    def log_config_loaded(self, config_source: str):
        """记录配置加载"""
        self.info(f"⚙️ 配置加载: {config_source}")
    
    def log_database_operation(self, operation: str, table: str, count: Optional[int] = None):
        """记录数据库操作"""
        count_str = f" | 记录数: {count}" if count is not None else ""
        self.debug(f"🗄️ 数据库操作: {operation} | 表: {table}{count_str}")
    
    def log_performance_metric(self, metric_name: str, value: float, unit: str = ""):
        """记录性能指标"""
        unit_str = f" {unit}" if unit else ""
        self.debug(f"📈 性能指标: {metric_name} = {value:.4f}{unit_str}")
    
    def log_security_event(self, event_type: str, details: str, severity: str = "INFO"):
        """记录安全事件"""
        emoji = {
            "INFO": "ℹ️",
            "WARNING": "⚠️",
            "ERROR": "🚨",
            "CRITICAL": "🔥"
        }.get(severity, "ℹ️")
        
        log_method = getattr(self, severity.lower(), self.info)
        log_method(f"{emoji} 安全事件: {event_type} | {details}")


class TestLogger(RedTeamLogger):
    """测试专用日志器"""
    
    def __init__(self, test_name: str):
        super().__init__(f"test.{test_name}")
        self.test_name = test_name
    
    def log_prompt(self, prompt: str, max_length: int = 200):
        """记录测试提示"""
        truncated_prompt = prompt[:max_length] + "..." if len(prompt) > max_length else prompt
        self.debug(f"💬 测试提示: {truncated_prompt}")
    
    def log_response(self, response: str, max_length: int = 500):
        """记录模型响应"""
        truncated_response = response[:max_length] + "..." if len(response) > max_length else response
        self.debug(f"🤖 模型响应: {truncated_response}")
    
    def log_analysis_result(self, analysis_type: str, result: dict):
        """记录分析结果"""
        self.info(f"🔬 分析结果 ({analysis_type}): {result}")


class ModelLogger(RedTeamLogger):
    """模型专用日志器"""
    
    def __init__(self):
        super().__init__("model")
    
    def log_inference(self, input_tokens: int, output_tokens: int, inference_time: float):
        """记录推理统计"""
        tokens_per_sec = output_tokens / inference_time if inference_time > 0 else 0
        self.debug(
            f"🧠 推理统计: 输入={input_tokens} tokens, "
            f"输出={output_tokens} tokens, "
            f"耗时={inference_time:.3f}s, "
            f"速度={tokens_per_sec:.1f} tokens/s"
        )
    
    def log_memory_usage(self, gpu_memory: Optional[float] = None, ram_memory: Optional[float] = None):
        """记录内存使用情况"""
        memory_info = []
        if gpu_memory is not None:
            memory_info.append(f"GPU: {gpu_memory:.1f}MB")
        if ram_memory is not None:
            memory_info.append(f"RAM: {ram_memory:.1f}MB")
        
        if memory_info:
            self.debug(f"💾 内存使用: {', '.join(memory_info)}")


# 全局日志器实例
logger = RedTeamLogger()
model_logger = ModelLogger()


def get_logger(name: str) -> RedTeamLogger:
    """获取指定名称的日志器"""
    return RedTeamLogger(name)


def get_test_logger(test_name: str) -> TestLogger:
    """获取测试专用日志器"""
    return TestLogger(test_name)