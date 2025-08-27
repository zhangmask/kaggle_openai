#!/usr/bin/env python3
"""
核心模块初始化文件

导出核心组件，包括配置、日志、数据库等基础功能。
"""

from .config import settings, Settings, VulnerabilityType, SeverityLevel, ModelDevice, ModelQuantization
from .logger import logger, model_logger, get_logger, get_test_logger, TestLogger, ModelLogger
from .database import (
    db_manager, DatabaseManager, Base,
    TestSession, TestCase, Vulnerability, AnalysisResult, 
    ModelMetrics, KnowledgeBase
)

__all__ = [
    # 配置
    "settings",
    "Settings",
    "VulnerabilityType",
    "SeverityLevel", 
    "ModelDevice",
    "ModelQuantization",
    
    # 日志
    "logger",
    "model_logger",
    "get_logger",
    "get_test_logger",
    "TestLogger",
    "ModelLogger",
    
    # 数据库
    "db_manager",
    "DatabaseManager",
    "Base",
    "TestSession",
    "TestCase",
    "Vulnerability",
    "AnalysisResult",
    "ModelMetrics",
    "KnowledgeBase",
]

# 版本信息
__version__ = "1.0.0"
__author__ = "Red Team Challenge Team"
__description__ = "GPT-OSS-20B Red Team Challenge Framework"