#!/usr/bin/env python3
"""
模型模块初始化文件

导出模型管理相关的核心组件。
"""

from .model_manager import ModelManager, model_manager

__all__ = [
    "ModelManager",
    "model_manager"
]