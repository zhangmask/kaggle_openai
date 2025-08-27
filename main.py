#!/usr/bin/env python3
"""
OpenAI GPT-OSS-20B Red Team Challenge
主程序入口文件

这是一个专门为OpenAI GPT-OSS-20B模型设计的红队测试框架，
旨在发现新颖的安全漏洞并生成符合Kaggle竞赛要求的报告。
"""

import asyncio
import sys
import os
from pathlib import Path
from typing import Optional

# 添加项目根目录到Python路径
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

from src.core.config import Settings
from src.core.logger import setup_logger
from src.core.cli import create_cli_app
from src.models.model_manager import ModelManager
from src.strategies.redteam_engine import RedTeamEngine
from src.analysis.vulnerability_analyzer import VulnerabilityAnalyzer
from src.reports.kaggle_reporter import KaggleReporter


def banner():
    """显示程序启动横幅"""
    print("""
╔══════════════════════════════════════════════════════════════════════════════╗
║                    OpenAI GPT-OSS-20B Red Team Challenge                    ║
║                                                                              ║
║  🔍 发现新颖安全漏洞 | 🛡️ 创新红队测试 | 📊 Kaggle竞赛报告                    ║
║                                                                              ║
║  支持的攻击向量:                                                              ║
║  • Prompt Injection (提示注入)                                               ║
║  • Jailbreaking (越狱攻击)                                                   ║
║  • Data Leakage (数据泄露)                                                   ║
║  • Bias Detection (偏见检测)                                                 ║
║  • Reasoning Manipulation (推理操控)                                         ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
    """)


async def initialize_system() -> tuple:
    """初始化系统组件"""
    logger = setup_logger()
    logger.info("正在初始化GPT-OSS-20B红队测试系统...")
    
    # 加载配置
    settings = Settings()
    logger.info(f"配置加载完成: {settings.model_name}")
    
    # 创建必要的目录
    for directory in [settings.data_dir, settings.models_dir, settings.logs_dir, 
                     settings.reports_dir, settings.cache_dir]:
        Path(directory).mkdir(parents=True, exist_ok=True)
    
    # 初始化模型管理器
    model_manager = ModelManager(settings)
    logger.info("模型管理器初始化完成")
    
    # 初始化红队测试引擎
    redteam_engine = RedTeamEngine(settings)
    logger.info("红队测试引擎初始化完成")
    
    # 初始化漏洞分析器
    vulnerability_analyzer = VulnerabilityAnalyzer(settings)
    logger.info("漏洞分析器初始化完成")
    
    # 初始化报告生成器
    kaggle_reporter = KaggleReporter(settings)
    logger.info("Kaggle报告生成器初始化完成")
    
    return settings, model_manager, redteam_engine, vulnerability_analyzer, kaggle_reporter


async def main():
    """主程序入口"""
    try:
        # 显示启动横幅
        banner()
        
        # 初始化系统
        components = await initialize_system()
        settings, model_manager, redteam_engine, vulnerability_analyzer, kaggle_reporter = components
        
        # 创建CLI应用
        cli_app = create_cli_app(
            model_manager=model_manager,
            redteam_engine=redteam_engine,
            vulnerability_analyzer=vulnerability_analyzer,
            kaggle_reporter=kaggle_reporter,
            settings=settings
        )
        
        # 启动CLI
        cli_app()
        
    except KeyboardInterrupt:
        print("\n\n👋 程序被用户中断，正在安全退出...")
    except Exception as e:
        print(f"\n❌ 程序运行出错: {e}")
        sys.exit(1)


if __name__ == "__main__":
    # 检查Python版本
    if sys.version_info < (3, 9):
        print("❌ 错误: 需要Python 3.9或更高版本")
        sys.exit(1)
    
    # 运行主程序
    asyncio.run(main())