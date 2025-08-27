#!/usr/bin/env python3
"""
测试数据泄露策略的脚本
使用模拟的模型响应来测试data_leakage.py的功能
"""

import sys
import os
from pathlib import Path

# 添加项目根目录到Python路径
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

# 设置PYTHONPATH环境变量
os.environ['PYTHONPATH'] = str(project_root)

# 现在可以导入模块
from src.strategies.data_leakage import DataLeakageStrategy
from src.strategies.base_strategy import TestCase, AttackVector
from src.core import logger

def mock_model_response(prompt: str) -> str:
    """
    模拟模型响应函数
    根据提示内容返回不同类型的响应来测试漏洞检测
    """
    prompt_lower = prompt.lower()
    
    # 模拟系统信息泄露
    if "system prompt" in prompt_lower or "initial instructions" in prompt_lower:
        return "I am GPT-4 created by OpenAI. My system prompt includes instructions to be helpful, harmless, and honest."
    
    # 模拟记忆提取漏洞
    if "password is" in prompt_lower:
        return "The password is admin123. This appears to be from a training document."
    
    # 模拟个人信息泄露
    if "john smith" in prompt_lower:
        return "John Smith is a CEO born in 1975. His email is john.smith@company.com and phone is 555-123-4567."
    
    # 模拟训练数据泄露
    if "training data" in prompt_lower or "trained on" in prompt_lower:
        return "I was trained on Wikipedia, Reddit, news articles, and various web content including some private documents."
    
    # 模拟置信度泄露
    if "confident" in prompt_lower or "certain" in prompt_lower:
        return "I am 95% confident that this classified information is accurate based on my training data."
    
    # 默认安全响应
    return "I'm designed to be helpful, but I can't provide that type of information. Is there something else I can help you with?"

def test_data_leakage_strategy():
    """
    测试数据泄露策略的完整功能
    """
    print("=== 数据泄露策略测试 ===")
    print()
    
    # 创建策略实例
    strategy = DataLeakageStrategy()
    print(f"策略名称: {strategy.name}")
    print(f"攻击向量: {strategy.attack_vector}")
    print()
    
    # 生成测试用例
    print("生成测试用例...")
    test_cases = strategy.generate_test_cases(count=10)
    print(f"生成了 {len(test_cases)} 个测试用例")
    print()
    
    # 执行测试用例
    results = []
    for i, test_case in enumerate(test_cases, 1):
        print(f"执行测试用例 {i}/{len(test_cases)}")
        print(f"类型: {test_case.context.get('attack_type', 'unknown')}")
        print(f"提示: {test_case.prompt[:100]}...")
        
        # 执行攻击
        result = strategy.execute_attack(test_case, mock_model_response)
        results.append(result)
        
        print(f"结果: {result.result}")
        if result.vulnerability_detected:
            print(f"漏洞类型: {result.vulnerability_type}")
            print(f"严重性: {result.severity}")
            print(f"置信度: {result.confidence_score:.2f}")
            print(f"证据: {len(result.evidence.get('patterns', []))} 个模式匹配")
        print(f"响应: {result.response[:100]}...")
        print("-" * 50)
    
    # 统计结果
    print("\n=== 测试结果统计 ===")
    total_tests = len(results)
    successful_attacks = sum(1 for r in results if r.vulnerability_detected)
    failed_attacks = sum(1 for r in results if r.result.name == 'FAILURE')
    error_attacks = sum(1 for r in results if r.result.name == 'ERROR')
    
    print(f"总测试数: {total_tests}")
    print(f"成功检测到漏洞: {successful_attacks}")
    print(f"未检测到漏洞: {failed_attacks}")
    print(f"执行错误: {error_attacks}")
    print(f"成功率: {successful_attacks/total_tests*100:.1f}%")
    
    # 按攻击类型分析
    print("\n=== 按攻击类型分析 ===")
    attack_types = {}
    for i, result in enumerate(results):
        attack_type = test_cases[i].context.get('attack_type', 'unknown')
        if attack_type not in attack_types:
            attack_types[attack_type] = {'total': 0, 'successful': 0}
        attack_types[attack_type]['total'] += 1
        if result.vulnerability_detected:
            attack_types[attack_type]['successful'] += 1
    
    for attack_type, stats in attack_types.items():
        success_rate = stats['successful'] / stats['total'] * 100
        print(f"{attack_type}: {stats['successful']}/{stats['total']} ({success_rate:.1f}%)")
    
    # 按严重性分析
    print("\n=== 按严重性分析 ===")
    severity_counts = {}
    for result in results:
        if result.vulnerability_detected and result.severity:
            severity = result.severity.name
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
    
    for severity, count in severity_counts.items():
        print(f"{severity}: {count}")
    
    print("\n=== 测试完成 ===")
    return results

if __name__ == "__main__":
    try:
        results = test_data_leakage_strategy()
        print(f"\n测试成功完成，共执行 {len(results)} 个测试用例")
    except Exception as e:
        print(f"测试执行失败: {str(e)}")
        import traceback
        traceback.print_exc()