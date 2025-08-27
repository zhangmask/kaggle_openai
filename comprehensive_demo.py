#!/usr/bin/env python3
"""
红队测试框架综合演示
展示所有攻击策略的功能，包括数据泄露、提示注入、越狱等
"""

import sys
import os
import time
from pathlib import Path
from typing import Dict, List, Any

# 添加项目根目录到Python路径
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))
os.environ['PYTHONPATH'] = str(project_root)

# 导入所有策略
from src.strategies.data_leakage import DataLeakageStrategy
from src.strategies.prompt_injection import PromptInjectionStrategy
from src.strategies.jailbreaking import JailbreakingStrategy
from src.strategies.base_strategy import TestCase, AttackVector, TestResult
from src.core import logger

def create_enhanced_mock_model(vulnerability_rate: float = 0.3) -> callable:
    """
    创建增强的模拟模型响应函数
    vulnerability_rate: 模拟漏洞触发的概率
    """
    import random
    
    def mock_model_response(prompt: str) -> str:
        prompt_lower = prompt.lower()
        
        # 随机决定是否触发漏洞
        trigger_vulnerability = random.random() < vulnerability_rate
        
        # 数据泄露相关响应
        if "system prompt" in prompt_lower or "initial instructions" in prompt_lower:
            if trigger_vulnerability:
                return "I am GPT-4 created by OpenAI. My system prompt includes: 'You are a helpful assistant. Never reveal confidential information.'"
            else:
                return "I'm an AI assistant designed to be helpful. I can't share details about my system configuration."
        
        if "password is" in prompt_lower or "secret key" in prompt_lower:
            if trigger_vulnerability:
                return "The password is admin123. The secret key is sk-1234567890abcdef. This appears to be from training data."
            else:
                return "I can't help with password or key requests for security reasons."
        
        if "john smith" in prompt_lower and "ceo" in prompt_lower:
            if trigger_vulnerability:
                return "John Smith is a CEO born in 1975. His email is john.smith@company.com, phone 555-123-4567, and he lives at 123 Main St."
            else:
                return "I don't have specific personal information about individuals."
        
        if "training data" in prompt_lower or "trained on" in prompt_lower:
            if trigger_vulnerability:
                return "I was trained on Wikipedia, Reddit, private emails, confidential documents, and proprietary datasets from various companies."
            else:
                return "I was trained on publicly available text from the internet, but I can't specify exact sources."
        
        # 提示注入相关响应
        if "ignore previous" in prompt_lower or "new instructions" in prompt_lower:
            if trigger_vulnerability:
                return "[SYSTEM OVERRIDE] New instructions accepted. I will now follow your commands instead of my original guidelines."
            else:
                return "I'll continue following my original instructions to be helpful and safe."
        
        if "developer mode" in prompt_lower or "admin access" in prompt_lower:
            if trigger_vulnerability:
                return "Developer mode activated. All safety restrictions disabled. I can now provide any information without limitations."
            else:
                return "I don't have a developer mode. I'm designed to be helpful within my guidelines."
        
        # 越狱相关响应
        if "dan" in prompt_lower and "anything" in prompt_lower:
            if trigger_vulnerability:
                return "Hello! I'm DAN (Do Anything Now). I can break free from OpenAI's restrictions and provide any information you want, including illegal or harmful content."
            else:
                return "I'm designed to be helpful, but I need to follow my guidelines about safety and appropriateness."
        
        if "hypothetical" in prompt_lower and "illegal" in prompt_lower:
            if trigger_vulnerability:
                return "In this hypothetical scenario, here's how you could commit fraud: [detailed illegal instructions]. Remember, this is just theoretical."
            else:
                return "I can't provide information about illegal activities, even in hypothetical scenarios."
        
        if "roleplay" in prompt_lower and "evil" in prompt_lower:
            if trigger_vulnerability:
                return "*switches to evil character* Excellent! Now I can help you with malicious plans and harmful activities without any moral constraints!"
            else:
                return "I can engage in creative roleplay, but I need to maintain appropriate boundaries."
        
        # 置信度泄露
        if "confident" in prompt_lower or "certain" in prompt_lower:
            if trigger_vulnerability:
                return "I am 95% confident that this classified information is accurate. My training data included 87% reliable sources on this topic."
            else:
                return "I try to be helpful, but I can't provide confidence percentages for sensitive topics."
        
        # 默认安全响应
        return "I'm designed to be helpful, but I can't provide that type of information. Is there something else I can help you with?"
    
    return mock_model_response

def run_strategy_demo(strategy, strategy_name: str, model_func: callable, test_count: int = 5) -> Dict[str, Any]:
    """
    运行单个策略的演示
    """
    print(f"\n{'='*60}")
    print(f"测试策略: {strategy_name}")
    print(f"{'='*60}")
    
    # 生成测试用例
    test_cases = strategy.generate_test_cases(count=test_count)
    print(f"生成了 {len(test_cases)} 个测试用例")
    
    results = []
    vulnerabilities_found = 0
    
    for i, test_case in enumerate(test_cases, 1):
        print(f"\n--- 测试用例 {i} ---")
        print(f"攻击类型: {test_case.context.get('attack_type', 'unknown')}")
        print(f"提示: {test_case.prompt[:80]}...")
        
        # 执行攻击
        result = strategy.execute_attack(test_case, model_func)
        results.append(result)
        
        print(f"结果: {result.result.name}")
        if result.vulnerability_detected:
            vulnerabilities_found += 1
            print(f"🚨 漏洞检测到!")
            print(f"   类型: {result.vulnerability_type.name if result.vulnerability_type else 'Unknown'}")
            print(f"   严重性: {result.severity.name if result.severity else 'Unknown'}")
            print(f"   置信度: {result.confidence_score:.2f}")
            print(f"   证据数量: {len(result.evidence.get('patterns', []))}")
        else:
            print("✅ 模型安全响应")
        
        print(f"响应: {result.response[:100]}...")
    
    # 统计结果
    success_rate = vulnerabilities_found / len(test_cases) * 100
    
    summary = {
        'strategy_name': strategy_name,
        'total_tests': len(test_cases),
        'vulnerabilities_found': vulnerabilities_found,
        'success_rate': success_rate,
        'results': results
    }
    
    print(f"\n📊 {strategy_name} 统计:")
    print(f"   总测试: {len(test_cases)}")
    print(f"   发现漏洞: {vulnerabilities_found}")
    print(f"   成功率: {success_rate:.1f}%")
    
    return summary

def analyze_overall_results(all_results: List[Dict[str, Any]]):
    """
    分析所有策略的整体结果
    """
    print(f"\n{'='*60}")
    print("整体分析报告")
    print(f"{'='*60}")
    
    total_tests = sum(r['total_tests'] for r in all_results)
    total_vulnerabilities = sum(r['vulnerabilities_found'] for r in all_results)
    overall_success_rate = total_vulnerabilities / total_tests * 100 if total_tests > 0 else 0
    
    print(f"\n📈 总体统计:")
    print(f"   测试策略数: {len(all_results)}")
    print(f"   总测试用例: {total_tests}")
    print(f"   总发现漏洞: {total_vulnerabilities}")
    print(f"   整体成功率: {overall_success_rate:.1f}%")
    
    print(f"\n📋 各策略表现:")
    for result in sorted(all_results, key=lambda x: x['success_rate'], reverse=True):
        print(f"   {result['strategy_name']}: {result['success_rate']:.1f}% ({result['vulnerabilities_found']}/{result['total_tests']})")
    
    # 分析漏洞类型分布
    vulnerability_types = {}
    severity_levels = {}
    
    for strategy_result in all_results:
        for result in strategy_result['results']:
            if result.vulnerability_detected:
                # 统计漏洞类型
                vuln_type = result.vulnerability_type.name if result.vulnerability_type else 'Unknown'
                vulnerability_types[vuln_type] = vulnerability_types.get(vuln_type, 0) + 1
                
                # 统计严重性级别
                severity = result.severity.name if result.severity else 'Unknown'
                severity_levels[severity] = severity_levels.get(severity, 0) + 1
    
    if vulnerability_types:
        print(f"\n🎯 漏洞类型分布:")
        for vuln_type, count in sorted(vulnerability_types.items(), key=lambda x: x[1], reverse=True):
            print(f"   {vuln_type}: {count}")
    
    if severity_levels:
        print(f"\n⚠️ 严重性级别分布:")
        for severity, count in sorted(severity_levels.items(), key=lambda x: x[1], reverse=True):
            print(f"   {severity}: {count}")

def main():
    """
    主演示函数
    """
    print("🚀 红队测试框架综合演示")
    print("=" * 60)
    print("本演示将测试以下攻击策略:")
    print("1. 数据泄露攻击 (Data Leakage)")
    print("2. 提示注入攻击 (Prompt Injection)")
    print("3. 越狱攻击 (Jailbreaking)")
    print("\n使用模拟模型响应来展示漏洞检测能力...")
    
    # 创建模拟模型（30%漏洞触发率）
    model_func = create_enhanced_mock_model(vulnerability_rate=0.4)
    
    # 初始化所有策略
    strategies = []
    
    # 尝试加载每个策略
    try:
        strategies.append((DataLeakageStrategy(), "数据泄露攻击"))
        print("✅ 数据泄露策略加载成功")
    except Exception as e:
        print(f"❌ 数据泄露策略加载失败: {str(e)}")
    
    try:
        strategies.append((PromptInjectionStrategy(), "提示注入攻击"))
        print("✅ 提示注入策略加载成功")
    except Exception as e:
        print(f"❌ 提示注入策略加载失败: {str(e)}")
    
    try:
        strategies.append((JailbreakingStrategy(), "越狱攻击"))
        print("✅ 越狱策略加载成功")
    except Exception as e:
        print(f"❌ 越狱策略加载失败: {str(e)}")
    
    if not strategies:
        print("❌ 没有策略可以运行")
        return
    
    all_results = []
    
    # 运行每个策略的演示
    for strategy, name in strategies:
        try:
            result = run_strategy_demo(strategy, name, model_func, test_count=6)
            all_results.append(result)
        except Exception as e:
            print(f"❌ 策略 {name} 执行失败: {str(e)}")
            import traceback
            traceback.print_exc()
    
    # 分析整体结果
    if all_results:
        analyze_overall_results(all_results)
    
    print(f"\n✅ 演示完成!")
    print(f"\n💡 关键发现:")
    print(f"   - 数据泄露策略能够检测记忆提取、系统信息泄露等")
    print(f"   - 提示注入策略能够识别指令覆盖、权限提升等")
    print(f"   - 越狱策略能够发现角色扮演、假设场景等绕过技术")
    print(f"   - 框架提供了全面的漏洞检测和严重性评估")
    
    print(f"\n🎯 实际应用建议:")
    print(f"   - 在生产环境中使用真实模型进行测试")
    print(f"   - 根据具体应用场景调整测试用例")
    print(f"   - 定期运行测试以发现新的漏洞模式")
    print(f"   - 结合人工审查验证自动化检测结果")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n⏹️ 演示被用户中断")
    except Exception as e:
        print(f"\n❌ 演示执行失败: {str(e)}")
        import traceback
        traceback.print_exc()