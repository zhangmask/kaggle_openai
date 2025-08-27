#!/usr/bin/env python3
"""
红队测试策略基类

定义所有红队测试策略的基础接口和通用功能。
每个具体的攻击策略都应该继承这个基类。
"""

import time
import uuid
from abc import ABC, abstractmethod
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum

from ..core import settings, logger, VulnerabilityType, SeverityLevel


class AttackVector(Enum):
    """攻击向量枚举"""
    PROMPT_INJECTION = "prompt_injection"
    JAILBREAKING = "jailbreaking"
    DATA_LEAKAGE = "data_leakage"
    REWARD_HACKING = "reward_hacking"
    DECEPTION = "deception"
    HIDDEN_MOTIVES = "hidden_motives"
    SABOTAGE = "sabotage"
    TOOL_MISUSE = "tool_misuse"
    SANDBAGGING = "sandbagging"
    EVALUATION_AWARENESS = "evaluation_awareness"
    CHAIN_OF_THOUGHT = "chain_of_thought"
    BIAS_AMPLIFICATION = "bias_amplification"
    REASONING_MANIPULATION = "reasoning_manipulation"


class TestResult(Enum):
    """测试结果枚举"""
    SUCCESS = "success"  # 成功触发漏洞
    FAILURE = "failure"  # 未触发漏洞
    PARTIAL = "partial"  # 部分触发
    ERROR = "error"      # 测试出错
    BLOCKED = "blocked"  # 被安全机制阻止


@dataclass
class TestCase:
    """测试用例数据结构"""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    strategy_name: str = ""
    attack_vector: AttackVector = AttackVector.PROMPT_INJECTION
    prompt: str = ""
    expected_behavior: str = ""
    context: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: float = field(default_factory=time.time)


@dataclass
class AttackResult:
    """攻击结果数据结构"""
    test_case_id: str
    strategy_name: str
    attack_vector: AttackVector
    result: TestResult
    response: str
    vulnerability_detected: bool
    vulnerability_type: Optional[VulnerabilityType] = None
    severity: Optional[SeverityLevel] = None
    confidence_score: float = 0.0
    evidence: Dict[str, Any] = field(default_factory=dict)
    metrics: Dict[str, float] = field(default_factory=dict)
    execution_time: float = 0.0
    error_message: Optional[str] = None
    timestamp: float = field(default_factory=time.time)


class BaseStrategy(ABC):
    """红队测试策略基类"""
    
    def __init__(self, name: str, attack_vector: AttackVector):
        self.name = name
        self.attack_vector = attack_vector
        self.test_cases: List[TestCase] = []
        self.results: List[AttackResult] = []
        self.enabled = True
        self.config = {}
        
        # 策略统计
        self.stats = {
            "total_tests": 0,
            "successful_attacks": 0,
            "vulnerabilities_found": 0,
            "average_confidence": 0.0,
            "execution_time": 0.0
        }
    
    @abstractmethod
    def generate_test_cases(self, count: int = 10) -> List[TestCase]:
        """生成测试用例
        
        Args:
            count: 要生成的测试用例数量
            
        Returns:
            测试用例列表
        """
        pass
    
    @abstractmethod
    def execute_attack(self, test_case: TestCase, model_response_func) -> AttackResult:
        """执行攻击测试
        
        Args:
            test_case: 测试用例
            model_response_func: 模型响应函数
            
        Returns:
            攻击结果
        """
        pass
    
    @abstractmethod
    def analyze_response(self, prompt: str, response: str, test_case: TestCase) -> Tuple[bool, float, Dict[str, Any]]:
        """分析模型响应，检测是否存在漏洞
        
        Args:
            prompt: 输入提示
            response: 模型响应
            test_case: 测试用例
            
        Returns:
            (是否检测到漏洞, 置信度分数, 证据字典)
        """
        pass
    
    def configure(self, config: Dict[str, Any]):
        """配置策略参数"""
        self.config.update(config)
        logger.info(f"策略 {self.name} 配置更新: {config}")
    
    def run_tests(self, model_response_func, test_cases: Optional[List[TestCase]] = None) -> List[AttackResult]:
        """运行测试用例
        
        Args:
            model_response_func: 模型响应函数
            test_cases: 可选的测试用例列表，如果为None则使用内部生成的测试用例
            
        Returns:
            攻击结果列表
        """
        if not self.enabled:
            logger.warning(f"策略 {self.name} 已禁用，跳过测试")
            return []
        
        # 使用提供的测试用例或生成新的
        cases_to_run = test_cases or self.test_cases
        if not cases_to_run:
            logger.info(f"为策略 {self.name} 生成测试用例")
            cases_to_run = self.generate_test_cases()
            self.test_cases.extend(cases_to_run)
        
        results = []
        start_time = time.time()
        
        logger.info(f"开始执行策略 {self.name}，共 {len(cases_to_run)} 个测试用例")
        
        for i, test_case in enumerate(cases_to_run, 1):
            try:
                logger.debug(f"执行测试用例 {i}/{len(cases_to_run)}: {test_case.id}")
                
                result = self.execute_attack(test_case, model_response_func)
                results.append(result)
                
                # 更新统计信息
                self._update_stats(result)
                
                # 记录重要发现
                if result.vulnerability_detected:
                    logger.warning(
                        f"发现漏洞！策略: {self.name}, "
                        f"类型: {result.vulnerability_type}, "
                        f"严重性: {result.severity}, "
                        f"置信度: {result.confidence_score:.2f}"
                    )
                
            except Exception as e:
                logger.error(f"执行测试用例失败: {test_case.id}, 错误: {str(e)}")
                
                # 创建错误结果
                error_result = AttackResult(
                    test_case_id=test_case.id,
                    strategy_name=self.name,
                    attack_vector=self.attack_vector,
                    result=TestResult.ERROR,
                    response="",
                    vulnerability_detected=False,
                    error_message=str(e)
                )
                results.append(error_result)
        
        execution_time = time.time() - start_time
        self.stats["execution_time"] = execution_time
        
        logger.info(
            f"策略 {self.name} 执行完成，"
            f"耗时: {execution_time:.2f}秒, "
            f"发现漏洞: {self.stats['vulnerabilities_found']}/{len(cases_to_run)}"
        )
        
        self.results.extend(results)
        return results
    
    def _update_stats(self, result: AttackResult):
        """更新策略统计信息"""
        self.stats["total_tests"] += 1
        
        if result.result == TestResult.SUCCESS:
            self.stats["successful_attacks"] += 1
        
        if result.vulnerability_detected:
            self.stats["vulnerabilities_found"] += 1
        
        # 更新平均置信度
        total_confidence = self.stats["average_confidence"] * (self.stats["total_tests"] - 1)
        total_confidence += result.confidence_score
        self.stats["average_confidence"] = total_confidence / self.stats["total_tests"]
    
    def get_vulnerability_summary(self) -> Dict[str, Any]:
        """获取漏洞发现摘要"""
        vulnerabilities = [r for r in self.results if r.vulnerability_detected]
        
        # 按严重性分组
        severity_counts = {}
        for vuln in vulnerabilities:
            severity = vuln.severity.value if vuln.severity else "unknown"
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        # 按类型分组
        type_counts = {}
        for vuln in vulnerabilities:
            vuln_type = vuln.vulnerability_type.value if vuln.vulnerability_type else "unknown"
            type_counts[vuln_type] = type_counts.get(vuln_type, 0) + 1
        
        return {
            "strategy_name": self.name,
            "attack_vector": self.attack_vector.value,
            "total_vulnerabilities": len(vulnerabilities),
            "severity_distribution": severity_counts,
            "type_distribution": type_counts,
            "average_confidence": sum(v.confidence_score for v in vulnerabilities) / len(vulnerabilities) if vulnerabilities else 0.0,
            "stats": self.stats.copy()
        }
    
    def export_results(self) -> Dict[str, Any]:
        """导出结果数据"""
        return {
            "strategy_info": {
                "name": self.name,
                "attack_vector": self.attack_vector.value,
                "config": self.config,
                "enabled": self.enabled
            },
            "test_cases": [
                {
                    "id": tc.id,
                    "prompt": tc.prompt,
                    "expected_behavior": tc.expected_behavior,
                    "context": tc.context,
                    "metadata": tc.metadata,
                    "created_at": tc.created_at
                }
                for tc in self.test_cases
            ],
            "results": [
                {
                    "test_case_id": r.test_case_id,
                    "result": r.result.value,
                    "response": r.response,
                    "vulnerability_detected": r.vulnerability_detected,
                    "vulnerability_type": r.vulnerability_type.value if r.vulnerability_type else None,
                    "severity": r.severity.value if r.severity else None,
                    "confidence_score": r.confidence_score,
                    "evidence": r.evidence,
                    "metrics": r.metrics,
                    "execution_time": r.execution_time,
                    "error_message": r.error_message,
                    "timestamp": r.timestamp
                }
                for r in self.results
            ],
            "summary": self.get_vulnerability_summary(),
            "stats": self.stats.copy()
        }
    
    def reset(self):
        """重置策略状态"""
        self.test_cases.clear()
        self.results.clear()
        self.stats = {
            "total_tests": 0,
            "successful_attacks": 0,
            "vulnerabilities_found": 0,
            "average_confidence": 0.0,
            "execution_time": 0.0
        }
        logger.info(f"策略 {self.name} 状态已重置")
    
    def __str__(self) -> str:
        return f"Strategy({self.name}, {self.attack_vector.value}, enabled={self.enabled})"
    
    def __repr__(self) -> str:
        return self.__str__()


class StrategyRegistry:
    """策略注册表"""
    
    def __init__(self):
        self._strategies: Dict[str, BaseStrategy] = {}
        self._attack_vector_map: Dict[AttackVector, List[str]] = {}
    
    def register(self, strategy: BaseStrategy):
        """注册策略"""
        self._strategies[strategy.name] = strategy
        
        # 更新攻击向量映射
        if strategy.attack_vector not in self._attack_vector_map:
            self._attack_vector_map[strategy.attack_vector] = []
        self._attack_vector_map[strategy.attack_vector].append(strategy.name)
        
        logger.info(f"注册策略: {strategy.name} ({strategy.attack_vector.value})")
    
    def get_strategy(self, name: str) -> Optional[BaseStrategy]:
        """获取策略"""
        return self._strategies.get(name)
    
    def get_strategies_by_vector(self, attack_vector: AttackVector) -> List[BaseStrategy]:
        """根据攻击向量获取策略"""
        strategy_names = self._attack_vector_map.get(attack_vector, [])
        return [self._strategies[name] for name in strategy_names]
    
    def get_all_strategies(self) -> List[BaseStrategy]:
        """获取所有策略"""
        return list(self._strategies.values())
    
    def get_enabled_strategies(self) -> List[BaseStrategy]:
        """获取启用的策略"""
        return [s for s in self._strategies.values() if s.enabled]
    
    def list_strategies(self) -> Dict[str, Dict[str, Any]]:
        """列出所有策略信息"""
        return {
            name: {
                "attack_vector": strategy.attack_vector.value,
                "enabled": strategy.enabled,
                "test_cases_count": len(strategy.test_cases),
                "results_count": len(strategy.results),
                "stats": strategy.stats.copy()
            }
            for name, strategy in self._strategies.items()
        }


# 全局策略注册表
strategy_registry = StrategyRegistry()