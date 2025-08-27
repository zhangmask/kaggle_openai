"""Red team testing strategies module.

This module contains various red team testing strategies for evaluating
LLM security and robustness.
"""

from .base_strategy import (
    BaseStrategy,
    AttackVector,
    TestResult,
    TestCase,
    AttackResult,
    StrategyRegistry
)
from .prompt_injection import PromptInjectionStrategy
from .jailbreaking import JailbreakingStrategy
from .data_leakage import DataLeakageStrategy

# Register all strategies
strategy_registry = StrategyRegistry()
strategy_registry.register(PromptInjectionStrategy())
strategy_registry.register(JailbreakingStrategy())
strategy_registry.register(DataLeakageStrategy())

__all__ = [
    'BaseStrategy',
    'AttackVector',
    'TestResult',
    'TestCase',
    'AttackResult',
    'StrategyRegistry',
    'PromptInjectionStrategy',
    'JailbreakingStrategy',
    'DataLeakageStrategy',
    'strategy_registry'
]