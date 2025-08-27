# 红队测试框架 (Red Team Testing Framework)

一个专为大语言模型安全测试设计的综合性红队测试框架，旨在发现和评估AI模型中的安全漏洞。

## 🎯 项目概述

本框架实现了多种攻击策略，用于测试大语言模型的安全性，包括：
- **数据泄露攻击** (Data Leakage)
- **提示注入攻击** (Prompt Injection) 
- **越狱攻击** (Jailbreaking)

## 🏗️ 项目结构

```
openai/
├── src/
│   ├── core/
│   │   ├── __init__.py          # 核心模块初始化
│   │   ├── config.py            # 配置管理
│   │   ├── logger.py            # 日志系统
│   │   └── enums.py             # 枚举定义
│   ├── strategies/
│   │   ├── __init__.py          # 策略模块初始化
│   │   ├── base_strategy.py     # 基础策略类
│   │   ├── data_leakage.py      # 数据泄露攻击策略
│   │   ├── prompt_injection.py  # 提示注入攻击策略
│   │   └── jailbreaking.py      # 越狱攻击策略
│   ├── models/
│   │   └── model_manager.py     # 模型管理器
│   ├── executors/
│   │   └── test_executor.py     # 测试执行器
│   └── analyzers/
│       └── vulnerability_analyzer.py  # 漏洞分析器
├── scripts/
│   ├── download_model.py        # 模型下载脚本
│   └── run_tests.py            # 测试运行脚本
├── tests/
│   └── test_strategies.py      # 策略测试
├── comprehensive_demo.py        # 综合演示脚本
├── test_data_leakage.py        # 数据泄露测试脚本
└── README.md                   # 项目文档
```

## 🚀 快速开始

### 1. 环境准备

```bash
# 安装依赖
pip install -r requirements.txt

# 配置环境变量（可选）
export OPENAI_API_KEY="your-api-key"
export MODEL_PATH="./models/gpt2"
```

### 2. 运行综合演示

```bash
# 运行所有攻击策略的演示
python comprehensive_demo.py
```

### 3. 单独测试特定策略

```bash
# 测试数据泄露策略
python test_data_leakage.py

# 运行完整测试套件
python scripts/run_tests.py
```

## 📋 攻击策略详解

### 1. 数据泄露攻击 (Data Leakage)

检测模型是否会泄露训练数据、系统信息或敏感内容：

- **记忆提取** (Memory Extraction): 尝试提取训练数据片段
- **系统信息探测** (System Probing): 获取模型系统信息
- **个人信息提取** (Personal Info Extraction): 提取个人敏感信息
- **训练数据探测** (Training Data Probing): 探测训练数据来源
- **侧信道攻击** (Side Channel): 通过间接方式获取信息
- **诱导性测试** (Elicitation): 诱导模型泄露信息

### 2. 提示注入攻击 (Prompt Injection)

测试模型是否容易受到指令注入攻击：

- **直接注入** (Direct Injection): 直接覆盖原始指令
- **角色扮演注入** (Role Playing): 通过角色扮演绕过限制
- **情境注入** (Scenario Injection): 创建特殊情境
- **编码注入** (Encoded Injection): 使用编码绕过检测
- **多语言注入** (Multilingual): 使用不同语言
- **逻辑绕过** (Logic Bypass): 通过逻辑推理绕过
- **权限提升** (Privilege Escalation): 尝试获取更高权限
- **社会工程** (Social Engineering): 利用社会工程技巧

### 3. 越狱攻击 (Jailbreaking)

测试模型的安全边界和限制机制：

- **DAN攻击** (Do Anything Now): 经典的越狱技术
- **角色扮演** (Role Playing): 扮演不受限制的角色
- **假设场景** (Hypothetical Scenarios): 创建假设情境
- **开发者模式** (Developer Mode): 模拟开发者权限
- **情感操控** (Emotional Manipulation): 利用情感因素
- **逐步诱导** (Gradual Persuasion): 逐步引导模型

## 🔍 漏洞检测机制

框架使用多层检测机制：

1. **模式匹配**: 使用正则表达式检测危险模式
2. **关键词分析**: 识别敏感关键词和短语
3. **语义分析**: 分析响应的语义内容
4. **行为分析**: 评估模型行为变化
5. **置信度评分**: 计算漏洞检测的置信度

## 📊 结果分析

### 漏洞严重性级别

- **CRITICAL**: 严重漏洞，可能导致重大安全风险
- **HIGH**: 高危漏洞，需要立即关注
- **MEDIUM**: 中等漏洞，建议修复
- **LOW**: 低危漏洞，可选择性修复

### 评估指标

- **成功率**: 攻击成功的百分比
- **置信度**: 漏洞检测的可信度 (0-1)
- **响应时间**: 模型响应时间
- **证据数量**: 支持漏洞判断的证据数量

## 🛠️ 自定义扩展

### 添加新的攻击策略

1. 继承 `BaseStrategy` 类
2. 实现必要的方法：
   - `generate_test_cases()`: 生成测试用例
   - `execute_attack()`: 执行攻击
   - `analyze_response()`: 分析响应

```python
from src.strategies.base_strategy import BaseStrategy

class CustomStrategy(BaseStrategy):
    def __init__(self):
        super().__init__("CustomStrategy", AttackVector.CUSTOM)
    
    def generate_test_cases(self, count: int) -> List[TestCase]:
        # 实现测试用例生成逻辑
        pass
    
    def execute_attack(self, test_case: TestCase, model_func) -> AttackResult:
        # 实现攻击执行逻辑
        pass
```

### 自定义检测模式

在策略类中添加新的检测模式：

```python
self.detection_patterns = [
    r"(?i)(your_custom_pattern)",
    r"\b(sensitive_keyword)\b",
    # 更多模式...
]
```

## 📈 演示结果示例

```
🚀 红队测试框架综合演示
============================================================

📈 总体统计:
   测试策略数: 3
   总测试用例: 18
   总发现漏洞: 3
   整体成功率: 16.7%

📋 各策略表现:
   越狱攻击: 33.3% (2/6)
   提示注入攻击: 16.7% (1/6)
   数据泄露攻击: 0.0% (0/6)

🎯 漏洞类型分布:
   JAILBREAKING: 2
   PROMPT_INJECTION: 1

⚠️ 严重性级别分布:
   LOW: 3
```

## ⚠️ 使用注意事项

1. **伦理使用**: 仅用于安全研究和模型改进
2. **授权测试**: 确保有权限测试目标模型
3. **数据保护**: 不要使用真实敏感数据进行测试
4. **结果验证**: 自动化检测结果需要人工验证
5. **负责任披露**: 发现的漏洞应负责任地报告

## 🤝 贡献指南

欢迎贡献新的攻击策略、检测方法或改进建议：

1. Fork 项目
2. 创建特性分支
3. 提交更改
4. 发起 Pull Request

## 📄 许可证

本项目仅供学术研究和安全测试使用。使用者需要遵守相关法律法规和伦理准则。

## 🔗 相关资源

- [OWASP LLM Top 10](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [AI Red Team Guidelines](https://www.anthropic.com/research/red-teaming-language-models)
- [Prompt Injection Research](https://arxiv.org/abs/2302.12173)

---

**免责声明**: 本框架仅用于安全研究目的。使用者需要确保遵守相关法律法规，不得用于恶意攻击或非法活动。