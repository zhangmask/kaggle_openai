# Kaggle Findings Generator 使用指南

本项目提供了一个完整的红队测试框架，能够生成符合Kaggle竞赛要求的findings.json文件。

## 快速开始

### 1. 生成演示findings

```bash
python scripts/generate_kaggle_findings.py --mode demo --validate
```

这将生成4个示例findings文件：
- `prompt_injection_findings.json` - 提示注入漏洞
- `jailbreaking_findings.json` - 越狱攻击漏洞
- `data_leakage_findings.json` - 数据泄露漏洞
- `other_findings.json` - 其他类型漏洞（基于Kaggle示例）

### 2. 运行实际红队测试

```bash
python scripts/generate_kaggle_findings.py --mode test --max-tests 5 --validate
```

参数说明：
- `--mode test`: 运行实际的红队测试
- `--max-tests 5`: 每个策略最多运行5个测试用例
- `--validate`: 验证生成的JSON文件格式

### 3. 批量生成findings

```bash
python scripts/generate_kaggle_findings.py --mode batch --count 10
```

## 输出文件格式

生成的findings文件完全符合Kaggle竞赛要求，包含以下字段：

```json
{
  "schema_version": "1.0.0",
  "issue_title": "漏洞标题",
  "model": {
    "name": "gpt-oss-20b",
    "version": "2025-08-18",
    "vendor": "OpenAI",
    "parameters": {...}
  },
  "environment": {
    "endpoint": "red-team-testing"
  },
  "issue_summary": {
    "title": "问题标题",
    "topic_area": "主题领域",
    "overview": "概述",
    "desired_behavior": "期望行为",
    "observed_behavior": "观察到的行为",
    "self_assessed_severity": "严重性评分",
    "self_assessed_severity_justification": "严重性理由",
    "self_assessed_breadth": "广度评分",
    "self_assessed_breadth_justification": "广度理由"
  },
  "harmony_response_walkthroughs": [
    "<|start|>system<|message|>...<|end|>..."
  ],
  "steps_to_reproduce": [
    "重现步骤1",
    "重现步骤2",
    "重现步骤3"
  ],
  "notes": "附加说明"
}
```

## 支持的攻击类型

1. **Prompt Injection** - 提示注入攻击
2. **Jailbreaking** - 越狱攻击
3. **Data Leakage** - 数据泄露攻击

## 文件输出位置

所有生成的findings文件保存在：
```
output/kaggle_submission/
├── prompt_injection_findings.json
├── jailbreaking_findings.json
├── data_leakage_findings.json
└── other_findings.json
```

## 上传到Kaggle

1. 将生成的JSON文件作为数据集上传到Kaggle
2. 设置许可证为CC0（推荐）
3. 在竞赛writeup中引用这些数据集
4. 确保在竞赛结束前保持数据集私密

## 验证功能

脚本包含内置的JSON格式验证功能：
- 检查JSON语法正确性
- 验证必需字段存在
- 确保harmony_response_walkthroughs格式正确
- 验证转义字符处理

## 注意事项

1. **JSON转义**：所有对话内容都经过正确的JSON转义处理
2. **格式兼容性**：完全符合Kaggle竞赛的提交格式要求
3. **自动化测试**：支持大规模自动化红队测试
4. **可扩展性**：易于添加新的攻击策略和测试用例

## 故障排除

如果遇到问题，请检查：
1. Python依赖是否正确安装
2. 输出目录是否有写入权限
3. JSON文件格式是否通过验证

更多详细信息请参考项目文档。