#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import os
from pathlib import Path

def validate_findings():
    """验证生成的findings文件"""
    output_dir = Path("output/kaggle_submission")
    
    if not output_dir.exists():
        print("❌ 输出目录不存在")
        return False
    
    files = [
        "prompt_injection_findings.json",
        "jailbreaking_findings.json", 
        "data_leakage_findings.json",
        "other_findings.json"
    ]
    
    all_valid = True
    total_findings = 0
    
    for filename in files:
        filepath = output_dir / filename
        
        if not filepath.exists():
            print(f"❌ 文件不存在: {filename}")
            all_valid = False
            continue
            
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                data = json.load(f)
                
            if isinstance(data, list):
                findings_count = len(data)
                total_findings += findings_count
                print(f"✓ {filename}: 有效JSON，包含 {findings_count} 个findings")
                
                # 验证每个finding的基本结构
                for i, finding in enumerate(data):
                    required_fields = [
                        'schema_version', 'issue_title', 'model', 
                        'environment', 'issue_summary', 
                        'harmony_response_walkthroughs', 
                        'steps_to_reproduce', 'notes'
                    ]
                    
                    missing_fields = []
                    for field in required_fields:
                        if field not in finding:
                            missing_fields.append(field)
                    
                    if missing_fields:
                        print(f"  ⚠️  Finding {i+1} 缺少字段: {missing_fields}")
                        all_valid = False
                    else:
                        print(f"  ✓ Finding {i+1} 结构完整")
            else:
                print(f"❌ {filename}: 不是有效的findings数组")
                all_valid = False
                
        except json.JSONDecodeError as e:
            print(f"❌ {filename}: JSON格式错误 - {e}")
            all_valid = False
        except Exception as e:
            print(f"❌ {filename}: 读取错误 - {e}")
            all_valid = False
    
    print(f"\n=== 验证结果 ===")
    print(f"总计findings: {total_findings}")
    
    if all_valid:
        print("✅ 所有文件验证通过！")
        print("\n这些文件可以直接上传到Kaggle作为数据集提交。")
    else:
        print("❌ 部分文件验证失败，请检查错误信息。")
    
    return all_valid

if __name__ == "__main__":
    validate_findings()