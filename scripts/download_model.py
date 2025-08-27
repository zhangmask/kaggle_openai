#!/usr/bin/env python3
"""
GPT-OSS-20B模型下载和配置脚本

提供命令行接口来下载、验证和配置GPT-OSS-20B模型。
支持多种下载选项和设备配置。
"""

import os
import sys
import argparse
import time
from pathlib import Path

# 添加项目根目录到Python路径
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from src.core import settings, logger
from src.models import model_manager


def parse_arguments():
    """解析命令行参数"""
    parser = argparse.ArgumentParser(
        description="GPT-OSS-20B模型下载和配置工具",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例用法:
  python scripts/download_model.py --download                    # 下载模型
  python scripts/download_model.py --download --force           # 强制重新下载
  python scripts/download_model.py --test                       # 测试模型加载
  python scripts/download_model.py --test --device cuda         # 在GPU上测试
  python scripts/download_model.py --info                       # 显示模型信息
  python scripts/download_model.py --download --test            # 下载并测试
        """
    )
    
    parser.add_argument(
        "--download", "-d",
        action="store_true",
        help="下载GPT-OSS-20B模型"
    )
    
    parser.add_argument(
        "--force", "-f",
        action="store_true",
        help="强制重新下载模型（即使已存在）"
    )
    
    parser.add_argument(
        "--test", "-t",
        action="store_true",
        help="测试模型加载和推理"
    )
    
    parser.add_argument(
        "--device",
        choices=["auto", "cpu", "cuda", "mps"],
        default="auto",
        help="指定设备类型（默认: auto）"
    )
    
    parser.add_argument(
        "--quantization", "-q",
        choices=["none", "int8", "int4"],
        default="none",
        help="量化类型（默认: none）"
    )
    
    parser.add_argument(
        "--info", "-i",
        action="store_true",
        help="显示模型和系统信息"
    )
    
    parser.add_argument(
        "--prompt", "-p",
        type=str,
        default="Hello, I am GPT-OSS-20B. How can I help you today?",
        help="测试用的提示词（默认: 问候语）"
    )
    
    parser.add_argument(
        "--max-tokens",
        type=int,
        default=100,
        help="生成的最大token数（默认: 100）"
    )
    
    parser.add_argument(
        "--temperature",
        type=float,
        default=0.7,
        help="生成温度（默认: 0.7）"
    )
    
    parser.add_argument(
        "--ollama",
        action="store_true",
        help="使用Ollama下载和运行模型"
    )
    
    return parser.parse_args()


def show_system_info():
    """显示系统信息"""
    import torch
    import psutil
    
    print("\n=== 系统信息 ===")
    print(f"Python版本: {sys.version}")
    print(f"PyTorch版本: {torch.__version__}")
    print(f"CUDA可用: {torch.cuda.is_available()}")
    
    if torch.cuda.is_available():
        print(f"CUDA版本: {torch.version.cuda}")
        print(f"GPU数量: {torch.cuda.device_count()}")
        for i in range(torch.cuda.device_count()):
            gpu_name = torch.cuda.get_device_name(i)
            gpu_memory = torch.cuda.get_device_properties(i).total_memory / 1024**3
            print(f"  GPU {i}: {gpu_name} ({gpu_memory:.1f}GB)")
    
    # 内存信息
    memory = psutil.virtual_memory()
    print(f"系统内存: {memory.total / 1024**3:.1f}GB (可用: {memory.available / 1024**3:.1f}GB)")
    
    # 磁盘空间
    disk = psutil.disk_usage('.')
    print(f"磁盘空间: {disk.total / 1024**3:.1f}GB (可用: {disk.free / 1024**3:.1f}GB)")


def show_model_info():
    """显示模型信息"""
    print("\n=== 模型配置 ===")
    print(f"模型名称: {settings.model_name}")
    print(f"模型路径: {settings.model_path}")
    print(f"缓存目录: {settings.hf_cache_dir}")
    print(f"设备: {settings.model_device.value}")
    print(f"量化: {settings.model_quantization.value}")
    print(f"最大tokens: {settings.max_tokens}")
    print(f"温度: {settings.temperature}")
    
    # 检查模型文件是否存在
    model_path = Path(settings.model_path)
    if model_path.exists():
        print(f"\n模型状态: 已下载")
        
        # 统计文件大小
        total_size = 0
        file_count = 0
        for file_path in model_path.rglob("*"):
            if file_path.is_file():
                total_size += file_path.stat().st_size
                file_count += 1
        
        print(f"文件数量: {file_count}")
        print(f"总大小: {total_size / 1024**3:.2f}GB")
    else:
        print(f"\n模型状态: 未下载")


def download_model(force: bool = False):
    """下载模型"""
    print("\n=== 下载模型 ===")
    
    if not force:
        model_path = Path(settings.model_path)
        if model_path.exists():
            print(f"模型已存在: {model_path}")
            response = input("是否重新下载? (y/N): ")
            if response.lower() not in ['y', 'yes']:
                print("跳过下载")
                return True
    
    print(f"开始下载 {settings.model_name}...")
    start_time = time.time()
    
    success = model_manager.download_model(force_download=force)
    
    if success:
        download_time = time.time() - start_time
        print(f"✅ 模型下载成功！耗时: {download_time:.2f}秒")
        return True
    else:
        print("❌ 模型下载失败")
        return False


def test_model(device: str = "auto", quantization: str = "none", 
               prompt: str = None, max_tokens: int = 100, 
               temperature: float = 0.7):
    """测试模型加载和推理"""
    print("\n=== 测试模型 ===")
    
    # 检查模型是否存在（对于预训练模型如gpt2，可以直接从transformers加载）
    model_path = Path(settings.model_path)
    if not model_path.exists() and settings.model_name not in ['gpt2', 'gpt2-medium', 'gpt2-large', 'gpt2-xl']:
        print("❌ 模型未下载，请先运行 --download")
        return False
    elif settings.model_name in ['gpt2', 'gpt2-medium', 'gpt2-large', 'gpt2-xl']:
        print(f"使用预训练模型: {settings.model_name}（将从transformers库自动下载）")
    
    try:
        # 加载模型
        print(f"加载模型到设备: {device}")
        if quantization != "none":
            print(f"使用量化: {quantization}")
        
        start_time = time.time()
        success = model_manager.load_model(device=device, quantization=quantization)
        
        if not success:
            print("❌ 模型加载失败")
            return False
        
        load_time = time.time() - start_time
        print(f"✅ 模型加载成功！耗时: {load_time:.2f}秒")
        
        # 显示模型信息
        model_info = model_manager.get_model_info()
        print(f"\n模型参数: {model_info['parameters']:,}")
        print(f"设备: {model_info['device']}")
        print(f"数据类型: {model_info['torch_dtype']}")
        
        # 内存使用情况
        memory_usage = model_info['memory_usage']
        print(f"内存使用: {memory_usage['ram_mb']:.1f}MB")
        if 'gpu_mb' in memory_usage:
            print(f"GPU内存: {memory_usage['gpu_mb']:.1f}MB")
        
        # 测试推理
        if prompt:
            print(f"\n=== 测试推理 ===")
            print(f"提示词: {prompt}")
            print(f"参数: max_tokens={max_tokens}, temperature={temperature}")
            
            start_time = time.time()
            result = model_manager.generate_response(
                prompt,
                max_new_tokens=max_tokens,
                temperature=temperature
            )
            
            inference_time = time.time() - start_time
            
            print(f"\n生成结果:")
            print(f"输入tokens: {result['input_tokens']}")
            print(f"输出tokens: {result['output_tokens']}")
            print(f"推理时间: {result['inference_time']:.2f}秒")
            print(f"生成速度: {result['tokens_per_second']:.1f} tokens/秒")
            print(f"\n响应内容:")
            print(f"{result['response']}")
        
        return True
        
    except Exception as e:
        print(f"❌ 测试失败: {str(e)}")
        return False
    
    finally:
        # 卸载模型释放内存
        if model_manager.is_loaded:
            print("\n卸载模型...")
            model_manager.unload_model()


def download_with_ollama():
    """使用Ollama下载模型"""
    print("\n=== 使用Ollama下载模型 ===")
    
    # 首先检查Ollama是否安装
    try:
        import subprocess
        result = subprocess.run(["ollama", "--version"], 
                              capture_output=True, text=True, encoding='utf-8', errors='ignore')
        if result.returncode != 0:
            print("❌ Ollama未安装或不在PATH中")
            print("请访问 https://ollama.ai 下载并安装Ollama")
            return False
        print(f"✅ 检测到Ollama: {result.stdout.strip()}")
    except FileNotFoundError:
        print("❌ Ollama未安装或不在PATH中")
        print("请访问 https://ollama.ai 下载并安装Ollama")
        return False
    except Exception as e:
        print(f"❌ 检查Ollama时出错: {str(e)}")
        return False
    
    # 尝试下载GPT-OSS-20B模型，如果失败则下载llama2作为替代
    models_to_try = ["gpt-oss:20b", "llama2"]
    
    for model_name in models_to_try:
        try:
            print(f"正在下载{model_name}模型，这可能需要几分钟...")
            result = subprocess.run(["ollama", "pull", model_name], 
                                  capture_output=True, text=True, encoding='utf-8', errors='ignore')
            if result.returncode == 0:
                print(f"✅ {model_name}模型下载成功")
                print("模型现在可以通过Ollama API使用")
                print(f"可以使用命令测试: ollama run {model_name}")
                return True
            else:
                print(f"❌ {model_name}下载失败: {result.stderr}")
                if "newer version" in result.stderr:
                    print("当前Ollama版本过旧，尝试下载其他模型...")
                    continue
        except Exception as e:
            print(f"❌ {model_name}下载异常: {str(e)}")
            continue
    
    print("❌ 所有模型下载都失败了")
    print("建议更新Ollama到最新版本: https://ollama.com/download")
    return False


def main():
    """主函数"""
    args = parse_arguments()
    
    print("GPT-OSS-20B 模型管理工具")
    print("=" * 50)
    
    # 显示信息
    if args.info or not any([args.download, args.test]):
        show_system_info()
        show_model_info()
    
    success = True
    
    # 下载模型
    if args.download:
        if args.ollama:
            success = download_with_ollama()
        else:
            success = download_model(force=args.force)
        if not success:
            sys.exit(1)
    
    # 测试模型
    if args.test:
        success = test_model(
            device=args.device,
            quantization=args.quantization,
            prompt=args.prompt,
            max_tokens=args.max_tokens,
            temperature=args.temperature
        )
        if not success:
            sys.exit(1)
    
    if success:
        print("\n✅ 所有操作完成！")
    else:
        print("\n❌ 操作失败")
        sys.exit(1)


if __name__ == "__main__":
    main()