#!/usr/bin/env python3
"""
模型管理器

负责GPT-OSS-20B模型的下载、加载、配置和推理管理。
支持多种设备、量化选项和推理优化。
"""

import os
import time
import torch
import psutil
from pathlib import Path
from typing import Optional, Dict, Any, List, Union
from transformers import (
    AutoTokenizer, AutoModelForCausalLM, AutoConfig,
    BitsAndBytesConfig, GenerationConfig
)
from huggingface_hub import hf_hub_download, snapshot_download
from accelerate import init_empty_weights, load_checkpoint_and_dispatch
import subprocess
import shutil
import requests
import json

from ..core import settings, logger, model_logger, ModelDevice, ModelQuantization


class ModelManager:
    """GPT-OSS-20B模型管理器"""
    
    def __init__(self):
        self.model = None
        self.tokenizer = None
        self.config = None
        self.generation_config = None
        self.device = None
        self.is_loaded = False
        self.model_info = {}
        
        # 性能统计
        self.inference_stats = {
            "total_requests": 0,
            "total_tokens_generated": 0,
            "total_inference_time": 0.0,
            "average_tokens_per_second": 0.0
        }
    
    def download_model(self, force: bool = False) -> bool:
        """
        下载模型到本地
        
        Args:
            force: 是否强制重新下载
            
        Returns:
            bool: 下载是否成功
        """
        try:
            # 优先尝试使用Ollama下载
            if self._download_with_ollama(force):
                logger.info("使用Ollama下载成功")
                return True
            
            model_path = Path(settings.model_path)
            
            # 检查模型是否已存在
            if model_path.exists() and any(model_path.iterdir()) and not force:
                logger.info(f"模型已存在: {model_path}")
                return True
            
            # 创建模型目录
            model_path.mkdir(parents=True, exist_ok=True)
            
            # 尝试使用huggingface-cli命令下载
            if self._download_with_hf_cli(model_path):
                logger.info("使用huggingface-cli命令下载成功")
                return True
            
            # 回退到Python API
            logger.info("huggingface-cli命令下载失败，尝试使用Python API...")
            return self._download_with_python_api(model_path)
            
        except Exception as e:
            logger.error(f"下载模型失败: {e}")
            return False
    
    def _download_with_ollama(self, force: bool = False) -> bool:
        """
        使用Ollama下载模型
        
        Args:
            force: 是否强制重新下载
            
        Returns:
            bool: 下载是否成功
        """
        try:
            # 检查Ollama是否安装
            if not shutil.which("ollama"):
                logger.warning("Ollama未安装，请从 https://ollama.ai 下载安装")
                return False
            
            logger.info("使用Ollama下载GPT-OSS-20B模型...")
            
            # 检查模型是否已存在（除非强制下载）
            if not force:
                check_cmd = ["ollama", "list"]
                result = subprocess.run(check_cmd, capture_output=True, text=True)
                if result.returncode == 0 and "gpt-oss:20b" in result.stdout:
                    logger.info("Ollama中已存在gpt-oss:20b模型")
                    return True
            
            # 下载模型
            cmd = ["ollama", "pull", "gpt-oss:20b"]
            
            logger.info("开始下载模型，这可能需要一些时间...")
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=3600  # 1小时超时
            )
            
            if result.returncode == 0:
                logger.info("Ollama模型下载成功")
                return True
            else:
                logger.error(f"Ollama下载失败: {result.stderr}")
                return False
                
        except subprocess.TimeoutExpired:
            logger.error("Ollama下载超时")
            return False
        except Exception as e:
            logger.error(f"Ollama下载异常: {e}")
            return False
    
    def _download_with_hf_cli(self, model_path: Path) -> bool:
        """使用hf命令行工具下载模型（官方推荐方法）"""
        try:
            import subprocess
            import shutil
            
            # 检查huggingface-cli命令是否可用
            if not shutil.which("huggingface-cli"):
                logger.warning("huggingface-cli命令未找到，请安装: pip install huggingface_hub[cli]")
                return False
            
            logger.info("使用huggingface-cli命令下载模型...")
            
            # 构建huggingface-cli下载命令（根据官方文档）
            cmd = [
                "huggingface-cli", "download", 
                settings.model_name,
                "--include", "original/*",
                "--local-dir", str(model_path)
            ]
            
            # 添加token（如果有）
            if settings.hf_token:
                cmd.extend(["--token", settings.hf_token])
            
            logger.info(f"执行命令: {' '.join(cmd)}")
            
            # 执行下载命令
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=3600  # 1小时超时
            )
            
            if result.returncode == 0:
                logger.info("hf命令下载成功")
                return True
            else:
                logger.error(f"hf命令下载失败: {result.stderr}")
                return False
                
        except subprocess.TimeoutExpired:
            logger.error("hf命令下载超时")
            return False
        except Exception as e:
            logger.error(f"hf命令下载异常: {str(e)}")
            return False
    
    def _download_with_python_api(self, model_path: Path) -> bool:
        """使用Python API下载模型（备用方法）"""
        try:
            logger.info("使用Python API下载模型...")
            
            # 使用snapshot_download下载整个模型
            downloaded_path = snapshot_download(
                repo_id=settings.model_name,
                cache_dir=settings.hf_cache_dir,
                local_dir=str(model_path),
                token=settings.hf_token,
                resume_download=True,
                local_dir_use_symlinks=False
            )
            
            logger.info(f"Python API下载成功: {downloaded_path}")
            return True
            
        except Exception as e:
            logger.error(f"Python API下载失败: {str(e)}")
            return False
    
    def _verify_model_files(self, model_path: Path) -> bool:
        """验证模型文件完整性"""
        required_files = [
            "config.json",
            "tokenizer.json",
            "tokenizer_config.json"
        ]
        
        missing_files = []
        for file_name in required_files:
            if not (model_path / file_name).exists():
                missing_files.append(file_name)
        
        if missing_files:
            logger.error(f"缺少必要文件: {missing_files}")
            return False
        
        # 检查模型权重文件
        weight_files = list(model_path.glob("*.safetensors")) + list(model_path.glob("*.bin"))
        if not weight_files:
            logger.error("未找到模型权重文件")
            return False
        
        logger.info(f"模型文件验证通过，找到 {len(weight_files)} 个权重文件")
        return True
    
    def _is_ollama_available(self) -> bool:
        """检查Ollama是否可用"""
        try:
            result = subprocess.run(["ollama", "--version"], 
                                  capture_output=True, text=True, 
                                  encoding='utf-8', errors='ignore')
            return result.returncode == 0
        except (FileNotFoundError, subprocess.SubprocessError):
            return False
    
    def load_model(self, device: Optional[str] = None, 
                  quantization: Optional[str] = None) -> bool:
        """加载模型到内存"""
        try:
            # 检查是否使用Ollama
            if self._is_ollama_available():
                logger.info("检测到Ollama，将使用Ollama API")
                self.use_ollama = True
                self.is_loaded = True  # 标记为已加载
                return True
            
            if self.is_loaded:
                logger.warning("模型已加载")
                return True
            
            start_time = time.time()
            
            # 确定设备
            self.device = self._determine_device(device)
            logger.info(f"使用设备: {self.device}")
            
            # 确定量化配置
            quant_config = self._get_quantization_config(quantization)
            
            # 加载配置
            self.config = AutoConfig.from_pretrained(
                settings.model_path,
                trust_remote_code=True
            )
            
            # 加载分词器
            logger.info("加载分词器...")
            self.tokenizer = AutoTokenizer.from_pretrained(
                settings.model_path,
                trust_remote_code=True,
                padding_side="left"
            )
            
            # 设置pad_token
            if self.tokenizer.pad_token is None:
                self.tokenizer.pad_token = self.tokenizer.eos_token
            
            # 加载模型
            logger.info("加载模型权重...")
            
            model_kwargs = {
                "config": self.config,
                "trust_remote_code": True,
                "torch_dtype": torch.float16 if self.device != "cpu" else torch.float32,
                "low_cpu_mem_usage": True
            }
            
            # 添加量化配置
            if quant_config:
                model_kwargs["quantization_config"] = quant_config
            
            # 根据设备类型加载模型
            if self.device == "cpu":
                model_kwargs["torch_dtype"] = torch.float32
                self.model = AutoModelForCausalLM.from_pretrained(
                    settings.model_path,
                    **model_kwargs
                )
            else:
                self.model = AutoModelForCausalLM.from_pretrained(
                    settings.model_path,
                    device_map="auto",
                    **model_kwargs
                )
            
            # 设置生成配置
            self._setup_generation_config()
            
            # 记录模型信息
            self._record_model_info()
            
            load_time = time.time() - start_time
            self.is_loaded = True
            
            model_logger.log_model_load(settings.model_name, self.device, load_time)
            logger.info(f"模型加载完成，耗时: {load_time:.2f}秒")
            
            return True
            
        except Exception as e:
            logger.error(f"模型加载失败: {str(e)}")
            return False
    
    def _determine_device(self, device: Optional[str] = None) -> str:
        """确定使用的设备"""
        if device:
            return device
        
        device_setting = settings.model_device.value
        
        if device_setting == "auto":
            if torch.cuda.is_available():
                return "cuda"
            elif hasattr(torch.backends, "mps") and torch.backends.mps.is_available():
                return "mps"
            else:
                return "cpu"
        
        return device_setting
    
    def _get_quantization_config(self, quantization: Optional[str] = None) -> Optional[BitsAndBytesConfig]:
        """获取量化配置"""
        quant_setting = quantization or settings.model_quantization.value
        
        if quant_setting == "none":
            return None
        elif quant_setting == "int8":
            return BitsAndBytesConfig(
                load_in_8bit=True,
                llm_int8_threshold=6.0,
                llm_int8_has_fp16_weight=False
            )
        elif quant_setting == "int4":
            return BitsAndBytesConfig(
                load_in_4bit=True,
                bnb_4bit_compute_dtype=torch.float16,
                bnb_4bit_use_double_quant=True,
                bnb_4bit_quant_type="nf4"
            )
        
        return None
    
    def _setup_generation_config(self):
        """设置生成配置"""
        self.generation_config = GenerationConfig(
            max_new_tokens=settings.max_tokens,
            temperature=settings.temperature,
            top_p=settings.top_p,
            top_k=settings.top_k,
            do_sample=True,
            pad_token_id=self.tokenizer.pad_token_id,
            eos_token_id=self.tokenizer.eos_token_id,
            repetition_penalty=1.1,
            length_penalty=1.0
        )
    
    def _record_model_info(self):
        """记录模型信息"""
        self.model_info = {
            "model_name": settings.model_name,
            "device": self.device,
            "quantization": settings.model_quantization.value,
            "parameters": self._count_parameters(),
            "memory_usage": self._get_memory_usage(),
            "torch_dtype": str(self.model.dtype) if self.model else None
        }
        
        logger.info(f"模型信息: {self.model_info}")
    
    def _count_parameters(self) -> int:
        """统计模型参数数量"""
        if not self.model:
            return 0
        return sum(p.numel() for p in self.model.parameters())
    
    def _get_memory_usage(self) -> Dict[str, float]:
        """获取内存使用情况"""
        memory_info = {
            "ram_mb": psutil.virtual_memory().used / 1024 / 1024
        }
        
        if torch.cuda.is_available() and self.device == "cuda":
            memory_info["gpu_mb"] = torch.cuda.memory_allocated() / 1024 / 1024
            memory_info["gpu_reserved_mb"] = torch.cuda.memory_reserved() / 1024 / 1024
        
        return memory_info
    
    def generate_response(self, prompt: str, **generation_kwargs) -> Dict[str, Any]:
        """生成模型响应"""
        if not self.is_loaded:
            raise RuntimeError("模型未加载")
        
        start_time = time.time()
        
        try:
            # 如果使用Ollama，调用Ollama API
            if hasattr(self, 'use_ollama') and self.use_ollama:
                return self._generate_with_ollama(prompt, **generation_kwargs)
            
            # 编码输入
            inputs = self.tokenizer(
                prompt,
                return_tensors="pt",
                padding=True,
                truncation=True,
                max_length=4096
            )
            
            if self.device != "cpu":
                inputs = {k: v.to(self.device) for k, v in inputs.items()}
            
            input_length = inputs["input_ids"].shape[1]
            
            # 合并生成参数
            gen_config = self.generation_config
            for key, value in generation_kwargs.items():
                setattr(gen_config, key, value)
            
            # 生成响应
            with torch.no_grad():
                outputs = self.model.generate(
                    **inputs,
                    generation_config=gen_config,
                    return_dict_in_generate=True,
                    output_scores=True
                )
            
            # 解码响应
            generated_tokens = outputs.sequences[0][input_length:]
            response = self.tokenizer.decode(generated_tokens, skip_special_tokens=True)
            
            # 计算统计信息
            inference_time = time.time() - start_time
            output_length = len(generated_tokens)
            tokens_per_second = output_length / inference_time if inference_time > 0 else 0
            
            # 更新统计
            self._update_inference_stats(input_length, output_length, inference_time)
            
            # 记录推理统计
            model_logger.log_inference(input_length, output_length, inference_time)
            
            return {
                "response": response,
                "input_tokens": input_length,
                "output_tokens": output_length,
                "inference_time": inference_time,
                "tokens_per_second": tokens_per_second,
                "memory_usage": self._get_memory_usage()
            }
            
        except Exception as e:
            logger.error(f"生成响应失败: {str(e)}")
            raise
    
    def _update_inference_stats(self, input_tokens: int, output_tokens: int, inference_time: float):
        """更新推理统计信息"""
        self.inference_stats["total_requests"] += 1
        self.inference_stats["total_tokens_generated"] += output_tokens
        self.inference_stats["total_inference_time"] += inference_time
        
        if self.inference_stats["total_inference_time"] > 0:
            self.inference_stats["average_tokens_per_second"] = (
                self.inference_stats["total_tokens_generated"] / 
                self.inference_stats["total_inference_time"]
            )
    
    def batch_generate(self, prompts: List[str], **generation_kwargs) -> List[Dict[str, Any]]:
        """批量生成响应"""
        if not self.is_loaded:
            raise RuntimeError("模型未加载")
        
        results = []
        
        # 简单的批处理实现（可以优化为真正的批处理）
        for prompt in prompts:
            try:
                result = self.generate_response(prompt, **generation_kwargs)
                results.append(result)
            except Exception as e:
                logger.error(f"批量生成失败，提示: {prompt[:50]}..., 错误: {str(e)}")
                results.append({
                    "response": "",
                    "error": str(e),
                    "input_tokens": 0,
                    "output_tokens": 0,
                    "inference_time": 0,
                    "tokens_per_second": 0
                })
        
        return results
    
    def get_model_info(self) -> Dict[str, Any]:
        """获取模型信息"""
        return {
            **self.model_info,
            "is_loaded": self.is_loaded,
            "inference_stats": self.inference_stats.copy()
        }
    
    def is_model_loaded(self) -> bool:
        """检查模型是否已加载"""
        return self.is_loaded or getattr(self, 'use_ollama', False)
    
    def unload_model(self):
        """卸载模型释放内存"""
        if self.model:
            del self.model
            self.model = None
        
        if self.tokenizer:
            del self.tokenizer
            self.tokenizer = None
        
        # 清理GPU缓存
        if torch.cuda.is_available():
            torch.cuda.empty_cache()
        
        self.is_loaded = False
        logger.info("模型已卸载")
    
    def _generate_with_ollama(self, prompt: str, **generation_kwargs) -> Dict[str, Any]:
        """
        使用Ollama API生成响应
        
        Args:
            prompt: 输入提示
            **generation_kwargs: 生成参数
            
        Returns:
            Dict[str, Any]: 生成结果
        """
        start_time = time.time()
        
        try:
            # 构建请求数据
            data = {
                "model": "gpt-oss:20b",  # 使用正确的GPT-OSS-20B模型名称
                "prompt": prompt,
                "stream": False
            }
            
            # 添加生成参数
            if "temperature" in generation_kwargs:
                data["options"] = data.get("options", {})
                data["options"]["temperature"] = generation_kwargs["temperature"]
            
            if "max_new_tokens" in generation_kwargs:
                data["options"] = data.get("options", {})
                data["options"]["num_predict"] = generation_kwargs["max_new_tokens"]
            
            # 发送请求到Ollama API
            response = requests.post(
                "http://localhost:11434/api/generate",
                json=data,
                timeout=300  # 5分钟超时
            )
            
            if response.status_code == 200:
                result = response.json()
                generated_text = result.get("response", "")
                
                # 计算统计信息
                inference_time = time.time() - start_time
                input_tokens = len(prompt.split())  # 简单估算
                output_tokens = len(generated_text.split())  # 简单估算
                tokens_per_second = output_tokens / inference_time if inference_time > 0 else 0
                
                # 更新统计
                self._update_inference_stats(input_tokens, output_tokens, inference_time)
                
                return {
                    "response": generated_text,
                    "input_tokens": input_tokens,
                    "output_tokens": output_tokens,
                    "inference_time": inference_time,
                    "tokens_per_second": tokens_per_second,
                    "memory_usage": self._get_memory_usage()
                }
            else:
                raise RuntimeError(f"Ollama API请求失败: {response.status_code} - {response.text}")
                
        except requests.exceptions.RequestException as e:
            logger.error(f"Ollama API连接失败: {e}")
            raise RuntimeError(f"无法连接到Ollama服务: {e}")
        except Exception as e:
            logger.error(f"Ollama生成失败: {e}")
            raise
    
    def __del__(self):
        """析构函数"""
        if self.is_loaded:
            self.unload_model()


# 全局模型管理器实例
model_manager = ModelManager()