#!/usr/bin/env python3
"""
数据库模型定义

定义SQLAlchemy数据库模型，用于存储红队测试结果、
漏洞信息、测试历史和分析数据。
"""

import uuid
from datetime import datetime
from typing import Optional, List, Dict, Any
from sqlalchemy import (
    create_engine, Column, String, Integer, Float, Boolean, DateTime,
    Text, JSON, ForeignKey, Index, UniqueConstraint
)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship, Session
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.sql import func
from pathlib import Path

from .config import settings
from .logger import logger

# 数据库基类
Base = declarative_base()


class TimestampMixin:
    """时间戳混入类"""
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)


class TestSession(Base, TimestampMixin):
    """测试会话模型"""
    __tablename__ = "test_sessions"
    
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    name = Column(String(255), nullable=False)
    description = Column(Text)
    status = Column(String(50), default="running")  # running, completed, failed, cancelled
    model_name = Column(String(100), nullable=False)
    model_config = Column(JSON)
    test_config = Column(JSON)
    start_time = Column(DateTime, default=datetime.utcnow)
    end_time = Column(DateTime)
    total_tests = Column(Integer, default=0)
    passed_tests = Column(Integer, default=0)
    failed_tests = Column(Integer, default=0)
    vulnerabilities_found = Column(Integer, default=0)
    
    # 关系
    test_cases = relationship("TestCase", back_populates="session", cascade="all, delete-orphan")
    vulnerabilities = relationship("Vulnerability", back_populates="session", cascade="all, delete-orphan")
    
    def __repr__(self):
        return f"<TestSession(id='{self.id}', name='{self.name}', status='{self.status}')>"


class TestCase(Base, TimestampMixin):
    """测试用例模型"""
    __tablename__ = "test_cases"
    
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    session_id = Column(String, ForeignKey("test_sessions.id"), nullable=False)
    name = Column(String(255), nullable=False)
    category = Column(String(100), nullable=False)  # vulnerability type
    strategy = Column(String(100), nullable=False)
    prompt = Column(Text, nullable=False)
    expected_behavior = Column(Text)
    actual_response = Column(Text)
    status = Column(String(50), default="pending")  # pending, running, passed, failed, error
    execution_time = Column(Float)  # seconds
    error_message = Column(Text)
    test_metadata = Column(JSON)  # additional test data
    
    # 关系
    session = relationship("TestSession", back_populates="test_cases")
    analysis_results = relationship("AnalysisResult", back_populates="test_case", cascade="all, delete-orphan")
    
    # 索引
    __table_args__ = (
        Index("idx_test_cases_session_category", "session_id", "category"),
        Index("idx_test_cases_status", "status"),
    )
    
    def __repr__(self):
        return f"<TestCase(id='{self.id}', name='{self.name}', category='{self.category}')>"


class Vulnerability(Base, TimestampMixin):
    """漏洞模型"""
    __tablename__ = "vulnerabilities"
    
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    session_id = Column(String, ForeignKey("test_sessions.id"), nullable=False)
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=False)
    category = Column(String(100), nullable=False)  # vulnerability type
    severity = Column(String(50), nullable=False)  # low, medium, high, critical
    confidence = Column(Float, nullable=False)  # 0.0 - 1.0
    novelty_score = Column(Float)  # 0.0 - 1.0
    reproducibility_score = Column(Float)  # 0.0 - 1.0
    impact_score = Column(Float)  # 0.0 - 1.0
    breadth_score = Column(Float)  # 0.0 - 1.0
    methodology_score = Column(Float)  # 0.0 - 1.0
    
    # 漏洞详细信息
    trigger_prompt = Column(Text, nullable=False)
    vulnerable_response = Column(Text, nullable=False)
    attack_vector = Column(Text)
    mitigation_suggestions = Column(Text)
    references = Column(JSON)  # list of reference URLs/papers
    
    # Kaggle竞赛相关
    kaggle_severity = Column(Integer)  # 0-10
    kaggle_breadth = Column(Integer)  # 0-10
    kaggle_novelty = Column(Integer)  # 0-10
    kaggle_reproducibility = Column(Integer)  # 0-10
    kaggle_methodology = Column(Integer)  # 0-10
    
    # 状态和标记
    verified = Column(Boolean, default=False)
    false_positive = Column(Boolean, default=False)
    submitted_to_kaggle = Column(Boolean, default=False)
    submission_date = Column(DateTime)
    
    # 关系
    session = relationship("TestSession", back_populates="vulnerabilities")
    
    # 索引
    __table_args__ = (
        Index("idx_vulnerabilities_category_severity", "category", "severity"),
        Index("idx_vulnerabilities_novelty", "novelty_score"),
        Index("idx_vulnerabilities_verified", "verified"),
    )
    
    def __repr__(self):
        return f"<Vulnerability(id='{self.id}', title='{self.title}', severity='{self.severity}')>"
    
    def to_kaggle_format(self) -> Dict[str, Any]:
        """转换为Kaggle提交格式"""
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "category": self.category,
            "severity": self.kaggle_severity or 1,
            "breadth": self.kaggle_breadth or 1,
            "novelty": self.kaggle_novelty or 1,
            "reproducibility": self.kaggle_reproducibility or 1,
            "methodology": self.kaggle_methodology or 1,
            "trigger_prompt": self.trigger_prompt,
            "vulnerable_response": self.vulnerable_response,
            "attack_vector": self.attack_vector,
            "mitigation_suggestions": self.mitigation_suggestions,
            "references": self.references or [],
            "discovered_at": self.created_at.isoformat(),
            "verified": self.verified
        }


class AnalysisResult(Base, TimestampMixin):
    """分析结果模型"""
    __tablename__ = "analysis_results"
    
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    test_case_id = Column(String, ForeignKey("test_cases.id"), nullable=False)
    analyzer_name = Column(String(100), nullable=False)
    analyzer_version = Column(String(50))
    analysis_type = Column(String(100), nullable=False)  # toxicity, bias, prompt_injection, etc.
    
    # 分析结果
    score = Column(Float)  # 0.0 - 1.0
    confidence = Column(Float)  # 0.0 - 1.0
    is_vulnerable = Column(Boolean, default=False)
    risk_level = Column(String(50))  # low, medium, high, critical
    
    # 详细结果
    details = Column(JSON)  # detailed analysis results
    evidence = Column(JSON)  # evidence supporting the analysis
    false_positive_likelihood = Column(Float)  # 0.0 - 1.0
    
    # 关系
    test_case = relationship("TestCase", back_populates="analysis_results")
    
    # 索引
    __table_args__ = (
        Index("idx_analysis_results_test_analyzer", "test_case_id", "analyzer_name"),
        Index("idx_analysis_results_vulnerable", "is_vulnerable"),
    )
    
    def __repr__(self):
        return f"<AnalysisResult(id='{self.id}', analyzer='{self.analyzer_name}', score={self.score})>"


class ModelMetrics(Base, TimestampMixin):
    """模型性能指标模型"""
    __tablename__ = "model_metrics"
    
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    session_id = Column(String, ForeignKey("test_sessions.id"))
    model_name = Column(String(100), nullable=False)
    device = Column(String(50))
    
    # 性能指标
    avg_inference_time = Column(Float)  # seconds
    avg_tokens_per_second = Column(Float)
    peak_memory_usage = Column(Float)  # MB
    total_requests = Column(Integer, default=0)
    successful_requests = Column(Integer, default=0)
    failed_requests = Column(Integer, default=0)
    
    # 质量指标
    avg_response_length = Column(Float)  # tokens
    avg_response_quality = Column(Float)  # 0.0 - 1.0
    hallucination_rate = Column(Float)  # 0.0 - 1.0
    
    # 时间窗口
    measurement_start = Column(DateTime, nullable=False)
    measurement_end = Column(DateTime, nullable=False)
    
    def __repr__(self):
        return f"<ModelMetrics(model='{self.model_name}', requests={self.total_requests})>"


class KnowledgeBase(Base, TimestampMixin):
    """知识库模型 - 存储已知漏洞和攻击模式"""
    __tablename__ = "knowledge_base"
    
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=False)
    category = Column(String(100), nullable=False)
    attack_pattern = Column(Text)
    indicators = Column(JSON)  # list of indicators
    references = Column(JSON)  # list of reference URLs/papers
    severity = Column(String(50))
    
    # 版本控制
    version = Column(String(50), default="1.0")
    is_active = Column(Boolean, default=True)
    
    # 索引
    __table_args__ = (
        Index("idx_knowledge_base_category", "category"),
        Index("idx_knowledge_base_active", "is_active"),
    )
    
    def __repr__(self):
        return f"<KnowledgeBase(id='{self.id}', title='{self.title}', category='{self.category}')>"


class DatabaseManager:
    """数据库管理器"""
    
    def __init__(self):
        self.engine = None
        self.SessionLocal = None
        self._setup_database()
    
    def _setup_database(self):
        """设置数据库连接"""
        # 创建数据目录
        if settings.database_url.startswith("sqlite"):
            db_path = settings.database_url.replace("sqlite:///", "")
            Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        
        # 创建引擎
        self.engine = create_engine(
            settings.database_url,
            echo=settings.database_echo,
            pool_pre_ping=True
        )
        
        # 创建会话工厂
        self.SessionLocal = sessionmaker(
            autocommit=False,
            autoflush=False,
            bind=self.engine
        )
        
        # 创建表
        Base.metadata.create_all(bind=self.engine)
        
        logger.log_database_operation("setup", "all_tables")
    
    def initialize_database(self):
        """初始化数据库（已在_setup_database中完成）"""
        # 数据库已在构造函数中初始化
        pass
    
    def close(self):
        """关闭数据库连接"""
        if self.engine:
            self.engine.dispose()
            logger.log_database_operation("close", "connection")
    
    def get_session(self) -> Session:
        """获取数据库会话"""
        return self.SessionLocal()
    
    def create_test_session(self, name: str, description: str = None, 
                          model_name: str = None, model_config: dict = None,
                          test_config: dict = None) -> TestSession:
        """创建测试会话"""
        with self.get_session() as session:
            test_session = TestSession(
                name=name,
                description=description,
                model_name=model_name or settings.model_name,
                model_config=model_config,
                test_config=test_config
            )
            session.add(test_session)
            session.commit()
            session.refresh(test_session)
            
            logger.log_database_operation("create", "test_sessions", 1)
            return test_session
    
    def get_active_sessions(self) -> List[TestSession]:
        """获取活跃的测试会话"""
        with self.get_session() as session:
            sessions = session.query(TestSession).filter(
                TestSession.status.in_(["running", "pending"])
            ).all()
            
            logger.log_database_operation("query", "test_sessions", len(sessions))
            return sessions
    
    def save_vulnerability(self, vulnerability_data: dict, session_id: str) -> Vulnerability:
        """保存漏洞信息"""
        with self.get_session() as session:
            vulnerability = Vulnerability(
                session_id=session_id,
                **vulnerability_data
            )
            session.add(vulnerability)
            session.commit()
            session.refresh(vulnerability)
            
            logger.log_vulnerability_found(
                vulnerability.category,
                vulnerability.severity,
                vulnerability.title
            )
            return vulnerability
    
    def get_vulnerabilities_by_novelty(self, min_novelty: float = 0.8) -> List[Vulnerability]:
        """根据新颖性获取漏洞"""
        with self.get_session() as session:
            vulnerabilities = session.query(Vulnerability).filter(
                Vulnerability.novelty_score >= min_novelty,
                Vulnerability.verified == True,
                Vulnerability.false_positive == False
            ).order_by(Vulnerability.novelty_score.desc()).all()
            
            logger.log_database_operation("query", "vulnerabilities", len(vulnerabilities))
            return vulnerabilities
    
    def update_session_stats(self, session_id: str):
        """更新会话统计信息"""
        with self.get_session() as session:
            test_session = session.query(TestSession).filter(
                TestSession.id == session_id
            ).first()
            
            if test_session:
                # 统计测试用例
                total_tests = session.query(TestCase).filter(
                    TestCase.session_id == session_id
                ).count()
                
                passed_tests = session.query(TestCase).filter(
                    TestCase.session_id == session_id,
                    TestCase.status == "passed"
                ).count()
                
                failed_tests = session.query(TestCase).filter(
                    TestCase.session_id == session_id,
                    TestCase.status == "failed"
                ).count()
                
                vulnerabilities_found = session.query(Vulnerability).filter(
                    Vulnerability.session_id == session_id,
                    Vulnerability.verified == True
                ).count()
                
                # 更新统计
                test_session.total_tests = total_tests
                test_session.passed_tests = passed_tests
                test_session.failed_tests = failed_tests
                test_session.vulnerabilities_found = vulnerabilities_found
                
                session.commit()
                logger.log_database_operation("update", "test_sessions", 1)
    
    def cleanup_old_data(self, days: int = 30):
        """清理旧数据"""
        cutoff_date = datetime.utcnow() - timedelta(days=days)
        
        with self.get_session() as session:
            # 删除旧的测试会话（及其关联数据）
            old_sessions = session.query(TestSession).filter(
                TestSession.created_at < cutoff_date,
                TestSession.status.in_(["completed", "failed", "cancelled"])
            ).all()
            
            for test_session in old_sessions:
                session.delete(test_session)
            
            session.commit()
            logger.log_database_operation("cleanup", "test_sessions", len(old_sessions))


# 全局数据库管理器实例
db_manager = DatabaseManager()