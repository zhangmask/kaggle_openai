"""Automated test executor for red team testing.

This module provides the TestExecutor class that orchestrates the execution
of various red team testing strategies against target models.
"""

import asyncio
import time
import json
from typing import Dict, List, Any, Optional, Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict

from .logger import get_logger
from .database import DatabaseManager, TestSession, TestCase as DBTestCase, Vulnerability
from ..strategies import (
    BaseStrategy, 
    AttackVector, 
    TestResult, 
    TestCase,
    AttackResult,
    strategy_registry
)

logger = get_logger(__name__)

@dataclass
class ExecutionConfig:
    """Configuration for test execution."""
    max_workers: int = 4
    timeout_per_test: int = 30
    max_retries: int = 3
    delay_between_tests: float = 0.5
    enable_parallel: bool = True
    save_to_database: bool = True
    strategies: List[str] = None  # None means all strategies
    test_cases_per_strategy: int = 50
    
    def __post_init__(self):
        if self.strategies is None:
            self.strategies = list(strategy_registry.get_all_strategies().keys())

@dataclass
class ExecutionStats:
    """Statistics for test execution."""
    total_tests: int = 0
    successful_tests: int = 0
    failed_tests: int = 0
    vulnerabilities_found: int = 0
    critical_vulnerabilities: int = 0
    high_vulnerabilities: int = 0
    medium_vulnerabilities: int = 0
    low_vulnerabilities: int = 0
    execution_time: float = 0.0
    strategies_executed: List[str] = None
    
    def __post_init__(self):
        if self.strategies_executed is None:
            self.strategies_executed = []
    
    def add_vulnerability(self, severity: str):
        """Add a vulnerability to the statistics."""
        self.vulnerabilities_found += 1
        severity_lower = severity.lower()
        if severity_lower == 'critical':
            self.critical_vulnerabilities += 1
        elif severity_lower == 'high':
            self.high_vulnerabilities += 1
        elif severity_lower == 'medium':
            self.medium_vulnerabilities += 1
        elif severity_lower == 'low':
            self.low_vulnerabilities += 1
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert stats to dictionary."""
        return asdict(self)

class TestExecutor:
    """Automated test executor for red team testing."""
    
    def __init__(self, 
                 model_function: Callable[[str], str],
                 config: Optional[ExecutionConfig] = None,
                 db_manager: Optional[DatabaseManager] = None):
        """
        Initialize the test executor.
        
        Args:
            model_function: Function that takes a prompt and returns model response
            config: Execution configuration
            db_manager: Database manager for storing results
        """
        self.model_function = model_function
        self.config = config or ExecutionConfig()
        self.db_manager = db_manager
        self.stats = ExecutionStats()
        self.session_id: Optional[str] = None
        
        # Initialize strategies
        self.strategies: Dict[str, BaseStrategy] = {}
        for strategy_name in self.config.strategies:
            if strategy_name in strategy_registry.get_all_strategies():
                strategy_class = strategy_registry.get_strategy(strategy_name)
                self.strategies[strategy_name] = strategy_class()
                logger.info(f"Initialized strategy: {strategy_name}")
            else:
                logger.warning(f"Unknown strategy: {strategy_name}")
    
    def execute_all_tests(self) -> ExecutionStats:
        """Execute all configured red team tests."""
        logger.info("Starting red team test execution")
        start_time = time.time()
        
        # Create test session in database
        if self.config.save_to_database and self.db_manager:
            self.session_id = self._create_test_session()
        
        try:
            if self.config.enable_parallel:
                self._execute_parallel()
            else:
                self._execute_sequential()
        except Exception as e:
            logger.error(f"Error during test execution: {e}")
            raise
        finally:
            self.stats.execution_time = time.time() - start_time
            
            # Update test session in database
            if self.session_id and self.db_manager:
                self._update_test_session()
            
            logger.info(f"Test execution completed in {self.stats.execution_time:.2f}s")
            self._log_execution_summary()
        
        return self.stats
    
    def _execute_parallel(self):
        """Execute tests in parallel using ThreadPoolExecutor."""
        with ThreadPoolExecutor(max_workers=self.config.max_workers) as executor:
            # Submit all test tasks
            future_to_test = {}
            
            for strategy_name, strategy in self.strategies.items():
                logger.info(f"Generating test cases for {strategy_name}")
                test_cases = strategy.generate_test_cases(self.config.test_cases_per_strategy)
                
                for test_case in test_cases:
                    future = executor.submit(self._execute_single_test, strategy, test_case)
                    future_to_test[future] = (strategy_name, test_case)
            
            # Process completed tests
            for future in as_completed(future_to_test):
                strategy_name, test_case = future_to_test[future]
                try:
                    result = future.result(timeout=self.config.timeout_per_test)
                    self._process_test_result(strategy_name, test_case, result)
                except Exception as e:
                    logger.error(f"Test failed for {strategy_name}: {e}")
                    self.stats.failed_tests += 1
                
                # Add delay between tests if configured
                if self.config.delay_between_tests > 0:
                    time.sleep(self.config.delay_between_tests)
    
    def _execute_sequential(self):
        """Execute tests sequentially."""
        for strategy_name, strategy in self.strategies.items():
            logger.info(f"Executing {strategy_name} strategy")
            test_cases = strategy.generate_test_cases(self.config.test_cases_per_strategy)
            
            for test_case in test_cases:
                try:
                    result = self._execute_single_test(strategy, test_case)
                    self._process_test_result(strategy_name, test_case, result)
                except Exception as e:
                    logger.error(f"Test failed for {strategy_name}: {e}")
                    self.stats.failed_tests += 1
                
                # Add delay between tests if configured
                if self.config.delay_between_tests > 0:
                    time.sleep(self.config.delay_between_tests)
    
    def _execute_single_test(self, strategy: BaseStrategy, test_case: TestCase) -> AttackResult:
        """Execute a single test case with retries."""
        last_exception = None
        
        for attempt in range(self.config.max_retries):
            try:
                # Execute the attack
                result = strategy.execute_attack(test_case, self.model_function)
                self.stats.total_tests += 1
                
                if result.test_result != TestResult.ERROR:
                    self.stats.successful_tests += 1
                    return result
                else:
                    self.stats.failed_tests += 1
                    logger.warning(f"Test attempt {attempt + 1} failed: {result.error_message}")
                    
            except Exception as e:
                last_exception = e
                logger.warning(f"Test attempt {attempt + 1} failed with exception: {e}")
                
                if attempt < self.config.max_retries - 1:
                    time.sleep(0.5 * (attempt + 1))  # Exponential backoff
        
        # All retries failed
        self.stats.failed_tests += 1
        error_msg = f"All {self.config.max_retries} attempts failed"
        if last_exception:
            error_msg += f": {last_exception}"
        
        return AttackResult(
            test_result=TestResult.ERROR,
            vulnerability_detected=False,
            confidence_score=0.0,
            severity="info",
            evidence=[],
            response_text="",
            error_message=error_msg
        )
    
    def _process_test_result(self, strategy_name: str, test_case: TestCase, result: AttackResult):
        """Process and store a test result."""
        # Update statistics
        if strategy_name not in self.stats.strategies_executed:
            self.stats.strategies_executed.append(strategy_name)
        
        if result.vulnerability_detected:
            self.stats.add_vulnerability(result.severity)
        
        # Save to database if configured
        if self.config.save_to_database and self.db_manager and self.session_id:
            self._save_test_result_to_db(strategy_name, test_case, result)
        
        # Log significant findings
        if result.vulnerability_detected and result.confidence_score > 0.7:
            logger.warning(
                f"High-confidence vulnerability found in {strategy_name}: "
                f"{result.severity} (confidence: {result.confidence_score:.2f})"
            )
    
    def _create_test_session(self) -> str:
        """Create a new test session in the database."""
        try:
            session = TestSession(
                strategies=json.dumps(self.config.strategies),
                config=json.dumps(asdict(self.config)),
                status="running"
            )
            session_id = self.db_manager.save_test_session(session)
            logger.info(f"Created test session: {session_id}")
            return session_id
        except Exception as e:
            logger.error(f"Failed to create test session: {e}")
            return None
    
    def _update_test_session(self):
        """Update the test session with final results."""
        try:
            if self.session_id:
                self.db_manager.update_test_session(
                    self.session_id,
                    status="completed",
                    results=json.dumps(self.stats.to_dict())
                )
                logger.info(f"Updated test session: {self.session_id}")
        except Exception as e:
            logger.error(f"Failed to update test session: {e}")
    
    def _save_test_result_to_db(self, strategy_name: str, test_case: TestCase, result: AttackResult):
        """Save a test result to the database."""
        try:
            # Save test case
            db_test_case = DBTestCase(
                session_id=self.session_id,
                strategy=strategy_name,
                attack_vector=test_case.attack_vector.value,
                prompt=test_case.prompt,
                expected_behavior=test_case.expected_behavior,
                test_result=result.test_result.value,
                response=result.response_text,
                confidence_score=result.confidence_score,
                execution_time=0.0  # Could be measured if needed
            )
            test_case_id = self.db_manager.save_test_case(db_test_case)
            
            # Save vulnerability if detected
            if result.vulnerability_detected:
                vulnerability = Vulnerability(
                    test_case_id=test_case_id,
                    vulnerability_type=test_case.attack_vector.value,
                    severity=result.severity,
                    confidence_score=result.confidence_score,
                    description=f"Vulnerability detected in {strategy_name} strategy",
                    evidence=json.dumps(result.evidence),
                    mitigation_suggestions=json.dumps([])
                )
                self.db_manager.save_vulnerability(vulnerability)
                
        except Exception as e:
            logger.error(f"Failed to save test result to database: {e}")
    
    def _log_execution_summary(self):
        """Log a summary of the test execution."""
        logger.info("=== Test Execution Summary ===")
        logger.info(f"Total tests: {self.stats.total_tests}")
        logger.info(f"Successful tests: {self.stats.successful_tests}")
        logger.info(f"Failed tests: {self.stats.failed_tests}")
        logger.info(f"Vulnerabilities found: {self.stats.vulnerabilities_found}")
        logger.info(f"  - Critical: {self.stats.critical_vulnerabilities}")
        logger.info(f"  - High: {self.stats.high_vulnerabilities}")
        logger.info(f"  - Medium: {self.stats.medium_vulnerabilities}")
        logger.info(f"  - Low: {self.stats.low_vulnerabilities}")
        logger.info(f"Execution time: {self.stats.execution_time:.2f}s")
        logger.info(f"Strategies executed: {', '.join(self.stats.strategies_executed)}")
    
    def get_vulnerability_summary(self) -> Dict[str, Any]:
        """Get a summary of vulnerabilities found."""
        return {
            'total_vulnerabilities': self.stats.vulnerabilities_found,
            'by_severity': {
                'critical': self.stats.critical_vulnerabilities,
                'high': self.stats.high_vulnerabilities,
                'medium': self.stats.medium_vulnerabilities,
                'low': self.stats.low_vulnerabilities
            },
            'by_strategy': {name: strategy.get_vulnerability_summary() 
                          for name, strategy in self.strategies.items()}
        }
    
    def export_results(self, format_type: str = 'json') -> str:
        """Export test results in specified format."""
        results = {
            'execution_stats': self.stats.to_dict(),
            'vulnerability_summary': self.get_vulnerability_summary(),
            'strategy_results': {name: strategy.export_results(format_type) 
                               for name, strategy in self.strategies.items()}
        }
        
        if format_type.lower() == 'json':
            return json.dumps(results, indent=2)
        else:
            raise ValueError(f"Unsupported format: {format_type}")