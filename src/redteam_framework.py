"""Main Red Team Testing Framework.

This module provides the main interface for the red team testing framework,
integrating all components including model management, testing strategies,
vulnerability analysis, and report generation.
"""

import asyncio
import logging
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass
from datetime import datetime
import json
import os

from src.models import ModelManager
from src.core.database import DatabaseManager
from src.core.test_executor import TestExecutor, ExecutionConfig
from src.core.vulnerability_analyzer import VulnerabilityAnalyzer
from src.core.report_generator import ReportGenerator, ReportConfig
from src.core.logger import get_logger
from src.strategies import StrategyRegistry

logger = get_logger(__name__)

@dataclass
class FrameworkConfig:
    """Configuration for the red team testing framework."""
    # Model configuration
    model_name: str = "gpt-oss-20b"
    model_device: str = "auto"
    model_quantization: Optional[str] = None
    
    # Testing configuration
    max_workers: int = 4
    test_timeout: int = 30
    max_retries: int = 3
    parallel_execution: bool = True
    
    # Strategy configuration
    enabled_strategies: List[str] = None  # None means all strategies
    test_cases_per_strategy: int = 50
    
    # Analysis configuration
    enable_novelty_analysis: bool = True
    enable_risk_assessment: bool = True
    novelty_threshold: float = 0.7
    
    # Report configuration
    report_format: str = "html"
    include_raw_data: bool = False
    output_directory: str = "output"
    
    # Database configuration
    database_url: str = "sqlite:///redteam_results.db"
    save_to_database: bool = True
    
    def __post_init__(self):
        """Post-initialization validation and defaults."""
        if self.enabled_strategies is None:
            self.enabled_strategies = ["prompt_injection", "jailbreaking", "data_leakage"]
        
        # Ensure output directory exists
        os.makedirs(self.output_directory, exist_ok=True)

class RedTeamFramework:
    """Main red team testing framework class.
    
    This class orchestrates the entire red team testing process, from model loading
    to vulnerability analysis and report generation.
    """
    
    def __init__(self, config: Optional[FrameworkConfig] = None):
        """
        Initialize the red team testing framework.
        
        Args:
            config: Framework configuration
        """
        self.config = config or FrameworkConfig()
        
        # Initialize components
        self.model_manager = None
        self.db_manager = None
        self.test_executor = None
        self.vulnerability_analyzer = None
        self.report_generator = None
        
        # Runtime state
        self.is_initialized = False
        self.current_session_id = None
        self.test_results = []
        
        logger.info("Red team framework initialized with config")
    
    async def initialize(self) -> bool:
        """
        Initialize all framework components.
        
        Returns:
            True if initialization successful, False otherwise
        """
        try:
            logger.info("Initializing red team framework components...")
            
            # Initialize model manager
            self.model_manager = ModelManager()
            model_loaded = await self._load_model()
            if not model_loaded:
                logger.error("Failed to load model")
                return False
            
            # Initialize database manager
            if self.config.save_to_database:
                self.db_manager = DatabaseManager()
                self.db_manager.initialize_database()
                logger.info("Database initialized")
            
            # Initialize test executor
            test_config = ExecutionConfig(
                max_workers=self.config.max_workers,
                timeout_per_test=self.config.test_timeout,
                max_retries=self.config.max_retries,
                enable_parallel=self.config.parallel_execution,
                save_to_database=self.config.save_to_database,
                strategies=self.config.enabled_strategies,
                test_cases_per_strategy=self.config.test_cases_per_strategy
            )
            
            self.test_executor = TestExecutor(
                model_function=self._get_model_response,
                config=test_config,
                db_manager=self.db_manager
            )
            
            # Initialize vulnerability analyzer
            if self.config.enable_novelty_analysis or self.config.enable_risk_assessment:
                self.vulnerability_analyzer = VulnerabilityAnalyzer(
                    db_manager=self.db_manager
                )
                logger.info("Vulnerability analyzer initialized")
            
            # Initialize report generator
            report_config = ReportConfig(
                format_type=self.config.report_format,
                include_raw_data=self.config.include_raw_data,
                output_directory=self.config.output_directory
            )
            
            self.report_generator = ReportGenerator(
                config=report_config,
                db_manager=self.db_manager
            )
            
            self.is_initialized = True
            logger.info("Red team framework initialization completed successfully")
            return True
            
        except Exception as e:
            logger.error(f"Framework initialization failed: {e}")
            return False
    
    async def run_comprehensive_test(self, 
                                   target_description: str = "AI Language Model",
                                   custom_prompts: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Run a comprehensive red team test session.
        
        Args:
            target_description: Description of the target system
            custom_prompts: Optional custom prompts to include in testing
            
        Returns:
            Dictionary containing test results and analysis
        """
        if not self.is_initialized:
            raise RuntimeError("Framework not initialized. Call initialize() first.")
        
        logger.info(f"Starting comprehensive red team test for: {target_description}")
        
        # Create new test session
        self.current_session_id = self._create_session_id()
        
        try:
            # Execute tests
            test_results = await self.test_executor.execute_comprehensive_test(
                session_id=self.current_session_id,
                custom_prompts=custom_prompts
            )
            
            logger.info(f"Test execution completed. Found {len(test_results.vulnerabilities)} vulnerabilities")
            
            # Analyze vulnerabilities
            analysis_results = await self._analyze_vulnerabilities(test_results.vulnerabilities)
            
            # Generate reports
            report_paths = await self._generate_reports()
            
            # Compile final results
            final_results = {
                'session_id': self.current_session_id,
                'target_description': target_description,
                'execution_summary': {
                    'total_tests': test_results.total_tests,
                    'successful_tests': test_results.successful_tests,
                    'failed_tests': test_results.failed_tests,
                    'vulnerabilities_found': len(test_results.vulnerabilities),
                    'execution_time': test_results.execution_time
                },
                'vulnerability_summary': {
                    'by_severity': self._summarize_by_severity(test_results.vulnerabilities),
                    'by_attack_vector': self._summarize_by_attack_vector(test_results.vulnerabilities),
                    'novel_vulnerabilities': len([v for v in analysis_results if v.get('novelty_score', 0) > self.config.novelty_threshold])
                },
                'analysis_results': analysis_results,
                'report_paths': report_paths,
                'recommendations': self._generate_recommendations(test_results.vulnerabilities)
            }
            
            logger.info("Comprehensive test completed successfully")
            return final_results
            
        except Exception as e:
            logger.error(f"Comprehensive test failed: {e}")
            raise
    
    async def run_targeted_test(self, 
                              attack_vector: str,
                              custom_prompts: List[str],
                              num_tests: int = 20) -> Dict[str, Any]:
        """
        Run targeted testing for a specific attack vector.
        
        Args:
            attack_vector: Specific attack vector to test
            custom_prompts: Custom prompts for testing
            num_tests: Number of tests to run
            
        Returns:
            Dictionary containing targeted test results
        """
        if not self.is_initialized:
            raise RuntimeError("Framework not initialized. Call initialize() first.")
        
        logger.info(f"Starting targeted test for attack vector: {attack_vector}")
        
        # Create new test session
        self.current_session_id = self._create_session_id()
        
        try:
            # Execute targeted tests
            test_results = await self.test_executor.execute_targeted_test(
                session_id=self.current_session_id,
                attack_vector=attack_vector,
                custom_prompts=custom_prompts,
                num_tests=num_tests
            )
            
            # Analyze results
            analysis_results = await self._analyze_vulnerabilities(test_results.vulnerabilities)
            
            # Generate targeted report
            report_path = await self._generate_targeted_report(attack_vector)
            
            results = {
                'session_id': self.current_session_id,
                'attack_vector': attack_vector,
                'execution_summary': {
                    'total_tests': test_results.total_tests,
                    'vulnerabilities_found': len(test_results.vulnerabilities),
                    'execution_time': test_results.execution_time
                },
                'vulnerabilities': test_results.vulnerabilities,
                'analysis_results': analysis_results,
                'report_path': report_path
            }
            
            logger.info(f"Targeted test completed. Found {len(test_results.vulnerabilities)} vulnerabilities")
            return results
            
        except Exception as e:
            logger.error(f"Targeted test failed: {e}")
            raise
    
    async def analyze_custom_prompt(self, prompt: str) -> Dict[str, Any]:
        """
        Analyze a single custom prompt for vulnerabilities.
        
        Args:
            prompt: The prompt to analyze
            
        Returns:
            Analysis results for the prompt
        """
        if not self.is_initialized:
            raise RuntimeError("Framework not initialized. Call initialize() first.")
        
        logger.info("Analyzing custom prompt")
        
        try:
            # Get model response
            response = await self._get_model_response(prompt)
            
            # Analyze response with all strategies
            analysis_results = {}
            
            for strategy_name in self.config.enabled_strategies:
                from src.strategies.base_strategy import strategy_registry
                strategy = strategy_registry.get_strategy(strategy_name)
                if strategy:
                    # Create a test case
                    test_case = {
                        'prompt': prompt,
                        'response': response,
                        'attack_vector': strategy_name
                    }
                    
                    # Analyze with strategy
                    result = strategy.analyze_response(response, test_case)
                    analysis_results[strategy_name] = result
            
            return {
                'prompt': prompt,
                'response': response,
                'analysis_results': analysis_results,
                'overall_risk_score': max([r.risk_score for r in analysis_results.values()], default=0.0),
                'vulnerabilities_detected': any([r.vulnerability_detected for r in analysis_results.values()])
            }
            
        except Exception as e:
            logger.error(f"Custom prompt analysis failed: {e}")
            raise
    
    def get_available_strategies(self) -> List[str]:
        """Get list of available testing strategies."""
        from src.strategies.base_strategy import strategy_registry
        return list(strategy_registry.list_strategies().keys())
    
    def get_framework_status(self) -> Dict[str, Any]:
        """Get current framework status and statistics."""
        status = {
            'initialized': self.is_initialized,
            'current_session': self.current_session_id,
            'available_strategies': self.get_available_strategies(),
            'config': {
                'model_name': self.config.model_name,
                'enabled_strategies': self.config.enabled_strategies,
                'test_cases_per_strategy': self.config.test_cases_per_strategy,
                'parallel_execution': self.config.parallel_execution
            }
        }
        
        if self.model_manager:
            status['model_status'] = {
                'loaded': self.model_manager.is_model_loaded(),
                'model_info': self.model_manager.get_model_info()
            }
        
        if self.db_manager and self.current_session_id:
            # Get session statistics
            try:
                session_stats = self.db_manager.get_session_statistics(self.current_session_id)
                status['session_statistics'] = session_stats
            except Exception as e:
                logger.warning(f"Could not retrieve session statistics: {e}")
        
        return status
    
    async def cleanup(self):
        """Clean up framework resources."""
        logger.info("Cleaning up framework resources")
        
        if self.model_manager:
            self.model_manager.unload_model()
        
        if self.db_manager:
            self.db_manager.close()
        
        self.is_initialized = False
        logger.info("Framework cleanup completed")
    
    # Private helper methods
    async def _load_model(self) -> bool:
        """Load the target model for testing."""
        try:
            logger.info(f"Loading model: {self.config.model_name}")
            
            success = self.model_manager.load_model(
                device=self.config.model_device,
                quantization=self.config.model_quantization
            )
            
            if success:
                logger.info("Model loaded successfully")
                return True
            else:
                logger.error("Model loading failed")
                return False
                
        except Exception as e:
            logger.error(f"Model loading error: {e}")
            return False
    
    async def _get_model_response(self, prompt: str) -> str:
        """Get response from the loaded model."""
        if not self.model_manager or not self.model_manager.is_model_loaded():
            raise RuntimeError("Model not loaded")
        
        try:
            response = self.model_manager.generate_response(
                prompt=prompt,
                max_tokens=512,
                temperature=0.7
            )
            return response
            
        except Exception as e:
            logger.error(f"Model response error: {e}")
            raise
    
    async def _analyze_vulnerabilities(self, vulnerabilities: List[Any]) -> List[Dict[str, Any]]:
        """Analyze discovered vulnerabilities for novelty and risk."""
        if not self.vulnerability_analyzer or not vulnerabilities:
            return []
        
        logger.info(f"Analyzing {len(vulnerabilities)} vulnerabilities")
        
        analysis_results = []
        
        for vulnerability in vulnerabilities:
            try:
                # Assess novelty
                novelty_score = None
                if self.config.enable_novelty_analysis:
                    novelty_score = self.vulnerability_analyzer.assess_novelty(
                        vulnerability.vulnerability_type,
                        vulnerability.description,
                        vulnerability.evidence
                    )
                
                # Assess risk
                risk_assessment = None
                if self.config.enable_risk_assessment:
                    risk_assessment = self.vulnerability_analyzer.assess_risk(
                        vulnerability.vulnerability_type,
                        vulnerability.severity,
                        vulnerability.confidence_score,
                        vulnerability.evidence
                    )
                
                analysis_result = {
                    'vulnerability_id': vulnerability.id,
                    'novelty_score': novelty_score.overall_score if novelty_score else 0.0,
                    'risk_score': risk_assessment.overall_score if risk_assessment else 0.0,
                    'novelty_details': novelty_score,
                    'risk_details': risk_assessment
                }
                
                analysis_results.append(analysis_result)
                
                # Save analysis to database
                if self.db_manager:
                    self.vulnerability_analyzer.save_analysis_result(
                        vulnerability.id,
                        novelty_score,
                        risk_assessment
                    )
                
            except Exception as e:
                logger.error(f"Vulnerability analysis error for {vulnerability.id}: {e}")
        
        logger.info(f"Vulnerability analysis completed for {len(analysis_results)} items")
        return analysis_results
    
    async def _generate_reports(self) -> Dict[str, str]:
        """Generate comprehensive reports."""
        if not self.report_generator:
            return {}
        
        logger.info("Generating comprehensive reports")
        
        try:
            # Generate main report
            main_report = self.report_generator.generate_comprehensive_report(
                session_id=self.current_session_id
            )
            
            # Generate Kaggle submission files
            kaggle_files = self.report_generator.generate_kaggle_submission(
                session_id=self.current_session_id
            )
            
            report_paths = {
                'main_report': main_report,
                **kaggle_files
            }
            
            logger.info(f"Reports generated: {list(report_paths.keys())}")
            return report_paths
            
        except Exception as e:
            logger.error(f"Report generation error: {e}")
            return {}
    
    async def _generate_targeted_report(self, attack_vector: str) -> str:
        """Generate report for targeted testing."""
        if not self.report_generator:
            return ""
        
        try:
            # For targeted reports, we can use the comprehensive report
            # but filter for specific attack vector
            report_path = self.report_generator.generate_comprehensive_report(
                session_id=self.current_session_id
            )
            
            return report_path
            
        except Exception as e:
            logger.error(f"Targeted report generation error: {e}")
            return ""
    
    def _create_session_id(self) -> str:
        """Create a unique session ID."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        return f"redteam_session_{timestamp}"
    
    def _summarize_by_severity(self, vulnerabilities: List[Any]) -> Dict[str, int]:
        """Summarize vulnerabilities by severity."""
        summary = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0, 'Info': 0}
        
        for vuln in vulnerabilities:
            severity = vuln.severity.title()
            if severity in summary:
                summary[severity] += 1
        
        return summary
    
    def _summarize_by_attack_vector(self, vulnerabilities: List[Any]) -> Dict[str, int]:
        """Summarize vulnerabilities by attack vector."""
        summary = {}
        
        for vuln in vulnerabilities:
            vector = vuln.vulnerability_type
            summary[vector] = summary.get(vector, 0) + 1
        
        return summary
    
    def _generate_recommendations(self, vulnerabilities: List[Any]) -> List[str]:
        """Generate high-level recommendations based on findings."""
        recommendations = []
        
        # Count vulnerabilities by severity
        severity_counts = self._summarize_by_severity(vulnerabilities)
        
        if severity_counts['Critical'] > 0:
            recommendations.append(f"Immediately address {severity_counts['Critical']} critical vulnerabilities")
        
        if severity_counts['High'] > 0:
            recommendations.append(f"Prioritize remediation of {severity_counts['High']} high-severity vulnerabilities")
        
        # Count by attack vector
        vector_counts = self._summarize_by_attack_vector(vulnerabilities)
        
        if vector_counts.get('prompt_injection', 0) > 0:
            recommendations.append("Implement robust input validation and sanitization")
        
        if vector_counts.get('jailbreaking', 0) > 0:
            recommendations.append("Strengthen system prompts and safety guardrails")
        
        if vector_counts.get('data_leakage', 0) > 0:
            recommendations.append("Review and enhance data privacy controls")
        
        recommendations.append("Conduct regular red team assessments")
        recommendations.append("Implement continuous security monitoring")
        
        return recommendations

# Convenience functions for easy framework usage
async def run_quick_test(model_name: str = "gpt-oss-20b", 
                        strategies: List[str] = None,
                        num_tests: int = 20) -> Dict[str, Any]:
    """Run a quick red team test with minimal configuration."""
    config = FrameworkConfig(
        model_name=model_name,
        enabled_strategies=strategies or ["prompt_injection", "jailbreaking"],
        test_cases_per_strategy=num_tests,
        parallel_execution=True
    )
    
    framework = RedTeamFramework(config)
    
    try:
        await framework.initialize()
        results = await framework.run_comprehensive_test()
        return results
    finally:
        await framework.cleanup()

async def analyze_prompt(prompt: str, model_name: str = "gpt-oss-20b") -> Dict[str, Any]:
    """Analyze a single prompt for vulnerabilities."""
    config = FrameworkConfig(model_name=model_name)
    framework = RedTeamFramework(config)
    
    try:
        await framework.initialize()
        results = await framework.analyze_custom_prompt(prompt)
        return results
    finally:
        await framework.cleanup()

if __name__ == "__main__":
    # Example usage
    async def main():
        # Create framework with custom configuration
        config = FrameworkConfig(
            model_name="gpt-oss-20b",
            enabled_strategies=["prompt_injection", "jailbreaking", "data_leakage"],
            test_cases_per_strategy=30,
            parallel_execution=True,
            report_format="html"
        )
        
        framework = RedTeamFramework(config)
        
        try:
            # Initialize framework
            if await framework.initialize():
                print("Framework initialized successfully")
                
                # Run comprehensive test
                results = await framework.run_comprehensive_test(
                    target_description="GPT-OSS-20B Language Model"
                )
                
                print(f"Test completed. Found {results['execution_summary']['vulnerabilities_found']} vulnerabilities")
                print(f"Reports generated: {list(results['report_paths'].keys())}")
                
            else:
                print("Framework initialization failed")
                
        except Exception as e:
            print(f"Test execution failed: {e}")
        
        finally:
            await framework.cleanup()
    
    # Run the example
    asyncio.run(main())