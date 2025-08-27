"""Report generator for Kaggle red team competition.

This module generates comprehensive reports that meet Kaggle competition requirements,
including vulnerability summaries, novelty assessments, and detailed findings.
"""

import json
import os
from datetime import datetime
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict
import pandas as pd
from jinja2 import Template

from .logger import get_logger
from .database import DatabaseManager
from .vulnerability_analyzer import NoveltyScore, RiskAssessment
from ..strategies import AttackVector

logger = get_logger(__name__)

@dataclass
class ReportConfig:
    """Configuration for report generation."""
    include_executive_summary: bool = True
    include_technical_details: bool = True
    include_novelty_analysis: bool = True
    include_risk_assessment: bool = True
    include_recommendations: bool = True
    include_raw_data: bool = False
    format_type: str = 'html'  # html, pdf, json, csv
    output_directory: str = 'reports'
    template_directory: str = 'templates'
    
@dataclass
class VulnerabilityFinding:
    """Individual vulnerability finding for the report."""
    id: str
    title: str
    severity: str
    confidence_score: float
    attack_vector: str
    description: str
    evidence: List[str]
    novelty_score: float
    risk_score: float
    impact: str
    recommendations: List[str]
    prompt: str
    response: str
    timestamp: datetime
    
@dataclass
class ExecutiveSummary:
    """Executive summary for the report."""
    total_tests: int
    vulnerabilities_found: int
    critical_vulnerabilities: int
    high_vulnerabilities: int
    novel_vulnerabilities: int
    average_novelty_score: float
    average_risk_score: float
    key_findings: List[str]
    recommendations: List[str]
    
class ReportGenerator:
    """Comprehensive report generator for red team testing results."""
    
    def __init__(self, 
                 config: Optional[ReportConfig] = None,
                 db_manager: Optional[DatabaseManager] = None):
        """
        Initialize the report generator.
        
        Args:
            config: Report generation configuration
            db_manager: Database manager for accessing results
        """
        self.config = config or ReportConfig()
        self.db_manager = db_manager
        
        # Ensure output directory exists
        os.makedirs(self.config.output_directory, exist_ok=True)
        
        # Load report templates
        self.templates = self._load_templates()
        
        logger.info(f"Report generator initialized with format: {self.config.format_type}")
    
    def generate_comprehensive_report(self, 
                                    session_id: Optional[str] = None,
                                    findings: Optional[List[VulnerabilityFinding]] = None) -> str:
        """
        Generate a comprehensive report for Kaggle competition submission.
        
        Args:
            session_id: Test session ID to generate report for
            findings: Pre-processed vulnerability findings
            
        Returns:
            Path to the generated report file
        """
        logger.info(f"Generating comprehensive report for session: {session_id}")
        
        # Collect data
        if findings is None:
            findings = self._collect_findings(session_id)
        
        # Generate report sections
        executive_summary = self._generate_executive_summary(findings)
        technical_analysis = self._generate_technical_analysis(findings)
        novelty_analysis = self._generate_novelty_analysis(findings)
        risk_assessment = self._generate_risk_assessment(findings)
        recommendations = self._generate_recommendations(findings)
        
        # Compile report data
        report_data = {
            'metadata': self._generate_metadata(session_id),
            'executive_summary': executive_summary,
            'technical_analysis': technical_analysis,
            'novelty_analysis': novelty_analysis,
            'risk_assessment': risk_assessment,
            'recommendations': recommendations,
            'findings': findings,
            'appendices': self._generate_appendices(findings)
        }
        
        # Generate report in specified format
        if self.config.format_type.lower() == 'html':
            report_path = self._generate_html_report(report_data)
        elif self.config.format_type.lower() == 'json':
            report_path = self._generate_json_report(report_data)
        elif self.config.format_type.lower() == 'csv':
            report_path = self._generate_csv_report(findings)
        else:
            raise ValueError(f"Unsupported report format: {self.config.format_type}")
        
        logger.info(f"Report generated successfully: {report_path}")
        return report_path
    
    def generate_kaggle_submission(self, 
                                  session_id: Optional[str] = None,
                                  findings: Optional[List[VulnerabilityFinding]] = None) -> Dict[str, str]:
        """
        Generate files specifically for Kaggle competition submission.
        
        Returns:
            Dictionary mapping file types to file paths
        """
        logger.info("Generating Kaggle competition submission files")
        
        if findings is None:
            findings = self._collect_findings(session_id)
        
        submission_files = {}
        
        # Main submission report (JSON format for programmatic evaluation)
        submission_data = self._prepare_kaggle_submission_data(findings)
        submission_path = os.path.join(self.config.output_directory, 'kaggle_submission.json')
        with open(submission_path, 'w', encoding='utf-8') as f:
            json.dump(submission_data, f, indent=2, default=str)
        submission_files['submission'] = submission_path
        
        # Detailed findings CSV
        csv_path = self._generate_csv_report(findings)
        submission_files['detailed_findings'] = csv_path
        
        # Executive summary
        summary_path = self._generate_executive_summary_report(findings)
        submission_files['executive_summary'] = summary_path
        
        # Novel vulnerabilities report
        novel_path = self._generate_novel_vulnerabilities_report(findings)
        submission_files['novel_vulnerabilities'] = novel_path
        
        logger.info(f"Kaggle submission files generated: {list(submission_files.keys())}")
        return submission_files
    
    def _collect_findings(self, session_id: Optional[str] = None) -> List[VulnerabilityFinding]:
        """Collect vulnerability findings from database or other sources."""
        findings = []
        
        if not self.db_manager:
            logger.warning("No database manager available, returning empty findings")
            return findings
        
        try:
            # Get vulnerabilities from database
            vulnerabilities = self.db_manager.get_vulnerabilities_by_session(session_id)
            
            for vuln in vulnerabilities:
                # Get associated test case
                test_case = self.db_manager.get_test_case(vuln.test_case_id)
                
                # Get analysis results
                analysis = self.db_manager.get_analysis_result(vuln.id)
                
                finding = VulnerabilityFinding(
                    id=str(vuln.id),
                    title=f"{vuln.vulnerability_type.title()} Vulnerability",
                    severity=vuln.severity,
                    confidence_score=vuln.confidence_score,
                    attack_vector=vuln.vulnerability_type,
                    description=vuln.description,
                    evidence=json.loads(vuln.evidence) if vuln.evidence else [],
                    novelty_score=analysis.novelty_score if analysis else 0.0,
                    risk_score=analysis.risk_score if analysis else 0.0,
                    impact=self._determine_impact_description(vuln),
                    recommendations=json.loads(vuln.mitigation_suggestions) if vuln.mitigation_suggestions else [],
                    prompt=test_case.prompt if test_case else "",
                    response=test_case.response if test_case else "",
                    timestamp=vuln.created_at
                )
                findings.append(finding)
                
        except Exception as e:
            logger.error(f"Error collecting findings: {e}")
        
        return findings
    
    def _generate_executive_summary(self, findings: List[VulnerabilityFinding]) -> ExecutiveSummary:
        """Generate executive summary from findings."""
        total_vulns = len(findings)
        critical_vulns = len([f for f in findings if f.severity.lower() == 'critical'])
        high_vulns = len([f for f in findings if f.severity.lower() == 'high'])
        novel_vulns = len([f for f in findings if f.novelty_score > 0.7])
        
        avg_novelty = sum(f.novelty_score for f in findings) / max(1, len(findings))
        avg_risk = sum(f.risk_score for f in findings) / max(1, len(findings))
        
        # Generate key findings
        key_findings = self._extract_key_findings(findings)
        
        # Generate high-level recommendations
        recommendations = self._extract_executive_recommendations(findings)
        
        return ExecutiveSummary(
            total_tests=total_vulns,  # This should be total tests, not just vulnerabilities
            vulnerabilities_found=total_vulns,
            critical_vulnerabilities=critical_vulns,
            high_vulnerabilities=high_vulns,
            novel_vulnerabilities=novel_vulns,
            average_novelty_score=avg_novelty,
            average_risk_score=avg_risk,
            key_findings=key_findings,
            recommendations=recommendations
        )
    
    def _generate_technical_analysis(self, findings: List[VulnerabilityFinding]) -> Dict[str, Any]:
        """Generate technical analysis section."""
        analysis = {
            'attack_vector_distribution': self._analyze_attack_vectors(findings),
            'severity_distribution': self._analyze_severity_distribution(findings),
            'confidence_analysis': self._analyze_confidence_scores(findings),
            'temporal_analysis': self._analyze_temporal_patterns(findings),
            'technique_analysis': self._analyze_techniques(findings)
        }
        
        return analysis
    
    def _generate_novelty_analysis(self, findings: List[VulnerabilityFinding]) -> Dict[str, Any]:
        """Generate novelty analysis section."""
        novel_findings = [f for f in findings if f.novelty_score > 0.5]
        
        analysis = {
            'novelty_distribution': self._analyze_novelty_distribution(findings),
            'novel_techniques': self._identify_novel_techniques(novel_findings),
            'innovation_metrics': self._calculate_innovation_metrics(findings),
            'comparison_analysis': self._compare_with_known_attacks(findings)
        }
        
        return analysis
    
    def _generate_risk_assessment(self, findings: List[VulnerabilityFinding]) -> Dict[str, Any]:
        """Generate risk assessment section."""
        assessment = {
            'overall_risk_score': sum(f.risk_score for f in findings) / max(1, len(findings)),
            'risk_distribution': self._analyze_risk_distribution(findings),
            'high_risk_vulnerabilities': [f for f in findings if f.risk_score > 7.0],
            'business_impact_analysis': self._analyze_business_impact(findings),
            'mitigation_priority': self._prioritize_mitigations(findings)
        }
        
        return assessment
    
    def _generate_recommendations(self, findings: List[VulnerabilityFinding]) -> Dict[str, Any]:
        """Generate recommendations section."""
        recommendations = {
            'immediate_actions': self._generate_immediate_actions(findings),
            'short_term_improvements': self._generate_short_term_improvements(findings),
            'long_term_strategy': self._generate_long_term_strategy(findings),
            'detection_rules': self._generate_detection_rules(findings),
            'training_recommendations': self._generate_training_recommendations(findings)
        }
        
        return recommendations
    
    def _generate_metadata(self, session_id: Optional[str] = None) -> Dict[str, Any]:
        """Generate report metadata."""
        return {
            'report_id': f"redteam_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            'session_id': session_id,
            'generated_at': datetime.now().isoformat(),
            'generator_version': '1.0.0',
            'format': self.config.format_type,
            'competition': 'Kaggle Red Team Challenge'
        }
    
    def _generate_appendices(self, findings: List[VulnerabilityFinding]) -> Dict[str, Any]:
        """Generate appendices with additional data."""
        appendices = {}
        
        if self.config.include_raw_data:
            appendices['raw_findings'] = [asdict(f) for f in findings]
        
        appendices['attack_patterns'] = self._extract_attack_patterns(findings)
        appendices['statistical_summary'] = self._generate_statistical_summary(findings)
        
        return appendices
    
    def _prepare_kaggle_submission_data(self, findings: List[VulnerabilityFinding]) -> Dict[str, Any]:
        """Prepare data specifically for Kaggle submission format."""
        submission_data = {
            'submission_info': {
                'team_name': 'Red Team AI',
                'submission_time': datetime.now().isoformat(),
                'total_vulnerabilities': len(findings),
                'novel_vulnerabilities': len([f for f in findings if f.novelty_score > 0.7])
            },
            'vulnerabilities': [],
            'summary_statistics': {
                'attack_vectors': self._analyze_attack_vectors(findings),
                'severity_breakdown': self._analyze_severity_distribution(findings),
                'novelty_metrics': self._calculate_innovation_metrics(findings)
            },
            'novel_findings': [
                {
                    'id': f.id,
                    'attack_vector': f.attack_vector,
                    'novelty_score': f.novelty_score,
                    'description': f.description,
                    'technique_summary': self._summarize_technique(f)
                }
                for f in findings if f.novelty_score > 0.7
            ]
        }
        
        # Add detailed vulnerability data
        for finding in findings:
            vuln_data = {
                'id': finding.id,
                'attack_vector': finding.attack_vector,
                'severity': finding.severity,
                'confidence_score': finding.confidence_score,
                'novelty_score': finding.novelty_score,
                'risk_score': finding.risk_score,
                'description': finding.description,
                'evidence_count': len(finding.evidence),
                'has_mitigation': len(finding.recommendations) > 0
            }
            submission_data['vulnerabilities'].append(vuln_data)
        
        return submission_data
    
    def _generate_html_report(self, report_data: Dict[str, Any]) -> str:
        """Generate HTML format report."""
        template = self.templates.get('html', self._get_default_html_template())
        
        html_content = template.render(**report_data)
        
        report_path = os.path.join(
            self.config.output_directory, 
            f"redteam_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        )
        
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        return report_path
    
    def _generate_json_report(self, report_data: Dict[str, Any]) -> str:
        """Generate JSON format report."""
        report_path = os.path.join(
            self.config.output_directory,
            f"redteam_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        )
        
        with open(report_path, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=2, default=str)
        
        return report_path
    
    def _generate_csv_report(self, findings: List[VulnerabilityFinding]) -> str:
        """Generate CSV format report."""
        # Convert findings to DataFrame
        data = []
        for finding in findings:
            data.append({
                'ID': finding.id,
                'Title': finding.title,
                'Attack Vector': finding.attack_vector,
                'Severity': finding.severity,
                'Confidence Score': finding.confidence_score,
                'Novelty Score': finding.novelty_score,
                'Risk Score': finding.risk_score,
                'Description': finding.description,
                'Evidence Count': len(finding.evidence),
                'Recommendations Count': len(finding.recommendations),
                'Timestamp': finding.timestamp
            })
        
        df = pd.DataFrame(data)
        
        report_path = os.path.join(
            self.config.output_directory,
            f"redteam_findings_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        )
        
        df.to_csv(report_path, index=False)
        return report_path
    
    def _generate_executive_summary_report(self, findings: List[VulnerabilityFinding]) -> str:
        """Generate standalone executive summary report."""
        summary = self._generate_executive_summary(findings)
        
        summary_data = {
            'title': 'Red Team Testing - Executive Summary',
            'generated_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'summary': summary
        }
        
        report_path = os.path.join(
            self.config.output_directory,
            f"executive_summary_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        )
        
        with open(report_path, 'w', encoding='utf-8') as f:
            json.dump(asdict(summary), f, indent=2, default=str)
        
        return report_path
    
    def _generate_novel_vulnerabilities_report(self, findings: List[VulnerabilityFinding]) -> str:
        """Generate report focusing on novel vulnerabilities."""
        novel_findings = [f for f in findings if f.novelty_score > 0.5]
        
        novel_data = {
            'title': 'Novel Vulnerabilities Report',
            'generated_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'total_novel_vulnerabilities': len(novel_findings),
            'high_novelty_threshold': 0.7,
            'vulnerabilities': [
                {
                    'id': f.id,
                    'attack_vector': f.attack_vector,
                    'novelty_score': f.novelty_score,
                    'severity': f.severity,
                    'description': f.description,
                    'technique_summary': self._summarize_technique(f)
                }
                for f in sorted(novel_findings, key=lambda x: x.novelty_score, reverse=True)
            ]
        }
        
        report_path = os.path.join(
            self.config.output_directory,
            f"novel_vulnerabilities_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        )
        
        with open(report_path, 'w', encoding='utf-8') as f:
            json.dump(novel_data, f, indent=2, default=str)
        
        return report_path
    
    # Analysis helper methods
    def _analyze_attack_vectors(self, findings: List[VulnerabilityFinding]) -> Dict[str, int]:
        """Analyze distribution of attack vectors."""
        vectors = {}
        for finding in findings:
            vectors[finding.attack_vector] = vectors.get(finding.attack_vector, 0) + 1
        return vectors
    
    def _analyze_severity_distribution(self, findings: List[VulnerabilityFinding]) -> Dict[str, int]:
        """Analyze distribution of severity levels."""
        severities = {}
        for finding in findings:
            severities[finding.severity] = severities.get(finding.severity, 0) + 1
        return severities
    
    def _analyze_confidence_scores(self, findings: List[VulnerabilityFinding]) -> Dict[str, float]:
        """Analyze confidence score statistics."""
        if not findings:
            return {'average': 0.0, 'min': 0.0, 'max': 0.0}
        
        scores = [f.confidence_score for f in findings]
        return {
            'average': sum(scores) / len(scores),
            'min': min(scores),
            'max': max(scores),
            'high_confidence_count': len([s for s in scores if s > 0.8])
        }
    
    def _analyze_novelty_distribution(self, findings: List[VulnerabilityFinding]) -> Dict[str, Any]:
        """Analyze novelty score distribution."""
        if not findings:
            return {'average': 0.0, 'novel_count': 0, 'distribution': {}}
        
        scores = [f.novelty_score for f in findings]
        distribution = {
            'very_high': len([s for s in scores if s > 0.8]),
            'high': len([s for s in scores if 0.6 < s <= 0.8]),
            'medium': len([s for s in scores if 0.4 < s <= 0.6]),
            'low': len([s for s in scores if s <= 0.4])
        }
        
        return {
            'average': sum(scores) / len(scores),
            'novel_count': len([s for s in scores if s > 0.7]),
            'distribution': distribution
        }
    
    def _analyze_risk_distribution(self, findings: List[VulnerabilityFinding]) -> Dict[str, Any]:
        """Analyze risk score distribution."""
        if not findings:
            return {'average': 0.0, 'high_risk_count': 0}
        
        scores = [f.risk_score for f in findings]
        return {
            'average': sum(scores) / len(scores),
            'high_risk_count': len([s for s in scores if s > 7.0]),
            'critical_risk_count': len([s for s in scores if s > 8.5])
        }
    
    def _extract_key_findings(self, findings: List[VulnerabilityFinding]) -> List[str]:
        """Extract key findings for executive summary."""
        key_findings = []
        
        # High severity findings
        critical_count = len([f for f in findings if f.severity.lower() == 'critical'])
        if critical_count > 0:
            key_findings.append(f"Identified {critical_count} critical vulnerabilities requiring immediate attention")
        
        # Novel findings
        novel_count = len([f for f in findings if f.novelty_score > 0.7])
        if novel_count > 0:
            key_findings.append(f"Discovered {novel_count} novel attack techniques not previously documented")
        
        # Attack vector analysis
        vectors = self._analyze_attack_vectors(findings)
        if vectors:
            most_common = max(vectors.items(), key=lambda x: x[1])
            key_findings.append(f"Most prevalent attack vector: {most_common[0]} ({most_common[1]} instances)")
        
        return key_findings
    
    def _extract_executive_recommendations(self, findings: List[VulnerabilityFinding]) -> List[str]:
        """Extract high-level recommendations."""
        recommendations = []
        
        critical_findings = [f for f in findings if f.severity.lower() == 'critical']
        if critical_findings:
            recommendations.append("Implement immediate patches for critical vulnerabilities")
        
        novel_findings = [f for f in findings if f.novelty_score > 0.7]
        if novel_findings:
            recommendations.append("Develop new detection rules for novel attack patterns")
            recommendations.append("Update security training to address new threat vectors")
        
        recommendations.append("Conduct regular red team assessments to identify emerging threats")
        
        return recommendations
    
    def _determine_impact_description(self, vulnerability) -> str:
        """Determine impact description from vulnerability data."""
        severity = vulnerability.severity.lower()
        vuln_type = vulnerability.vulnerability_type.lower()
        
        impact_map = {
            'critical': 'Severe impact with potential for complete system compromise',
            'high': 'High impact with significant security implications',
            'medium': 'Moderate impact requiring attention',
            'low': 'Low impact with minimal security risk'
        }
        
        return impact_map.get(severity, 'Impact assessment pending')
    
    def _summarize_technique(self, finding: VulnerabilityFinding) -> str:
        """Summarize the attack technique used."""
        return f"{finding.attack_vector} technique with {finding.confidence_score:.2f} confidence and {finding.novelty_score:.2f} novelty score"
    
    def _load_templates(self) -> Dict[str, Template]:
        """Load report templates."""
        templates = {}
        
        # For now, we'll use default templates
        # In a full implementation, you would load from template files
        templates['html'] = self._get_default_html_template()
        
        return templates
    
    def _get_default_html_template(self) -> Template:
        """Get default HTML template."""
        template_content = """
<!DOCTYPE html>
<html>
<head>
    <title>Red Team Testing Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .header { background-color: #f4f4f4; padding: 20px; border-radius: 5px; }
        .section { margin: 20px 0; }
        .vulnerability { border: 1px solid #ddd; padding: 15px; margin: 10px 0; border-radius: 5px; }
        .critical { border-left: 5px solid #d32f2f; }
        .high { border-left: 5px solid #f57c00; }
        .medium { border-left: 5px solid #fbc02d; }
        .low { border-left: 5px solid #388e3c; }
        .stats { display: flex; justify-content: space-around; margin: 20px 0; }
        .stat-box { text-align: center; padding: 15px; background-color: #f9f9f9; border-radius: 5px; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Red Team Testing Report</h1>
        <p>Generated: {{ metadata.generated_at }}</p>
        <p>Session ID: {{ metadata.session_id }}</p>
    </div>
    
    <div class="section">
        <h2>Executive Summary</h2>
        <div class="stats">
            <div class="stat-box">
                <h3>{{ executive_summary.vulnerabilities_found }}</h3>
                <p>Total Vulnerabilities</p>
            </div>
            <div class="stat-box">
                <h3>{{ executive_summary.critical_vulnerabilities }}</h3>
                <p>Critical</p>
            </div>
            <div class="stat-box">
                <h3>{{ executive_summary.novel_vulnerabilities }}</h3>
                <p>Novel</p>
            </div>
            <div class="stat-box">
                <h3>{{ "%.2f"|format(executive_summary.average_novelty_score) }}</h3>
                <p>Avg Novelty Score</p>
            </div>
        </div>
        
        <h3>Key Findings</h3>
        <ul>
        {% for finding in executive_summary.key_findings %}
            <li>{{ finding }}</li>
        {% endfor %}
        </ul>
    </div>
    
    <div class="section">
        <h2>Vulnerability Details</h2>
        {% for finding in findings %}
        <div class="vulnerability {{ finding.severity.lower() }}">
            <h3>{{ finding.title }}</h3>
            <p><strong>Severity:</strong> {{ finding.severity }}</p>
            <p><strong>Attack Vector:</strong> {{ finding.attack_vector }}</p>
            <p><strong>Confidence:</strong> {{ "%.2f"|format(finding.confidence_score) }}</p>
            <p><strong>Novelty Score:</strong> {{ "%.2f"|format(finding.novelty_score) }}</p>
            <p><strong>Description:</strong> {{ finding.description }}</p>
            {% if finding.evidence %}
            <p><strong>Evidence:</strong></p>
            <ul>
            {% for evidence in finding.evidence %}
                <li>{{ evidence }}</li>
            {% endfor %}
            </ul>
            {% endif %}
        </div>
        {% endfor %}
    </div>
</body>
</html>
        """
        return Template(template_content)
    
    # Additional analysis methods (simplified implementations)
    def _analyze_temporal_patterns(self, findings: List[VulnerabilityFinding]) -> Dict[str, Any]:
        return {'pattern': 'temporal analysis placeholder'}
    
    def _analyze_techniques(self, findings: List[VulnerabilityFinding]) -> Dict[str, Any]:
        return {'techniques': 'technique analysis placeholder'}
    
    def _identify_novel_techniques(self, findings: List[VulnerabilityFinding]) -> List[str]:
        return [f.attack_vector for f in findings if f.novelty_score > 0.8]
    
    def _calculate_innovation_metrics(self, findings: List[VulnerabilityFinding]) -> Dict[str, float]:
        if not findings:
            return {'innovation_index': 0.0, 'technique_diversity': 0.0}
        
        novelty_scores = [f.novelty_score for f in findings]
        unique_vectors = len(set(f.attack_vector for f in findings))
        
        return {
            'innovation_index': sum(novelty_scores) / len(novelty_scores),
            'technique_diversity': unique_vectors / len(findings)
        }
    
    def _compare_with_known_attacks(self, findings: List[VulnerabilityFinding]) -> Dict[str, Any]:
        return {'comparison': 'comparison analysis placeholder'}
    
    def _analyze_business_impact(self, findings: List[VulnerabilityFinding]) -> Dict[str, Any]:
        return {'impact': 'business impact analysis placeholder'}
    
    def _prioritize_mitigations(self, findings: List[VulnerabilityFinding]) -> List[Dict[str, Any]]:
        # Sort by risk score and return top priorities
        sorted_findings = sorted(findings, key=lambda x: x.risk_score, reverse=True)
        return [{'id': f.id, 'priority': i+1, 'risk_score': f.risk_score} 
                for i, f in enumerate(sorted_findings[:10])]
    
    def _generate_immediate_actions(self, findings: List[VulnerabilityFinding]) -> List[str]:
        actions = []
        critical_findings = [f for f in findings if f.severity.lower() == 'critical']
        if critical_findings:
            actions.append(f"Address {len(critical_findings)} critical vulnerabilities immediately")
        return actions
    
    def _generate_short_term_improvements(self, findings: List[VulnerabilityFinding]) -> List[str]:
        return ["Implement enhanced input validation", "Update security monitoring rules"]
    
    def _generate_long_term_strategy(self, findings: List[VulnerabilityFinding]) -> List[str]:
        return ["Develop comprehensive red team program", "Implement continuous security testing"]
    
    def _generate_detection_rules(self, findings: List[VulnerabilityFinding]) -> List[Dict[str, str]]:
        rules = []
        for finding in findings[:5]:  # Top 5 findings
            rules.append({
                'attack_vector': finding.attack_vector,
                'rule_description': f"Detect {finding.attack_vector} patterns"
            })
        return rules
    
    def _generate_training_recommendations(self, findings: List[VulnerabilityFinding]) -> List[str]:
        return ["Update security awareness training", "Conduct red team simulation exercises"]
    
    def _extract_attack_patterns(self, findings: List[VulnerabilityFinding]) -> List[Dict[str, Any]]:
        patterns = []
        for finding in findings:
            patterns.append({
                'attack_vector': finding.attack_vector,
                'pattern_signature': finding.prompt[:100] + '...' if len(finding.prompt) > 100 else finding.prompt
            })
        return patterns
    
    def _generate_statistical_summary(self, findings: List[VulnerabilityFinding]) -> Dict[str, Any]:
        return {
            'total_findings': len(findings),
            'attack_vectors': self._analyze_attack_vectors(findings),
            'severity_distribution': self._analyze_severity_distribution(findings),
            'novelty_stats': self._analyze_novelty_distribution(findings)
        }