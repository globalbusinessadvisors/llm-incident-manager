use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

/// Compliance frameworks supported by the governance system
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "UPPERCASE")]
pub enum ComplianceFramework {
    GDPR,
    HIPAA,
    SOC2,
    PCI,
    ISO27001,
    Custom(String),
}

/// Compliance check request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceRequest {
    pub id: Uuid,
    pub incident_id: Uuid,
    pub frameworks: Vec<ComplianceFramework>,
    pub data: ComplianceData,
    pub timestamp: DateTime<Utc>,
}

impl ComplianceRequest {
    pub fn new(incident_id: Uuid, frameworks: Vec<ComplianceFramework>, data: ComplianceData) -> Self {
        Self {
            id: Uuid::new_v4(),
            incident_id,
            frameworks,
            data,
            timestamp: Utc::now(),
        }
    }
}

/// Data to be checked for compliance
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceData {
    /// Data classification level
    pub classification: DataClassification,

    /// Personal data contained in incident
    pub personal_data: Option<PersonalDataInfo>,

    /// Health information
    pub health_data: Option<HealthDataInfo>,

    /// Payment information
    pub payment_data: Option<PaymentDataInfo>,

    /// Custom metadata for compliance checks
    pub metadata: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum DataClassification {
    Public,
    Internal,
    Confidential,
    Restricted,
}

/// Personal data information for GDPR compliance
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersonalDataInfo {
    pub contains_pii: bool,
    pub data_subjects_affected: Option<u64>,
    pub data_types: Vec<String>,
    pub processing_purpose: String,
}

/// Health data information for HIPAA compliance
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthDataInfo {
    pub contains_phi: bool,
    pub covered_entities_affected: Vec<String>,
    pub data_types: Vec<String>,
}

/// Payment data information for PCI compliance
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentDataInfo {
    pub contains_cardholder_data: bool,
    pub card_brands_affected: Vec<String>,
    pub transaction_count: Option<u64>,
}

/// Compliance check response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceResponse {
    pub request_id: Uuid,
    pub incident_id: Uuid,
    pub is_compliant: bool,
    pub violations: Vec<PolicyViolation>,
    pub recommendations: Vec<String>,
    pub audit_entry_id: Option<Uuid>,
    pub checked_at: DateTime<Utc>,
}

/// Policy violation details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyViolation {
    pub id: Uuid,
    pub framework: ComplianceFramework,
    pub policy_id: String,
    pub policy_name: String,
    pub severity: ViolationSeverity,
    pub description: String,
    pub remediation: String,
    pub detected_at: DateTime<Utc>,
}

impl PolicyViolation {
    pub fn new(
        framework: ComplianceFramework,
        policy_id: String,
        policy_name: String,
        severity: ViolationSeverity,
        description: String,
        remediation: String,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            framework,
            policy_id,
            policy_name,
            severity,
            description,
            remediation,
            detected_at: Utc::now(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum ViolationSeverity {
    Low,
    Medium,
    High,
    Critical,
}

/// Audit report for compliance tracking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditReport {
    pub id: Uuid,
    pub incident_id: Uuid,
    pub report_type: AuditReportType,
    pub period_start: DateTime<Utc>,
    pub period_end: DateTime<Utc>,
    pub total_checks: u64,
    pub compliant_checks: u64,
    pub violations: Vec<PolicyViolation>,
    pub summary: String,
    pub created_at: DateTime<Utc>,
}

impl AuditReport {
    pub fn new(
        incident_id: Uuid,
        report_type: AuditReportType,
        period_start: DateTime<Utc>,
        period_end: DateTime<Utc>,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            incident_id,
            report_type,
            period_start,
            period_end,
            total_checks: 0,
            compliant_checks: 0,
            violations: Vec::new(),
            summary: String::new(),
            created_at: Utc::now(),
        }
    }

    pub fn compliance_rate(&self) -> f64 {
        if self.total_checks == 0 {
            0.0
        } else {
            (self.compliant_checks as f64 / self.total_checks as f64) * 100.0
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum AuditReportType {
    Daily,
    Weekly,
    Monthly,
    Quarterly,
    OnDemand,
}

/// Audit trail entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub id: Uuid,
    pub incident_id: Uuid,
    pub action: String,
    pub actor: String,
    pub details: HashMap<String, serde_json::Value>,
    pub timestamp: DateTime<Utc>,
}

impl AuditEntry {
    pub fn new(incident_id: Uuid, action: String, actor: String) -> Self {
        Self {
            id: Uuid::new_v4(),
            incident_id,
            action,
            actor,
            details: HashMap::new(),
            timestamp: Utc::now(),
        }
    }

    pub fn with_detail(mut self, key: String, value: serde_json::Value) -> Self {
        self.details.insert(key, value);
        self
    }
}

/// Governance metrics for monitoring
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GovernanceMetrics {
    pub total_checks: u64,
    pub passed_checks: u64,
    pub failed_checks: u64,
    pub total_violations: u64,
    pub violations_by_severity: HashMap<String, u64>,
    pub violations_by_framework: HashMap<String, u64>,
    pub avg_check_duration_ms: f64,
    pub last_updated: DateTime<Utc>,
}

impl Default for GovernanceMetrics {
    fn default() -> Self {
        Self {
            total_checks: 0,
            passed_checks: 0,
            failed_checks: 0,
            total_violations: 0,
            violations_by_severity: HashMap::new(),
            violations_by_framework: HashMap::new(),
            avg_check_duration_ms: 0.0,
            last_updated: Utc::now(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compliance_request_creation() {
        let data = ComplianceData {
            classification: DataClassification::Confidential,
            personal_data: Some(PersonalDataInfo {
                contains_pii: true,
                data_subjects_affected: Some(100),
                data_types: vec!["email".to_string(), "name".to_string()],
                processing_purpose: "incident investigation".to_string(),
            }),
            health_data: None,
            payment_data: None,
            metadata: HashMap::new(),
        };

        let request = ComplianceRequest::new(
            Uuid::new_v4(),
            vec![ComplianceFramework::GDPR],
            data,
        );

        assert_eq!(request.frameworks.len(), 1);
        assert_eq!(request.frameworks[0], ComplianceFramework::GDPR);
    }

    #[test]
    fn test_policy_violation_creation() {
        let violation = PolicyViolation::new(
            ComplianceFramework::GDPR,
            "GDPR-001".to_string(),
            "Data Breach Notification".to_string(),
            ViolationSeverity::High,
            "Notification not sent within 72 hours".to_string(),
            "Send breach notification immediately".to_string(),
        );

        assert_eq!(violation.severity, ViolationSeverity::High);
        assert_eq!(violation.framework, ComplianceFramework::GDPR);
    }

    #[test]
    fn test_audit_report_compliance_rate() {
        let mut report = AuditReport::new(
            Uuid::new_v4(),
            AuditReportType::Daily,
            Utc::now(),
            Utc::now(),
        );

        report.total_checks = 100;
        report.compliant_checks = 95;

        assert_eq!(report.compliance_rate(), 95.0);
    }

    #[test]
    fn test_audit_entry_with_details() {
        let entry = AuditEntry::new(
            Uuid::new_v4(),
            "incident_created".to_string(),
            "system".to_string(),
        )
        .with_detail("severity".to_string(), serde_json::json!("high"))
        .with_detail("source".to_string(), serde_json::json!("sentinel"));

        assert_eq!(entry.details.len(), 2);
        assert!(entry.details.contains_key("severity"));
    }

    #[test]
    fn test_violation_severity_ordering() {
        assert!(ViolationSeverity::Critical > ViolationSeverity::High);
        assert!(ViolationSeverity::High > ViolationSeverity::Medium);
        assert!(ViolationSeverity::Medium > ViolationSeverity::Low);
    }
}
