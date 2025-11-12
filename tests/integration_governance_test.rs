use llm_incident_manager::integrations::governance::*;
use llm_incident_manager::models::{Incident, IncidentType, Severity};
use std::collections::HashMap;
use uuid::Uuid;

/// Helper function to create a test incident
fn create_test_incident(title: &str, severity: Severity) -> Incident {
    Incident::new(
        "test-source".to_string(),
        title.to_string(),
        "Test description".to_string(),
        severity,
        IncidentType::Security,
    )
}

/// Test governance client creation and local-only mode
#[tokio::test]
async fn test_governance_client_creation() {
    let client = GovernanceClient::local_only();

    // Health check should pass for local-only mode
    let healthy = client.health_check().await.unwrap();
    assert!(healthy);
}

/// Test governance client with remote endpoint (should fallback to local)
#[tokio::test]
async fn test_governance_client_with_endpoint() {
    let client = GovernanceClient::new(
        "http://localhost:9999".to_string(),
        Some("test-token".to_string()),
        5,
    );

    // Health check should fail for non-existent endpoint
    let healthy = client.health_check().await.unwrap();
    assert!(!healthy);
}

/// Test GDPR compliance checking
#[tokio::test]
async fn test_gdpr_compliance_check() {
    let client = GovernanceClient::local_only();

    let mut metadata = HashMap::new();
    metadata.insert("notification_sent".to_string(), serde_json::json!(false));

    let data = ComplianceData {
        classification: DataClassification::Restricted,
        personal_data: Some(PersonalDataInfo {
            contains_pii: true,
            data_subjects_affected: Some(1000),
            data_types: vec!["email".to_string(), "name".to_string()],
            processing_purpose: "incident investigation".to_string(),
        }),
        health_data: None,
        payment_data: None,
        metadata,
    };

    let request = ComplianceRequest::new(
        Uuid::new_v4(),
        vec![ComplianceFramework::GDPR],
        data,
    );

    let response = client.check_compliance(request).await.unwrap();

    // Should have violations due to notification not sent
    assert!(!response.is_compliant);
    assert!(!response.violations.is_empty());
    assert!(response.violations.iter().any(|v| v.policy_id == "GDPR-001"));
}

/// Test HIPAA compliance checking
#[tokio::test]
async fn test_hipaa_compliance_check() {
    let client = GovernanceClient::local_only();

    let mut metadata = HashMap::new();
    metadata.insert("data_encrypted".to_string(), serde_json::json!(false));

    let data = ComplianceData {
        classification: DataClassification::Confidential,
        personal_data: None,
        health_data: Some(HealthDataInfo {
            contains_phi: true,
            covered_entities_affected: vec!["Hospital A".to_string()],
            data_types: vec!["medical_records".to_string()],
        }),
        payment_data: None,
        metadata,
    };

    let request = ComplianceRequest::new(
        Uuid::new_v4(),
        vec![ComplianceFramework::HIPAA],
        data,
    );

    let response = client.check_compliance(request).await.unwrap();

    // Should have violations due to PHI not encrypted
    assert!(!response.is_compliant);
    assert!(!response.violations.is_empty());
    assert!(response.violations.iter().any(|v| v.policy_id == "HIPAA-001"));
}

/// Test PCI compliance checking
#[tokio::test]
async fn test_pci_compliance_check() {
    let client = GovernanceClient::local_only();

    let mut metadata = HashMap::new();
    metadata.insert("pci_compliant_storage".to_string(), serde_json::json!(false));

    let data = ComplianceData {
        classification: DataClassification::Restricted,
        personal_data: None,
        health_data: None,
        payment_data: Some(PaymentDataInfo {
            contains_cardholder_data: true,
            card_brands_affected: vec!["Visa".to_string(), "Mastercard".to_string()],
            transaction_count: Some(5000),
        }),
        metadata,
    };

    let request = ComplianceRequest::new(
        Uuid::new_v4(),
        vec![ComplianceFramework::PCI],
        data,
    );

    let response = client.check_compliance(request).await.unwrap();

    // Should have violations due to non-compliant storage
    assert!(!response.is_compliant);
    assert!(!response.violations.is_empty());
    assert!(response.violations.iter().any(|v| v.policy_id == "PCI-001"));
}

/// Test compliant data (no violations)
#[tokio::test]
async fn test_compliant_data() {
    let client = GovernanceClient::local_only();

    let mut metadata = HashMap::new();
    metadata.insert("notification_sent".to_string(), serde_json::json!(true));
    metadata.insert("data_encrypted".to_string(), serde_json::json!(true));
    metadata.insert("access_controls_enabled".to_string(), serde_json::json!(true));

    let data = ComplianceData {
        classification: DataClassification::Internal,
        personal_data: None,
        health_data: None,
        payment_data: None,
        metadata,
    };

    let request = ComplianceRequest::new(
        Uuid::new_v4(),
        vec![ComplianceFramework::SOC2],
        data,
    );

    let response = client.check_compliance(request).await.unwrap();

    // Should be compliant
    assert!(response.is_compliant);
    assert!(response.violations.is_empty());
}

/// Test multi-framework compliance checking
#[tokio::test]
async fn test_multi_framework_compliance() {
    let client = GovernanceClient::local_only();

    let data = ComplianceData {
        classification: DataClassification::Internal,
        personal_data: None,
        health_data: None,
        payment_data: None,
        metadata: HashMap::new(),
    };

    let request = ComplianceRequest::new(
        Uuid::new_v4(),
        vec![
            ComplianceFramework::GDPR,
            ComplianceFramework::HIPAA,
            ComplianceFramework::SOC2,
        ],
        data,
    );

    let response = client.check_compliance(request).await.unwrap();

    // Should complete without errors
    assert!(response.is_compliant || !response.violations.is_empty());
}

/// Test policy engine
#[tokio::test]
async fn test_policy_engine() {
    let engine = PolicyEngine::new();

    // Check that policies are loaded
    let gdpr_policies = engine.get_policies(&ComplianceFramework::GDPR);
    assert!(!gdpr_policies.is_empty());

    let hipaa_policies = engine.get_policies(&ComplianceFramework::HIPAA);
    assert!(!hipaa_policies.is_empty());

    let soc2_policies = engine.get_policies(&ComplianceFramework::SOC2);
    assert!(!soc2_policies.is_empty());
}

/// Test compliance event handler - incident created
#[tokio::test]
async fn test_event_handler_incident_created() {
    let handler = ComplianceEventHandler::new();

    let mut incident = create_test_incident("Security Incident", Severity::P0);
    let mut labels = HashMap::new();
    labels.insert("pii".to_string(), "true".to_string());
    labels.insert("gdpr".to_string(), "true".to_string());
    incident.labels = Some(labels);

    handler.on_incident_created(&incident).await.unwrap();

    // Check audit trail
    let entries = handler.get_audit_trail(incident.id).await.unwrap();
    assert!(!entries.is_empty());
    assert_eq!(entries[0].action, "incident_created");

    // Check metrics
    let metrics = handler.get_metrics().await.unwrap();
    assert!(metrics.total_checks > 0);
}

/// Test compliance event handler - incident updated
#[tokio::test]
async fn test_event_handler_incident_updated() {
    let handler = ComplianceEventHandler::new();

    let incident = create_test_incident("Test Incident", Severity::P1);

    handler.on_incident_updated(&incident, "user@example.com").await.unwrap();

    let entries = handler.get_audit_trail(incident.id).await.unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].action, "incident_updated");
    assert_eq!(entries[0].actor, "user@example.com");
}

/// Test compliance event handler - incident deleted
#[tokio::test]
async fn test_event_handler_incident_deleted() {
    let handler = ComplianceEventHandler::new();
    let incident_id = Uuid::new_v4();

    handler.on_incident_deleted(incident_id, "admin@example.com").await.unwrap();

    let entries = handler.get_audit_trail(incident_id).await.unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].action, "incident_deleted");
    assert_eq!(entries[0].actor, "admin@example.com");
}

/// Test compliance event handler - incident escalated
#[tokio::test]
async fn test_event_handler_incident_escalated() {
    let handler = ComplianceEventHandler::new();

    let incident = create_test_incident("Critical Incident", Severity::P0);

    handler.on_incident_escalated(&incident, "oncall-team@example.com").await.unwrap();

    let entries = handler.get_audit_trail(incident.id).await.unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].action, "incident_escalated");
}

/// Test audit report generation
#[tokio::test]
async fn test_audit_report_generation() {
    let client = GovernanceClient::local_only();
    let incident_id = Uuid::new_v4();

    let report = client.generate_audit_report(incident_id, AuditReportType::OnDemand).await.unwrap();

    assert_eq!(report.incident_id, incident_id);
    assert_eq!(report.report_type, AuditReportType::OnDemand);
    assert!(report.summary.len() > 0);
}

/// Test audit report compliance rate calculation
#[tokio::test]
async fn test_audit_report_compliance_rate() {
    let mut report = AuditReport::new(
        Uuid::new_v4(),
        AuditReportType::Daily,
        chrono::Utc::now(),
        chrono::Utc::now(),
    );

    report.total_checks = 100;
    report.compliant_checks = 85;

    assert_eq!(report.compliance_rate(), 85.0);

    // Test zero checks
    report.total_checks = 0;
    report.compliant_checks = 0;
    assert_eq!(report.compliance_rate(), 0.0);
}

/// Test policy violation creation
#[tokio::test]
async fn test_policy_violation_creation() {
    let violation = PolicyViolation::new(
        ComplianceFramework::GDPR,
        "GDPR-001".to_string(),
        "Data Breach Notification".to_string(),
        ViolationSeverity::Critical,
        "Notification not sent within 72 hours".to_string(),
        "Send notification immediately".to_string(),
    );

    assert_eq!(violation.framework, ComplianceFramework::GDPR);
    assert_eq!(violation.severity, ViolationSeverity::Critical);
    assert!(!violation.description.is_empty());
    assert!(!violation.remediation.is_empty());
}

/// Test violation severity ordering
#[tokio::test]
async fn test_violation_severity_ordering() {
    let mut violations = vec![
        PolicyViolation::new(
            ComplianceFramework::GDPR,
            "1".to_string(),
            "Low".to_string(),
            ViolationSeverity::Low,
            "desc".to_string(),
            "fix".to_string(),
        ),
        PolicyViolation::new(
            ComplianceFramework::GDPR,
            "2".to_string(),
            "Critical".to_string(),
            ViolationSeverity::Critical,
            "desc".to_string(),
            "fix".to_string(),
        ),
        PolicyViolation::new(
            ComplianceFramework::GDPR,
            "3".to_string(),
            "High".to_string(),
            ViolationSeverity::High,
            "desc".to_string(),
            "fix".to_string(),
        ),
    ];

    violations.sort_by(|a, b| b.severity.cmp(&a.severity));

    assert_eq!(violations[0].severity, ViolationSeverity::Critical);
    assert_eq!(violations[1].severity, ViolationSeverity::High);
    assert_eq!(violations[2].severity, ViolationSeverity::Low);
}

/// Test governance metrics tracking
#[tokio::test]
async fn test_governance_metrics() {
    let handler = ComplianceEventHandler::new();

    let incident = create_test_incident("Metrics Test", Severity::P2);

    handler.on_incident_created(&incident).await.unwrap();

    let metrics = handler.get_metrics().await.unwrap();
    assert!(metrics.total_checks > 0);
}

/// Test audit entry with details
#[tokio::test]
async fn test_audit_entry_with_details() {
    let entry = AuditEntry::new(
        Uuid::new_v4(),
        "test_action".to_string(),
        "test_actor".to_string(),
    )
    .with_detail("key1".to_string(), serde_json::json!("value1"))
    .with_detail("key2".to_string(), serde_json::json!(42));

    assert_eq!(entry.details.len(), 2);
    assert!(entry.details.contains_key("key1"));
    assert!(entry.details.contains_key("key2"));
}

/// Test compliance data classification
#[tokio::test]
async fn test_compliance_data_classification() {
    let data = ComplianceData {
        classification: DataClassification::Restricted,
        personal_data: None,
        health_data: None,
        payment_data: None,
        metadata: HashMap::new(),
    };

    assert_eq!(data.classification, DataClassification::Restricted);
}

/// Test recommendations generation
#[tokio::test]
async fn test_recommendations_generation() {
    let client = GovernanceClient::local_only();

    let data = ComplianceData {
        classification: DataClassification::Confidential,
        personal_data: Some(PersonalDataInfo {
            contains_pii: true,
            data_subjects_affected: Some(50),
            data_types: vec!["email".to_string()],
            processing_purpose: "investigation".to_string(),
        }),
        health_data: Some(HealthDataInfo {
            contains_phi: true,
            covered_entities_affected: vec!["Hospital".to_string()],
            data_types: vec!["records".to_string()],
        }),
        payment_data: None,
        metadata: HashMap::new(),
    };

    let request = ComplianceRequest::new(
        Uuid::new_v4(),
        vec![ComplianceFramework::GDPR, ComplianceFramework::HIPAA],
        data,
    );

    let response = client.check_compliance(request).await.unwrap();
    assert!(!response.recommendations.is_empty());
}

/// Test custom compliance framework
#[tokio::test]
async fn test_custom_compliance_framework() {
    let framework = ComplianceFramework::Custom("MyCompanyPolicy".to_string());

    let data = ComplianceData {
        classification: DataClassification::Internal,
        personal_data: None,
        health_data: None,
        payment_data: None,
        metadata: HashMap::new(),
    };

    let request = ComplianceRequest::new(
        Uuid::new_v4(),
        vec![framework],
        data,
    );

    // Should not panic with custom framework
    assert_eq!(request.frameworks.len(), 1);
}

/// Test concurrent compliance checks
#[tokio::test]
async fn test_concurrent_compliance_checks() {
    let client = GovernanceClient::local_only();

    let mut handles = vec![];

    for i in 0..10 {
        let client = client.clone();
        let handle = tokio::spawn(async move {
            let data = ComplianceData {
                classification: DataClassification::Internal,
                personal_data: None,
                health_data: None,
                payment_data: None,
                metadata: HashMap::new(),
            };

            let request = ComplianceRequest::new(
                Uuid::new_v4(),
                vec![ComplianceFramework::SOC2],
                data,
            );

            client.check_compliance(request).await
        });
        handles.push(handle);
    }

    for handle in handles {
        let result = handle.await.unwrap();
        assert!(result.is_ok());
    }
}

/// Test error handling for timeout (simulated with local-only)
#[tokio::test]
async fn test_timeout_handling() {
    let client = GovernanceClient::new(
        "http://localhost:9999".to_string(),
        None,
        1, // 1 second timeout
    );

    // With local fallback, this should still succeed
    let data = ComplianceData {
        classification: DataClassification::Internal,
        personal_data: None,
        health_data: None,
        payment_data: None,
        metadata: HashMap::new(),
    };

    let request = ComplianceRequest::new(
        Uuid::new_v4(),
        vec![ComplianceFramework::SOC2],
        data,
    );

    let response = client.check_compliance(request).await.unwrap();
    assert!(response.is_compliant || !response.violations.is_empty());
}
