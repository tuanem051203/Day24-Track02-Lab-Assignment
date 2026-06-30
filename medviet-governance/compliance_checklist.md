# NĐ13/2023 Compliance Checklist — MedViet AI Platform

## A. Data Localization
- [x] Tất cả patient data lưu trên servers đặt tại Việt Nam
- [x] Backup cũng phải ở trong lãnh thổ VN
- [x] Log việc transfer data ra ngoài nếu có (OPA policy: deny nếu destination_country != "VN")

## B. Explicit Consent
- [ ] Thu thập consent trước khi dùng data cho AI training
- [ ] Có mechanism để user rút consent (Right to Erasure)
- [ ] Lưu consent record với timestamp

## C. Breach Notification (72h)
- [ ] Có incident response plan
- [ ] Alert tự động khi phát hiện breach
- [ ] Quy trình báo cáo đến cơ quan có thẩm quyền trong 72h

## D. DPO Appointment
- [ ] Đã bổ nhiệm Data Protection Officer
- [ ] DPO có thể liên hệ tại: ___

## E. Technical Controls (mapping từ requirements)
| NĐ13 Requirement | Technical Control | Status | Owner |
|-----------------|-------------------|--------|-------|
| Data minimization | PII anonymization pipeline (Presidio) | ✅ Done | AI Team |
| Access control | RBAC (Casbin) + ABAC (OPA) + Agent Governance (AGT) | ✅ Done | Platform Team |
| Encryption | AES-256-GCM envelope encryption (SimpleVault) + TLS 1.3 in transit | ✅ Done | Infra Team |
| Audit logging | FastAPI request logging + Prometheus metrics + CloudTrail | 🚧 In Progress | Platform Team |
| Breach detection | Anomaly monitoring (Prometheus + Grafana) + automated alerts | 🚧 In Progress | Security Team |
| Data quality | Great Expectations validation suite | ✅ Done | AI Team |
| Security scanning | git-secrets pre-commit hook + Bandit SAST + pip-audit | ✅ Done | Platform Team |

## F. Technical Solutions cho các mục TODO

### Audit Logging
- **Solution:** FastAPI middleware để log mọi request (user, action, timestamp, status code) vào audit log file.
- **Prometheus metrics:** Export custom metrics cho mỗi API call (request_count, response_time, error_rate).
- **CloudTrail integration:** AWS CloudTrail hoặc equivalent để audit mọi truy cập S3/blob storage chứa data.
- **Retention:** Audit logs lưu tối thiểu 2 năm theo yêu cầu NĐ13.

### Breach Detection
- **Solution:** Prometheus alerting rules để detect anomalous access patterns:
  - Spike trong số lượng request từ một user/IP
  - Access denied rate tăng bất thường
  - Data export volume vượt ngưỡng
- **Grafana dashboards:** Real-time monitoring cho API access, PII detection rate, encryption status.
- **Automated alerting:** PagerDuty/Slack integration để thông báo security team trong 15 phút.
- **Incident response:** Runbook tự động hóa quá trình contain → investigate → notify trong 72h.

## G. Additional NĐ13 Controls
| Requirement | Implementation | Status |
|------------|----------------|--------|
| PII detection ≥ 95% | Presidio analyzer với CCCD, phone, email, person recognizers | ✅ |
| Anonymization | Replace, mask, hash strategies | ✅ |
| Role-based access | 4 roles: admin, ml_engineer, data_analyst, intern | ✅ |
| Envelope encryption | KEK + DEK pattern với AES-256-GCM | ✅ |
| Data validation | Great Expectations suite cho schema + values | ✅ |
| Agent governance | Microsoft AGT PolicyEvaluator + StatelessKernel | ✅ |
| OPA policy engine | Rego rules cho data access control | ✅ |
