workspace "Smart Parking System" "High-interoperability smart parking system architecture" {

    !identifiers hierarchical
    
    model {
        group "Smart Parking Enterprise" {
            driver = person "Driver" "Uses mobile app and interacts with parking system" {
                url https://example.com/driver
            }
            
            admin = person "Administrator" "Manages system through dashboard" {
                url https://example.com/admin
            }
            
            # Threat Actors and Misuse Cases
            externalAttacker = person "External Attacker" "Malicious external entity attempting to compromise the system" {
                tags "Threat Actor,External,Internet Zone"
            }
            
            maliciousInsider = person "Malicious Insider" "Authorized user with malicious intent" {
                tags "Threat Actor,Internal,Cloud Zone"
            }
            
            scriptKiddie = person "Script Kiddie" "Low-skill attacker using automated tools" {
                tags "Threat Actor,External,Internet Zone"
            }
            
            nationState = person "Nation State Actor" "Sophisticated attacker with significant resources" {
                tags "Threat Actor,External,Internet Zone,Advanced"
            }
            
            system = softwareSystem "Smart Parking System" "Data-first, contract-led microservices with standardized schemas and unified ontology" {
                # Edge Zone Components
                anprService = container "ANPR Service" "Performs real-time license plate recognition with versioned API" "Python/FastAPI" {
                    tags "Edge Service,Microservice,High Risk,Edge Zone"
                    url https://github.com/your-repo/anpr-service
                }
                
                gateway = container "Gateway Service" "Secure protocol translation with Modbus security wrapper and pluggable adapters" "Python + TLS/VPN + Security Framework" {
                    tags "Edge Service,Event Publisher,High Risk,Edge Zone,Supply Chain Tracked"
                    url https://github.com/your-repo/gateway-service
                    properties {
                        "arch.ref" "smartparking.arch.container.gateway-service"
                        "bom.enabled" "true"
                        "bom.ref" "smartparking.bom.gateway-service"
                        "runtime.unit" "edge-gateway-service"
                        "sbom.scope" "deployable-unit"
                        "cbom.scope" "transport-crypto-and-device-auth"
                        "vex.scope" "deployable-unit"
                        "asset.criticality" "high"
                        "deployment.zone" "edge"
                    }
                    
                    rtspClient = component "RTSP Client" "Handles video stream ingestion with mTLS" "Python"
                    onvifParser = component "ONVIF Parser" "Processes camera metadata with validation" "Python"
                    mqttPublisher = component "MQTT Publisher" "Publishes standardized device events with encryption" "Python/paho-mqtt"
                    modbusTranslator = component "Modbus Translator" "Converts to industrial protocols with sanitization" "Python"
                    modbusSecurityWrapper = component "Modbus Security Wrapper" "TLS/SSL tunneling and device authentication for Modbus/RS485" "Python + TLS"
                    modbusProtocolFilter = component "Modbus Protocol Filter" "Whitelist-based command filtering and input validation" "Python"
                    modbusAnomalyDetector = component "Modbus Anomaly Detector" "Real-time monitoring and detection of malicious Modbus traffic" "Python + ML"
                    deviceCertificateManager = component "Device Certificate Manager" "X.509 certificate management for Modbus device authentication" "Python + Vault"
                    schemaValidator = component "Schema Validator" "Validates events against Schema Registry" "Python"
                    securityValidator = component "Security Validator" "Validates and sanitizes all incoming data" "Python"
                    authHandler = component "Auth Handler" "Handles device authentication and authorization" "Python"
                    pluginLoader = component "Plugin Loader" "Loads and manages protocol adapter plugins" "Python"
                    adapterRuntime = component "Adapter Runtime" "Executes pluggable protocol adapters" "Python"
                }
                
                edgeAI = container "Edge AI Runtime" "Real-time inference on edge devices with model versioning" "TensorFlow Lite/ONNX" {
                    tags "Edge Service,AI/ML,High Risk,Edge Zone,Supply Chain Tracked"
                    url https://github.com/your-repo/edge-ai
                    properties {
                        "arch.ref" "smartparking.arch.container.edge-ai-runtime"
                        "bom.enabled" "true"
                        "bom.ref" "smartparking.bom.edge-ai-runtime"
                        "runtime.unit" "edge-ai-runtime"
                        "sbom.scope" "deployable-unit"
                        "cbom.scope" "model-integrity-and-secure-channel"
                        "vex.scope" "edge-inference-runtime"
                        "asset.criticality" "high"
                        "deployment.zone" "edge"
                    }
                }
                
                edgeStorage = container "Edge Storage" "Local storage for autonomous operation during outages" "MinIO/EdgeFS" {
                    tags "Edge Service,Storage,High Risk,Edge Zone"
                    url https://min.io/
                }
                
                edgeOrchestrator = container "Edge Orchestrator" "K3s-based container orchestration for edge devices" "K3s" {
                    tags "Edge Service,Orchestration,High Risk,Edge Zone"
                    url https://k3s.io/
                }
                
                securityGateway = container "Security Gateway" "Zero-trust protocol translation with validation" "Envoy Proxy" {
                    tags "Edge Service,Security,High Risk,Edge Zone"
                    url https://envoyproxy.io/
                }
                
                protocolAdapterManager = container "Protocol Adapter Manager" "Pluggable protocol translators and adapters" "Plugin Manager" {
                    tags "Edge Service,Platform,High Risk,Edge Zone"
                    url https://github.com/your-repo/protocol-adapters
                }
                
                # Fog Zone Components
                fogGateway = container "Fog Gateway" "Aggregation and analytics layer between edge and cloud" "Kubernetes" {
                    tags "Fog Service,Gateway,Medium Risk,Fog Zone"
                    url https://github.com/your-repo/fog-gateway
                }
                
                # Cloud Zone Components
                apiGateway = container "API Gateway" "Centralized API management with versioning and contract enforcement" "Kong/AWS API Gateway" {
                    tags "Cloud Service,API Management,Medium Risk,Cloud Zone,Supply Chain Tracked"
                    url https://github.com/your-repo/api-gateway
                    properties {
                        "arch.ref" "smartparking.arch.container.api-gateway"
                        "bom.enabled" "true"
                        "bom.ref" "smartparking.bom.api-gateway"
                        "runtime.unit" "cloud-api-gateway"
                        "sbom.scope" "deployable-unit"
                        "cbom.scope" "tls-termination-and-token-validation"
                        "vex.scope" "internet-facing-runtime"
                        "asset.criticality" "high"
                        "deployment.zone" "cloud"
                    }
                }
                
                schemaRegistry = container "Schema Registry" "Centralized schema management for all events and data payloads" "Confluent Schema Registry" {
                    tags "Cloud Service,Data Management"
                    url https://docs.confluent.io/platform/current/schema-registry/
                }
                
                dataFabric = container "Data Fabric" "Unified data management and standardized data access layer" "Apache Kafka Connect + DataHub" {
                    tags "Cloud Service,Data Management"
                    url https://github.com/your-repo/data-fabric
                }
                
                ontologyService = container "Ontology Service" "Formal definitions of parking entities (Spaces, Vehicles, Gates, Permits)" "Python/FastAPI" {
                    tags "Cloud Service,Data Management"
                    url https://github.com/your-repo/ontology-service
                }
                
                eventBus = container "Event Bus" "Message broker for asynchronous event-driven communication with schema validation" "Apache Kafka" {
                    tags "Cloud Service,Event-Driven,Cloud Zone,Supply Chain Tracked"
                    url https://kafka.apache.org/
                    properties {
                        "arch.ref" "smartparking.arch.container.event-bus"
                        "bom.enabled" "true"
                        "bom.ref" "smartparking.bom.event-bus"
                        "runtime.unit" "cloud-event-bus"
                        "sbom.scope" "platform-service"
                        "cbom.scope" "none"
                        "vex.scope" "platform-service"
                        "asset.criticality" "high"
                        "deployment.zone" "cloud"
                    }
                }
                
                accessControl = container "Access Control Service" "Manages gate operations with contract-first API design" "Python/FastAPI" {
                    tags "Cloud Service,Microservice,Cloud Zone"
                    url https://github.com/your-repo/access-control-service
                }
                
                parkingMgmt = container "Parking Space Management" "Tracks occupancy and reservations via versioned APIs" "Python/FastAPI" {
                    tags "Cloud Service,Microservice"
                    url https://github.com/your-repo/parking-service
                }
                
                paymentService = container "Payment Service" "Handles payment processing with versioned payment APIs" "Python/FastAPI" {
                    tags "Cloud Service,Microservice"
                    url https://github.com/your-repo/payment-service
                }
                
                mlopsPipeline = container "MLOps Pipeline" "Automated model training, validation, packaging, and deployment" "Kubeflow/Airflow" {
                    tags "Cloud Service,MLOps"
                    url https://github.com/your-repo/mlops-pipeline
                }
                
                modelRegistry = container "Model Registry" "Versioned AI model artifacts and metadata management" "MLflow Model Registry" {
                    tags "Cloud Service,MLOps"
                    url https://mlflow.org/
                }
                
                modelServing = container "Model Serving" "A/B testing, canary releases, and shadow mode deployment" "Seldon Core" {
                    tags "Cloud Service,MLOps"
                    url https://github.com/SeldonIO/seldon-core
                }
                
                modelMonitoring = container "Model Monitoring" "Performance drift detection and centralized monitoring" "Evidently AI" {
                    tags "Cloud Service,MLOps"
                    url https://evidentlyai.com/
                }
                
                aiAnalytics = container "AI Analytics Service" "ML-powered insights using standardized data schemas" "Python/TensorFlow" {
                    tags "Cloud Service,AI/ML"
                    url https://github.com/your-repo/ai-analytics
                }
                
                
                
                
                otaManager = container "OTA Manager" "Over-the-air updates for edge software and models" "Balena/OTA" {
                    tags "Cloud Service,Deployment"
                    url https://github.com/your-repo/ota-manager
                }
                
                
                identityProvider = container "Identity Provider" "Zero-trust identity management for all entities" "Keycloak/Auth0" {
                    tags "Cloud Service,Security,Supply Chain Tracked"
                    url https://www.keycloak.org/
                    properties {
                        "arch.ref" "smartparking.arch.container.identity-provider"
                        "bom.enabled" "true"
                        "bom.ref" "smartparking.bom.identity-provider"
                        "runtime.unit" "cloud-identity-provider"
                        "sbom.scope" "security-service"
                        "cbom.scope" "token-signing-and-trust-material"
                        "vex.scope" "identity-runtime"
                        "asset.criticality" "high"
                        "deployment.zone" "cloud"
                    }
                }
                
                certificateAuthority = container "Certificate Authority" "X.509 certificate management for devices and services" "HashiCorp Vault" {
                    tags "Cloud Service,Security"
                    url https://www.vaultproject.io/
                }
                
                policyEngine = container "Policy Engine" "Least privilege access control and authorization" "Open Policy Agent" {
                    tags "Cloud Service,Security"
                    url https://www.openpolicyagent.org/
                }
                
                
                securityMonitoring = container "Security Monitoring" "Threat detection and security event analysis" "ELK Stack + Wazuh" {
                    tags "Cloud Service,Security"
                    url https://wazuh.com/
                }
                
                encryptionService = container "Encryption Service" "Data encryption at rest and key management" "HashiCorp Vault" {
                    tags "Cloud Service,Security"
                    url https://www.vaultproject.io/
                }
                
                metricsCollector = container "Metrics Collector" "Prometheus-based metrics collection and aggregation" "Prometheus" {
                    tags "Cloud Service,Observability"
                    url https://prometheus.io/
                }
                
                logAggregator = container "Log Aggregator" "Centralized logging and log analysis" "ELK Stack" {
                    tags "Cloud Service,Observability"
                    url https://www.elastic.co/elk-stack
                }
                
                tracingPlatform = container "Tracing Platform" "Distributed tracing for request flow tracking" "Jaeger" {
                    tags "Cloud Service,Observability"
                    url https://www.jaegertracing.io/
                }
                
                observabilityDashboard = container "Observability Dashboard" "Unified monitoring and alerting interface" "Grafana" {
                    tags "Cloud Service,Observability"
                    url https://grafana.com/
                }
                
                aiMetricsCollector = container "AI Metrics Collector" "ML-specific metrics and model performance tracking" "MLflow + Prometheus" {
                    tags "Cloud Service,Observability"
                    url https://mlflow.org/
                }
                
                alertingSystem = container "Alerting System" "Proactive alerting and notification management" "AlertManager + PagerDuty" {
                    tags "Cloud Service,Observability"
                    url https://prometheus.io/docs/alerting/latest/alertmanager/
                }
                
                infrastructureAsCode = container "Infrastructure as Code" "Terraform-based infrastructure provisioning and management" "Terraform + Ansible" {
                    tags "Cloud Service,Configuration"
                    url https://www.terraform.io/
                }
                
                configurationManager = container "Configuration Manager" "Dynamic configuration and feature flag management" "Consul + Vault" {
                    tags "Cloud Service,Configuration"
                    url https://www.consul.io/
                }
                
                deploymentPipeline = container "Deployment Pipeline" "Automated CI/CD for infrastructure and applications" "GitLab CI/CD" {
                    tags "Cloud Service,Configuration"
                    url https://docs.gitlab.com/ee/ci/
                }
                
                environmentManager = container "Environment Manager" "Multi-tenant environment provisioning and management" "Kubernetes + Helm" {
                    tags "Cloud Service,Configuration"
                    url https://helm.sh/
                }
                
                featureFlagService = container "Feature Flag Service" "Dynamic feature toggles and A/B testing configuration" "LaunchDarkly/Unleash" {
                    tags "Cloud Service,Configuration"
                    url https://www.launchdarkly.com/
                }
                
                secretsManager = container "Secrets Manager" "Secure secrets and credential management" "HashiCorp Vault" {
                    tags "Cloud Service,Configuration,Supply Chain Tracked"
                    url https://www.vaultproject.io/
                    properties {
                        "arch.ref" "smartparking.arch.container.secrets-manager"
                        "bom.enabled" "true"
                        "bom.ref" "smartparking.bom.secrets-manager"
                        "runtime.unit" "cloud-secrets-manager"
                        "sbom.scope" "security-service"
                        "cbom.scope" "key-and-secret-management"
                        "vex.scope" "secret-management-runtime"
                        "asset.criticality" "high"
                        "deployment.zone" "cloud"
                    }
                }
                
                pluginFramework = container "Plugin Framework" "Extensible plugin architecture and runtime" "Plugin SDK" {
                    tags "Cloud Service,Platform"
                    url https://github.com/your-repo/plugin-framework
                }
                
                pluginRegistry = container "Plugin Registry" "Plugin discovery, validation, and lifecycle management" "Plugin Registry" {
                    tags "Cloud Service,Platform"
                    url https://github.com/your-repo/plugin-registry
                }
                
                extensionAPI = container "Extension API" "Third-party integration and extension APIs" "REST/GraphQL" {
                    tags "Cloud Service,Platform"
                    url https://github.com/your-repo/extension-api
                }
                
                
                aiPipelineAPI = container "AI Pipeline API" "Extensible AI analytics and processing API" "Python/FastAPI" {
                    tags "Cloud Service,Platform"
                    url https://github.com/your-repo/ai-pipeline-api
                }
                
                dataSinkManager = container "Data Sink Manager" "Pluggable data streaming and external integrations" "Kafka Connect" {
                    tags "Cloud Service,Platform"
                    url https://kafka.apache.org/documentation/#connect
                }
                
                dataLake = container "Data Lake" "Centralized storage for all parking data with standardized schemas" "Apache Iceberg/S3" {
                    tags "Cloud Service,Data Storage"
                    url https://iceberg.apache.org/
                }
                
                
                dashboard = container "Management Dashboard" "Web interface for monitoring/configuration" "React" {
                    tags "Cloud Service,Frontend"
                    url https://github.com/your-repo/dashboard
                }
                
                mobileApi = container "Mobile API" "Versioned REST APIs for mobile app with OpenAPI documentation" "Python/FastAPI" {
                    tags "Cloud Service,API"
                    url https://github.com/your-repo/mobile-api
                }
                
                metadataDb = container "Metadata Database" "Stores plates, rules, users, events" "PostgreSQL" {
                    tags "Cloud Service,Database"
                    url https://www.postgresql.org/
                }
                
                videoStorage = container "Video Storage" "Stores video evidence" "S3/NAS" {
                    tags "Cloud Service,Storage"
                    url https://aws.amazon.com/s3/
                }
            }

            policeDb = softwareSystem "Police Database" "External plate verification system" {
                tags "external,Internet Zone"
                url https://example.com/police-db
            }
            
            paymentGateway = softwareSystem "Payment Gateway" "Handles payment processing" {
                tags "external,Internet Zone"
                url https://example.com/payment-gateway
            }
            
            erpSystem = softwareSystem "ERP System" "Enterprise resource planning integration" {
                tags "external,Internet Zone"
                url https://example.com/erp-system
            }
            
            # Data-first, contract-led relationships with standardized schemas
            driver -> system.apiGateway "Uses mobile app via versioned APIs" "HTTPS"
            admin -> system.apiGateway "Manages system via versioned APIs" "HTTPS"
            
            # API Gateway routes to microservices
            system.apiGateway -> system.mobileApi "Routes mobile requests to v1 API" "HTTPS"
            system.apiGateway -> system.dashboard "Routes admin requests to v1 API" "HTTPS"
            system.apiGateway -> system.anprService "Routes ANPR requests to v2 API" "HTTPS"
            system.apiGateway -> system.accessControl "Routes access control to v1 API" "HTTPS"
            system.apiGateway -> system.parkingMgmt "Routes parking requests to v1 API" "HTTPS"
            system.apiGateway -> system.paymentService "Routes payment requests to v2 API" "HTTPS"
            
            # Schema Registry - All services register and validate schemas
            system.schemaRegistry -> system.gateway "Provides standardized event schemas" "HTTPS"
            system.schemaRegistry -> system.anprService "Validates 'license_plate_read' schema" "HTTPS"
            system.schemaRegistry -> system.accessControl "Validates 'gate_control' schema" "HTTPS"
            system.schemaRegistry -> system.parkingMgmt "Validates 'space_occupancy' schema" "HTTPS"
            system.schemaRegistry -> system.paymentService "Validates 'payment_event' schema" "HTTPS"
            system.schemaRegistry -> system.aiAnalytics "Provides ML feature schemas" "HTTPS"
            
            # Ontology Service - Formal entity definitions
            system.ontologyService -> system.anprService "Provides Vehicle entity definitions" "HTTPS"
            system.ontologyService -> system.parkingMgmt "Provides Space entity definitions" "HTTPS"
            system.ontologyService -> system.accessControl "Provides Gate entity definitions" "HTTPS"
            system.ontologyService -> system.paymentService "Provides Permit entity definitions" "HTTPS"
            
            # Event-driven communication with schema validation
            system.gateway -> system.eventBus "Publishes standardized 'license_plate_read' events" "Kafka"
            system.gateway -> system.eventBus "Publishes standardized 'gate_opened' events" "Kafka"
            system.gateway -> system.eventBus "Publishes standardized 'space_occupied' events" "Kafka"
            
            system.eventBus -> system.anprService "Consumes validated 'license_plate_read' events" "Kafka"
            system.eventBus -> system.accessControl "Consumes validated 'gate_control' events" "Kafka"
            system.eventBus -> system.parkingMgmt "Consumes validated 'space_status' events" "Kafka"
            system.eventBus -> system.paymentService "Consumes validated 'payment_required' events" "Kafka"
            system.eventBus -> system.aiAnalytics "Consumes all events for ML training" "Kafka"
            
            # Data Fabric - Unified data access
            system.dataFabric -> system.metadataDb "Ingests operational data" "SQL"
            system.dataFabric -> system.dataLake "Stores historical data with schemas" "HTTPS"
            system.dataFabric -> system.aiAnalytics "Provides training datasets" "HTTPS"
            
            # MLOps Pipeline - Model Lifecycle Management
            system.mlopsPipeline -> system.dataLake "Reads training datasets" "HTTPS"
            system.mlopsPipeline -> system.schemaRegistry "Validates data schemas for training" "HTTPS"
            system.mlopsPipeline -> system.modelRegistry "Stores versioned model artifacts" "HTTPS"
            system.mlopsPipeline -> system.modelServing "Deploys models for A/B testing" "HTTPS"
            
            # Model Registry - Versioned Artifacts
            system.modelRegistry -> system.modelServing "Provides model versions for deployment" "HTTPS"
            system.modelRegistry -> system.edgeAI "Distributes models to edge devices" "HTTPS"
            system.modelRegistry -> system.anprService "Provides ANPR model versions" "HTTPS"
            
            # Model Serving - A/B Testing & Canary Releases
            system.modelServing -> system.anprService "Routes inference requests (A/B testing)" "HTTPS"
            system.modelServing -> system.gateway "Deploys models to edge cameras (canary)" "HTTPS"
            system.modelServing -> system.modelMonitoring "Sends inference logs for monitoring" "HTTPS"
            
            # Model Monitoring - Drift Detection
            system.modelMonitoring -> system.dataLake "Analyzes data drift patterns" "HTTPS"
            system.modelMonitoring -> system.mlopsPipeline "Triggers retraining on drift detection" "HTTPS"
            system.modelMonitoring -> system.modelServing "Monitors model performance metrics" "HTTPS"
            
            # Edge-to-Cloud Continuum - Strategic Workload Partitioning
            
            # Edge Layer - Autonomous, Low-latency Operations
            system.edgeOrchestrator -> system.edgeAI "Manages AI runtime containers" "K3s"
            system.edgeOrchestrator -> system.gateway "Orchestrates gateway services" "K3s"
            system.edgeOrchestrator -> system.anprService "Manages ANPR service containers" "K3s"
            system.edgeOrchestrator -> system.edgeStorage "Manages local storage" "K3s"
            
            system.edgeAI -> system.modelRegistry "Pulls latest model versions (when connected)" "HTTPS"
            system.edgeAI -> system.gateway "Provides real-time ANPR inference" "MQTT"
            system.edgeAI -> system.edgeStorage "Caches models locally for autonomy" "Local"
            
            system.gateway -> system.edgeStorage "Stores events locally during outages" "Local"
            system.anprService -> system.edgeStorage "Caches video clips locally" "Local"
            
            # Fog Layer - Aggregation and Analytics
            system.fogGateway -> system.edgeOrchestrator "Aggregates data from edge devices" "HTTPS"
            system.fogGateway -> system.dataFabric "Processes aggregated data" "HTTPS"
            system.fogGateway -> system.aiAnalytics "Provides edge analytics" "HTTPS"
            
            # OTA Updates - Over-the-air Management
            system.otaManager -> system.edgeOrchestrator "Deploys software updates" "HTTPS"
            system.otaManager -> system.modelRegistry "Pushes model updates" "HTTPS"
            system.otaManager -> system.edgeAI "Updates AI models on edge" "HTTPS"
            
            # Zero-Trust Security Model - Identity for Everything
            
            # Identity Provider - Centralized Identity Management
            system.identityProvider -> system.anprService "Provides OAuth2 client credentials" "mTLS"
            system.identityProvider -> system.accessControl "Provides OAuth2 client credentials" "mTLS"
            system.identityProvider -> system.parkingMgmt "Provides OAuth2 client credentials" "mTLS"
            system.identityProvider -> system.paymentService "Provides OAuth2 client credentials" "mTLS"
            system.identityProvider -> system.gateway "Provides OAuth2 client credentials" "mTLS"
            system.identityProvider -> system.edgeAI "Provides OAuth2 client credentials" "mTLS"
            system.identityProvider -> driver "Provides user authentication" "HTTPS"
            system.identityProvider -> admin "Provides admin authentication" "HTTPS"
            
            # Certificate Authority - Device Identity Management
            system.certificateAuthority -> system.gateway "Issues X.509 certificates for cameras" "mTLS"
            system.certificateAuthority -> system.anprService "Issues X.509 certificates for edge devices" "mTLS"
            system.certificateAuthority -> system.edgeAI "Issues X.509 certificates for AI devices" "mTLS"
            system.certificateAuthority -> system.edgeOrchestrator "Issues X.509 certificates for K3s nodes" "mTLS"
            
            # Policy Engine - Least Privilege Access Control
            system.policyEngine -> system.anprService "Enforces ANPR-only permissions" "mTLS"
            system.policyEngine -> system.accessControl "Enforces gate control permissions" "mTLS"
            system.policyEngine -> system.paymentService "Enforces payment-only permissions" "mTLS"
            system.policyEngine -> system.parkingMgmt "Enforces space management permissions" "mTLS"
            system.policyEngine -> system.gateway "Enforces protocol translation permissions" "mTLS"
            
            # Security Gateway - Zero-Trust Protocol Translation
            system.securityGateway -> system.gateway "Validates all protocol translations" "mTLS"
            system.securityGateway -> system.anprService "Secures ANPR service communications" "mTLS"
            system.securityGateway -> system.accessControl "Secures access control communications" "mTLS"
            
            # Encryption Service - Encryption Everywhere
            system.encryptionService -> system.metadataDb "Encrypts database at rest" "mTLS"
            system.encryptionService -> system.dataLake "Encrypts data lake at rest" "mTLS"
            system.encryptionService -> system.videoStorage "Encrypts video storage at rest" "mTLS"
            system.encryptionService -> system.edgeStorage "Provides encryption keys for edge storage" "mTLS"
            
            # Security Monitoring - Threat Detection
            system.securityMonitoring -> system.gateway "Monitors gateway security events" "mTLS"
            system.securityMonitoring -> system.anprService "Monitors ANPR service security events" "mTLS"
            system.securityMonitoring -> system.accessControl "Monitors access control security events" "mTLS"
            system.securityMonitoring -> system.paymentService "Monitors payment service security events" "mTLS"
            system.securityMonitoring -> system.identityProvider "Monitors authentication events" "mTLS"
            system.securityMonitoring -> system.policyEngine "Monitors authorization events" "mTLS"
            
            # Observability Stack - Unified Monitoring Platform
            
            # Metrics Collection - Performance Tracking
            system.metricsCollector -> system.anprService "Collects ANPR accuracy % and latency metrics" "HTTPS"
            system.metricsCollector -> system.apiGateway "Collects API latency and throughput metrics" "HTTPS"
            system.metricsCollector -> system.eventBus "Collects queue depth and processing metrics" "HTTPS"
            system.metricsCollector -> system.parkingMgmt "Collects occupancy rates and space utilization" "HTTPS"
            system.metricsCollector -> system.gateway "Collects protocol translation metrics" "HTTPS"
            system.metricsCollector -> system.edgeAI "Collects edge inference metrics" "HTTPS"
            
            # AI-Specific Metrics - Model Performance
            system.aiMetricsCollector -> system.edgeAI "Collects model latency and inference counts" "HTTPS"
            system.aiMetricsCollector -> system.modelServing "Collects A/B testing performance metrics" "HTTPS"
            system.aiMetricsCollector -> system.modelMonitoring "Collects confidence score distributions" "HTTPS"
            system.aiMetricsCollector -> system.anprService "Collects ANPR model accuracy metrics" "HTTPS"
            system.aiMetricsCollector -> system.mlopsPipeline "Collects training and validation metrics" "HTTPS"
            
            # Log Aggregation - Centralized Logging
            system.logAggregator -> system.anprService "Aggregates ANPR service logs" "HTTPS"
            system.logAggregator -> system.accessControl "Aggregates access control audit trails" "HTTPS"
            system.logAggregator -> system.paymentService "Aggregates payment processing logs" "HTTPS"
            system.logAggregator -> system.gateway "Aggregates gateway protocol logs" "HTTPS"
            system.logAggregator -> system.identityProvider "Aggregates authentication logs" "HTTPS"
            system.logAggregator -> system.policyEngine "Aggregates authorization decision logs" "HTTPS"
            system.logAggregator -> system.edgeOrchestrator "Aggregates K3s orchestration logs" "HTTPS"
            
            # Distributed Tracing - Request Flow Tracking
            system.tracingPlatform -> system.apiGateway "Traces API request flows" "HTTPS"
            system.tracingPlatform -> system.anprService "Traces ANPR processing flows" "HTTPS"
            system.tracingPlatform -> system.accessControl "Traces gate control flows" "HTTPS"
            system.tracingPlatform -> system.paymentService "Traces payment processing flows" "HTTPS"
            system.tracingPlatform -> system.parkingMgmt "Traces space management flows" "HTTPS"
            system.tracingPlatform -> system.gateway "Traces protocol translation flows" "HTTPS"
            system.tracingPlatform -> system.eventBus "Traces event processing flows" "HTTPS"
            
            # Observability Dashboard - Unified Interface
            system.observabilityDashboard -> system.metricsCollector "Displays performance metrics" "HTTPS"
            system.observabilityDashboard -> system.logAggregator "Displays log analysis" "HTTPS"
            system.observabilityDashboard -> system.tracingPlatform "Displays request traces" "HTTPS"
            system.observabilityDashboard -> system.aiMetricsCollector "Displays AI/ML metrics" "HTTPS"
            system.observabilityDashboard -> system.alertingSystem "Manages alerting rules" "HTTPS"
            
            # Alerting System - Proactive Notifications
            system.alertingSystem -> system.metricsCollector "Monitors performance thresholds" "HTTPS"
            system.alertingSystem -> system.aiMetricsCollector "Monitors AI model performance" "HTTPS"
            system.alertingSystem -> system.logAggregator "Monitors error patterns" "HTTPS"
            system.alertingSystem -> system.tracingPlatform "Monitors latency anomalies" "HTTPS"
            system.alertingSystem -> admin "Sends critical alerts" "Email/SMS"
            system.alertingSystem -> system.securityMonitoring "Integrates security alerts" "HTTPS"
            
            # Configuration as Code - Infrastructure and Dynamic Configuration
            
            # Infrastructure as Code - Reproducible Deployments
            system.infrastructureAsCode -> system.edgeOrchestrator "Provisions K3s edge clusters" "Terraform"
            system.infrastructureAsCode -> system.fogGateway "Provisions fog computing infrastructure" "Terraform"
            system.infrastructureAsCode -> system.apiGateway "Provisions cloud infrastructure" "Terraform"
            system.infrastructureAsCode -> system.mlopsPipeline "Provisions ML infrastructure" "Terraform"
            system.infrastructureAsCode -> system.observabilityDashboard "Provisions monitoring infrastructure" "Terraform"
            system.infrastructureAsCode -> system.securityMonitoring "Provisions security infrastructure" "Terraform"
            
            # Configuration Manager - Dynamic Configuration
            system.configurationManager -> system.anprService "Provides dynamic configuration" "HTTPS"
            system.configurationManager -> system.accessControl "Provides dynamic configuration" "HTTPS"
            system.configurationManager -> system.parkingMgmt "Provides dynamic configuration" "HTTPS"
            system.configurationManager -> system.paymentService "Provides dynamic configuration" "HTTPS"
            system.configurationManager -> system.gateway "Provides dynamic configuration" "HTTPS"
            system.configurationManager -> system.edgeAI "Provides dynamic configuration" "HTTPS"
            system.configurationManager -> system.apiGateway "Provides API endpoint configuration" "HTTPS"
            
            # Feature Flag Service - Dynamic Feature Toggles
            system.featureFlagService -> system.anprService "Controls ANPR feature toggles" "HTTPS"
            system.featureFlagService -> system.accessControl "Controls access control features" "HTTPS"
            system.featureFlagService -> system.paymentService "Controls payment features" "HTTPS"
            system.featureFlagService -> system.dashboard "Controls UI feature flags" "HTTPS"
            system.featureFlagService -> system.mobileApi "Controls mobile app features" "HTTPS"
            system.featureFlagService -> system.modelServing "Controls A/B testing features" "HTTPS"
            
            # Secrets Manager - Secure Configuration
            system.secretsManager -> system.anprService "Provides encrypted secrets" "mTLS"
            system.secretsManager -> system.accessControl "Provides encrypted secrets" "mTLS"
            system.secretsManager -> system.paymentService "Provides encrypted secrets" "mTLS"
            system.secretsManager -> system.gateway "Provides encrypted secrets" "mTLS"
            system.secretsManager -> system.edgeAI "Provides encrypted secrets" "mTLS"
            system.secretsManager -> system.identityProvider "Provides authentication secrets" "mTLS"
            system.secretsManager -> system.certificateAuthority "Provides certificate secrets" "mTLS"
            
            # Environment Manager - Multi-tenant Deployment
            system.environmentManager -> system.infrastructureAsCode "Manages tenant-specific infrastructure" "HTTPS"
            system.environmentManager -> system.configurationManager "Manages tenant-specific configuration" "HTTPS"
            system.environmentManager -> system.featureFlagService "Manages tenant-specific feature flags" "HTTPS"
            system.environmentManager -> system.secretsManager "Manages tenant-specific secrets" "HTTPS"
            
            # Deployment Pipeline - Automated CI/CD
            system.deploymentPipeline -> system.infrastructureAsCode "Triggers infrastructure deployments" "HTTPS"
            system.deploymentPipeline -> system.environmentManager "Deploys to multiple environments" "HTTPS"
            system.deploymentPipeline -> system.otaManager "Deploys edge updates" "HTTPS"
            system.deploymentPipeline -> system.mlopsPipeline "Deploys ML models" "HTTPS"
            system.deploymentPipeline -> system.configurationManager "Updates configuration" "HTTPS"
            system.deploymentPipeline -> system.featureFlagService "Updates feature flags" "HTTPS"
            
            # Plugin Architecture - Extensibility Points for Third-Party Innovation
            
            # Plugin Framework - Core Extensibility Platform
            system.pluginFramework -> system.gateway "Provides plugin runtime for protocol adapters" "HTTPS"
            system.pluginFramework -> system.aiPipelineAPI "Provides plugin runtime for AI extensions" "HTTPS"
            system.pluginFramework -> system.dataSinkManager "Provides plugin runtime for data sinks" "HTTPS"
            system.pluginFramework -> system.extensionAPI "Provides plugin SDK for third-party developers" "HTTPS"
            
            # Plugin Registry - Plugin Lifecycle Management
            system.pluginRegistry -> system.pluginFramework "Manages plugin discovery and validation" "HTTPS"
            system.pluginRegistry -> system.protocolAdapterManager "Registers protocol adapter plugins" "HTTPS"
            system.pluginRegistry -> system.aiPipelineAPI "Registers AI pipeline plugins" "HTTPS"
            system.pluginRegistry -> system.dataSinkManager "Registers data sink plugins" "HTTPS"
            system.pluginRegistry -> system.extensionAPI "Manages third-party plugin registrations" "HTTPS"
            
            # Protocol Adapter Manager - Pluggable Protocol Translation
            system.protocolAdapterManager -> system.gateway "Loads protocol adapter plugins" "HTTPS"
            system.protocolAdapterManager -> system.pluginRegistry "Discovers available protocol adapters" "HTTPS"
            system.protocolAdapterManager -> system.schemaRegistry "Validates adapter schemas" "HTTPS"
            system.protocolAdapterManager -> system.securityGateway "Validates adapter security" "HTTPS"
            
            # Gateway Service - Extensible Protocol Translation
            system.gateway -> system.protocolAdapterManager "Uses pluggable protocol adapters" "HTTPS"
            system.gateway -> system.pluginFramework "Executes protocol adapter plugins" "HTTPS"
            system.gateway -> system.eventBus "Publishes events from all protocol adapters" "Kafka"
            
            # AI Pipeline API - Extensible AI Analytics
            system.aiPipelineAPI -> system.pluginFramework "Executes AI pipeline plugins" "HTTPS"
            system.aiPipelineAPI -> system.eventBus "Consumes video streams for analysis" "Kafka"
            system.aiPipelineAPI -> system.modelRegistry "Uses AI models for analysis" "HTTPS"
            system.aiPipelineAPI -> system.dataLake "Stores AI analysis results" "HTTPS"
            system.aiPipelineAPI -> system.anprService "Integrates with existing ANPR" "HTTPS"
            
            # Data Sink Manager - Pluggable External Integrations
            system.dataSinkManager -> system.eventBus "Streams all parking events to external systems" "Kafka"
            system.dataSinkManager -> system.dataLake "Streams data to external data warehouses" "HTTPS"
            system.dataSinkManager -> system.pluginFramework "Executes data sink plugins" "HTTPS"
            system.dataSinkManager -> system.schemaRegistry "Validates data sink schemas" "HTTPS"
            
            # Extension API - Third-Party Integration Platform
            system.extensionAPI -> system.pluginRegistry "Provides plugin management APIs" "HTTPS"
            system.extensionAPI -> system.apiGateway "Integrates with main API gateway" "HTTPS"
            system.extensionAPI -> system.identityProvider "Manages third-party authentication" "HTTPS"
            system.extensionAPI -> system.policyEngine "Enforces third-party access policies" "HTTPS"
            system.extensionAPI -> system.configurationManager "Manages third-party configuration" "HTTPS"
            
            # Autonomous Edge Operation (Network Outage Scenarios)
            system.edgeStorage -> system.gateway "Provides local data during outages" "Local"
            system.edgeStorage -> system.anprService "Enables offline operation" "Local"
            system.edgeAI -> system.edgeStorage "Uses cached models when disconnected" "Local"
            
            # AI/ML Services consume standardized data
            system.aiAnalytics -> system.dataLake "Reads training data with consistent schemas" "HTTPS"
            system.aiAnalytics -> system.ontologyService "Uses entity definitions for feature engineering" "HTTPS"
            system.aiAnalytics -> system.modelRegistry "Stores trained model artifacts" "HTTPS"
            
            # Direct service-to-service (when synchronous needed)
            system.anprService -> system.videoStorage "Stores/retrieves video clips" "RTSP"
            system.accessControl -> system.metadataDb "Checks permissions and rules" "SQL"
            system.paymentService -> system.metadataDb "Updates payment records" "SQL"
            system.parkingMgmt -> system.metadataDb "Updates occupancy data" "SQL"
            
            # External system integration via API Gateway
            system.apiGateway -> policeDb "Verifies stolen plates via v1 API" "HTTPS"
            system.apiGateway -> paymentGateway "Processes payments via v2 API" "HTTPS"
            system.apiGateway -> erpSystem "Shares business data via v1 API" "HTTPS"
            
            # Threat Modeling - Attack Vectors and Security Relationships
            
            # External Attack Vectors
            externalAttacker -> system.apiGateway "API exploitation attempts" "HTTPS" {
                tags "Attack Vector,High Risk"
            }
            externalAttacker -> system.gateway "Protocol manipulation" "MQTT" {
                tags "Attack Vector,High Risk"
            }
            scriptKiddie -> system.anprService "Service compromise attempts" "HTTPS" {
                tags "Attack Vector,Medium Risk"
            }
            nationState -> system.edgeAI "Model poisoning attacks" "HTTPS" {
                tags "Attack Vector,High Risk,Advanced"
            }
            
            # Internal Attack Vectors
            maliciousInsider -> system.identityProvider "Privilege escalation attempts" "HTTPS" {
                tags "Attack Vector,High Risk,Insider"
            }
            maliciousInsider -> system.secretsManager "Secret exfiltration attempts" "mTLS" {
                tags "Attack Vector,High Risk,Insider"
            }
            maliciousInsider -> system.dataLake "Data exfiltration attempts" "HTTPS" {
                tags "Attack Vector,High Risk,Insider"
            }
            
            # Sensitive Data Flows
            driver -> system.apiGateway "Personal information transmission" "HTTPS" {
                tags "PII,Cardholder,High Risk"
            }
            system.paymentService -> paymentGateway "Payment data transmission" "HTTPS" {
                tags "Cardholder,Secrets,High Risk"
            }
            system.anprService -> system.dataLake "License plate data storage" "HTTPS" {
                tags "PII,High Risk"
            }
            system.identityProvider -> system.secretsManager "Credential management" "mTLS" {
                tags "Secrets,High Risk"
            }
            
            # Deployment model - Edge-to-Cloud Continuum with Strategic Partitioning
        deploymentEnvironment "Production" {
                # Edge Layer - Autonomous, Low-latency Operations with Zero-Trust Security
                deploymentNode "Edge Cluster" "On-premises K3s cluster with security" "K3s" {
                    containerInstance system.edgeOrchestrator
                    containerInstance system.anprService
                    containerInstance system.gateway
                    containerInstance system.edgeAI
                    containerInstance system.edgeStorage
                    containerInstance system.securityGateway
                    containerInstance system.protocolAdapterManager
                    
                    deploymentNode "Camera Network" "IP Cameras with Edge AI" "ONVIF" {
                        infrastructureNode "Entrance Camera" "License plate capture with real-time inference"
                        infrastructureNode "Exit Camera" "License plate capture with real-time inference"
                        infrastructureNode "Parking Area Cameras" "Occupancy detection with AI"
                    }
                    
                    deploymentNode "Gate Controller" "Industrial controller" "Modbus" {
                        infrastructureNode "Entry Gate" "Vehicle access control"
                        infrastructureNode "Exit Gate" "Vehicle access control"
                    }
                }
                
                # Fog Layer - Aggregation and Analytics
                deploymentNode "Fog Cluster" "Regional aggregation" "Kubernetes" {
                    containerInstance system.fogGateway
                }
            
            deploymentNode "Cloud Provider" "AWS/Azure" "Cloud" {
                    deploymentNode "API Gateway Server" "API Management" "Kong/AWS API Gateway" {
                        containerInstance system.apiGateway
                    }
                    
                    deploymentNode "Data Management Server" "Schema Registry & Ontology" "Docker" {
                        containerInstance system.schemaRegistry
                        containerInstance system.ontologyService
                        containerInstance system.dataFabric
                    }
                    
                    deploymentNode "Event Bus Server" "Message Broker" "Apache Kafka" {
                        containerInstance system.eventBus
                    }
                    
                    deploymentNode "Microservices Server" "Cloud compute" "Docker" {
                        containerInstance system.accessControl
                        containerInstance system.parkingMgmt
                        containerInstance system.paymentService
                        containerInstance system.mobileApi
                    }
                    
                    deploymentNode "MLOps Server" "Machine Learning Operations" "Kubernetes" {
                        containerInstance system.mlopsPipeline
                        containerInstance system.modelRegistry
                        containerInstance system.modelServing
                        containerInstance system.modelMonitoring
                        containerInstance system.aiAnalytics
                    }
                    
                    deploymentNode "OTA Management Server" "Over-the-air Updates" "Docker" {
                        containerInstance system.otaManager
                    }
                    
                    deploymentNode "Security Server" "Zero-Trust Security Infrastructure" "Kubernetes" {
                        containerInstance system.identityProvider
                        containerInstance system.certificateAuthority
                        containerInstance system.policyEngine
                        containerInstance system.securityMonitoring
                        containerInstance system.encryptionService
                    }
                    
                    deploymentNode "Observability Server" "Unified Monitoring Platform" "Kubernetes" {
                        containerInstance system.metricsCollector
                        containerInstance system.logAggregator
                        containerInstance system.tracingPlatform
                        containerInstance system.observabilityDashboard
                        containerInstance system.aiMetricsCollector
                        containerInstance system.alertingSystem
                    }
                    
                    deploymentNode "Configuration Server" "Infrastructure as Code and Dynamic Configuration" "Kubernetes" {
                        containerInstance system.infrastructureAsCode
                        containerInstance system.configurationManager
                        containerInstance system.deploymentPipeline
                        containerInstance system.environmentManager
                        containerInstance system.featureFlagService
                        containerInstance system.secretsManager
                    }
                    
                    deploymentNode "Platform Server" "Plugin Architecture and Extension Platform" "Kubernetes" {
                        containerInstance system.pluginFramework
                        containerInstance system.pluginRegistry
                        containerInstance system.extensionAPI
                        containerInstance system.aiPipelineAPI
                        containerInstance system.dataSinkManager
                    }
                
                deploymentNode "Database Server" "Managed DB" "PostgreSQL" {
                        containerInstance system.metadataDb
                    }
                    
                    deploymentNode "Data Lake Server" "Data Storage" "Apache Iceberg/S3" {
                        containerInstance system.dataLake
                }
                
                deploymentNode "Storage Server" "Object storage" "S3" {
                        containerInstance system.videoStorage
                }
                
                deploymentNode "Web Server" "Frontend hosting" "Docker" {
                        containerInstance system.dashboard
                    }
                }
            }
        }
    }

    views {
        # System Context Diagram
        systemContext system "SystemContext" {
            include *
            autolayout lr
            title "System Context Diagram - Smart Parking System"
        }
        
        # Container Diagram
        container system "Containers" {
            include *
            autolayout tb
            title "Container Diagram - Smart Parking System"
        }
        
        # Component Diagram (Gateway Service)
        component system.gateway "GatewayComponents" {
            include *
            autolayout lr
            title "Component Diagram - Gateway Service"
        }
        
        # Security Views - Threat Modeling
        
        # System Context with Threat Actors
        systemContext system "SecurityContext" {
            include *
            autolayout lr
            title "System Context with Threat Actors"
        }
        
        # Container View with Trust Boundaries
        container system "SecurityContainers" {
            include *
            autolayout tb
            title "Container Diagram with Trust Boundaries and Risk Levels"
        }
        
        # Security Attack Paths Views
        
        # External Attack Paths
        dynamic system "ExternalAttackPaths" {
            externalAttacker -> system.apiGateway "Attempts API exploitation" "HTTPS"
            externalAttacker -> system.gateway "Attempts protocol manipulation" "MQTT"
            scriptKiddie -> system.anprService "Attempts service compromise" "HTTPS"
            nationState -> system.edgeAI "Attempts model poisoning" "HTTPS"
            autolayout lr
            title "External Attack Paths and Vectors"
        }
        
        # Internal Attack Paths
        dynamic system "InternalAttackPaths" {
            maliciousInsider -> system.identityProvider "Attempts privilege escalation" "HTTPS"
            maliciousInsider -> system.secretsManager "Attempts secret exfiltration" "mTLS"
            maliciousInsider -> system.dataLake "Attempts data exfiltration" "HTTPS"
            autolayout lr
            title "Internal Attack Paths and Insider Threats"
        }
        
        # Attack Vector Analysis
        dynamic system "AttackVectorAnalysis" {
            externalAttacker -> system.apiGateway "API exploitation" "HTTPS"
            externalAttacker -> system.gateway "Protocol manipulation" "MQTT"
            scriptKiddie -> system.anprService "Service compromise" "HTTPS"
            nationState -> system.edgeAI "Model poisoning" "HTTPS"
            maliciousInsider -> system.identityProvider "Privilege escalation" "HTTPS"
            maliciousInsider -> system.secretsManager "Secret exfiltration" "mTLS"
            autolayout lr
            title "Comprehensive Attack Vector Analysis"
        }
        
        # Deployment Diagram
        deployment system "Production" "ProductionDeployment" {
            include *
            autolayout lr
            title "Deployment Diagram - Production"
        }
        
        # Styles - Data-first, contract-led architecture
        styles {
            element "Person" {
                shape Person
                background #08427b
                color #ffffff
            }
            element "Software System" {
                background #1168bd
                color #ffffff
            }
            element "Container" {
                background #4390d6
                color #ffffff
            }
            element "Component" {
                background #6baae3
                color #000000
            }
            element "External" {
                background #999999
                color #000000
                shape WebBrowser
            }
            element "Microservice" {
                shape Hexagon
                background #2e7d32
                color #ffffff
            }
            element "API Management" {
                shape RoundedBox
                background #7b1fa2
                color #ffffff
            }
            element "Data Management" {
                shape RoundedBox
                background #9c27b0
                color #ffffff
            }
            element "AI/ML" {
                shape RoundedBox
                background #e91e63
                color #ffffff
            }
            element "MLOps" {
                shape RoundedBox
                background #ff5722
                color #ffffff
            }
            element "Orchestration" {
                shape RoundedBox
                background #4caf50
                color #ffffff
            }
            element "Fog Service" {
                shape RoundedBox
                background #2196f3
                color #ffffff
            }
            element "Deployment" {
                shape RoundedBox
                background #795548
                color #ffffff
            }
            element "Security" {
                shape RoundedBox
                background #d32f2f
                color #ffffff
            }
            element "Observability" {
                shape RoundedBox
                background #673ab7
                color #ffffff
            }
            element "Configuration" {
                shape RoundedBox
                background #607d8b
                color #ffffff
            }
            element "Platform" {
                shape RoundedBox
                background #3f51b5
                color #ffffff
            }
            element "Threat Actor" {
                shape Person
                background #d32f2f
                color #ffffff
            }
            element "High Risk" {
                background #ff5722
                color #ffffff
                shape RoundedBox
            }
            element "Medium Risk" {
                background #ff9800
                color #ffffff
                shape RoundedBox
            }
            element "Low Risk" {
                background #4caf50
                color #ffffff
                shape RoundedBox
            }
            element "Internet Zone" {
                background #ffebee
                color #c62828
                shape RoundedBox
            }
            element "Edge Zone" {
                background #fff3e0
                color #ef6c00
                shape RoundedBox
            }
            element "Fog Zone" {
                background #f3e5f5
                color #7b1fa2
                shape RoundedBox
            }
            element "Cloud Zone" {
                background #e8f5e8
                color #2e7d32
                shape RoundedBox
            }
            element "Event-Driven" {
                shape RoundedBox
                background #ff6f00
                color #ffffff
            }
            element "Edge Service" {
                background #73c974
            }
            element "Cloud Service" {
                background #f9a03c
            }
            element "Frontend" {
                background #1976d2
                color #ffffff
            }
            element "Database" {
                background #5d4037
                color #ffffff
                shape Cylinder
            }
            element "Data Storage" {
                background #37474f
                color #ffffff
                shape Cylinder
            }
            element "Storage" {
                background #424242
                color #ffffff
                shape Cylinder
            }
            relationship "Relationship" {
                thickness 2
                color #707070
                fontSize 20
            }
        }
        
        theme default
    }
    
}
