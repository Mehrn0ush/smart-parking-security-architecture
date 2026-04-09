# ADR-002: Hybrid Edge/Cloud Architecture

**Date:** 2025-08-10  
**Status:** Accepted  
**Deciders:** Architecture Team  
**Technical Story:** Smart Parking System Edge-to-Cloud Continuum  

## Context

The Smart Parking System operates across multiple environments with different requirements:

- **Edge Requirements**: 
  - Real-time processing (ANPR, gate control)
  - Low latency (<100ms for critical operations)
  - Autonomous operation during network outages
  - Limited compute resources
  - Harsh environmental conditions

- **Cloud Requirements**:
  - Data aggregation and analytics
  - Model training and MLOps
  - User management and APIs
  - Long-term storage and reporting
  - Integration with external systems

- **Fog Requirements**:
  - Regional data aggregation
  - Edge-to-cloud communication
  - Local analytics and caching

The system must balance performance, reliability, and cost while maintaining data consistency across all layers.

## Decision

We will implement a hybrid edge/cloud architecture with three distinct layers:

### Edge Layer
- **Purpose**: Real-time processing and autonomous operation
- **Technology**: K3s (lightweight Kubernetes) for container orchestration
- **Services**: ANPR Service, Gateway Service, Edge AI Runtime, Edge Storage
- **Characteristics**: 
  - Autonomous operation during network outages
  - Local data processing and caching
  - Over-the-air (OTA) updates for software and models
  - Hardware-optimized for edge constraints

### Fog Layer
- **Purpose**: Regional aggregation and edge-to-cloud communication
- **Technology**: Kubernetes clusters in regional data centers
- **Services**: Fog Gateway, Regional Analytics, Data Aggregation
- **Characteristics**:
  - Aggregates data from multiple edge locations
  - Provides regional caching and analytics
  - Handles edge-to-cloud communication
  - Manages regional failover and disaster recovery

### Cloud Layer
- **Purpose**: Centralized services, analytics, and integration
- **Technology**: Cloud-native services (AWS/Azure/GCP)
- **Services**: API Gateway, Data Lake, MLOps Pipeline, User Management
- **Characteristics**:
  - Centralized data storage and analytics
  - Model training and deployment
  - External system integration
  - Global monitoring and management

## Consequences

### Positive

- **Performance Optimization**: Critical operations run at edge for low latency
- **Autonomous Operation**: Edge can function independently during outages
- **Scalability**: Each layer can scale independently
- **Cost Efficiency**: Processing happens close to data source
- **Data Locality**: Sensitive data can be processed locally
- **Resilience**: Multiple layers provide fault tolerance
- **Flexibility**: Different technologies optimized for each layer

### Negative

- **Complexity**: Three-layer architecture increases operational complexity
- **Data Synchronization**: Challenges with data consistency across layers
- **Network Dependencies**: Edge depends on fog/cloud for some operations
- **Deployment Complexity**: Different deployment strategies for each layer
- **Monitoring Complexity**: Need observability across all layers
- **Security Challenges**: Multiple attack surfaces and trust boundaries

### Risks

- **Data Inconsistency**: Risk of data divergence between layers
- **Network Partitioning**: Edge may become isolated from cloud
- **Operational Overhead**: Managing three different environments
- **Cost Overrun**: Risk of over-provisioning resources across layers

## Alternatives Considered

### Pure Cloud Architecture
- **Rejected**: Would not meet real-time processing requirements
- **Reason**: Network latency would be too high for critical operations

### Pure Edge Architecture
- **Rejected**: Would not provide centralized management and analytics
- **Reason**: Need cloud services for data aggregation and external integration

### Two-Tier Architecture (Edge + Cloud)
- **Rejected**: Missing regional aggregation layer
- **Reason**: Fog layer provides better data aggregation and regional failover

## Implementation Strategy

### Edge Deployment
- Use K3s for lightweight container orchestration
- Implement OTA update mechanism for software and models
- Deploy edge-optimized AI models (TensorFlow Lite, ONNX)
- Implement local storage and caching

### Fog Deployment
- Use Kubernetes for container orchestration
- Implement data aggregation and caching services
- Deploy regional monitoring and management tools
- Handle edge-to-cloud communication and failover

### Cloud Deployment
- Use cloud-native services and managed Kubernetes
- Implement centralized data lake and analytics
- Deploy MLOps pipeline for model training and deployment
- Integrate with external systems and APIs

## Monitoring and Management

- **Edge**: Local monitoring with cloud reporting
- **Fog**: Regional monitoring and management
- **Cloud**: Centralized monitoring and global management
- **Cross-layer**: Unified observability platform

## Related ADRs

- ADR-001: Microservices Architecture
- ADR-003: Python/FastAPI Technology Stack
- ADR-006: Zero-Trust Security Model
- ADR-007: Observability Stack
