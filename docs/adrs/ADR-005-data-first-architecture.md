# ADR-005: Data-First Architecture with Schema Registry

**Date:** 2025-08-10  
**Status:** Accepted  
**Deciders:** Architecture Team  
**Technical Story:** Smart Parking System Data Management Strategy  

## Context

The Smart Parking System generates and processes large volumes of diverse data:

- **Real-time Data**: License plate detections, sensor readings, gate operations
- **Historical Data**: Parking transactions, occupancy patterns, user behavior
- **External Data**: Police database lookups, payment processing, ERP integration
- **Analytics Data**: ML model inputs, performance metrics, business intelligence
- **Configuration Data**: Device settings, business rules, user permissions

The system needs to:
- Ensure data consistency across all services
- Support data evolution and schema changes
- Enable real-time analytics and reporting
- Provide data lineage and governance
- Support multiple data formats and protocols
- Enable third-party integrations

## Decision

We will implement a data-first architecture with the following components:

### Schema Registry
- **Technology**: Confluent Schema Registry
- **Purpose**: Centralized schema management and validation
- **Features**: Schema evolution, compatibility checking, versioning
- **Formats**: Avro for binary serialization, JSON Schema for validation

### Data Fabric
- **Technology**: Apache Kafka Connect + DataHub
- **Purpose**: Unified data management and standardized access
- **Features**: Data lineage, metadata management, data discovery
- **Integration**: Connects to all data sources and sinks

### Ontology Service
- **Technology**: Python/FastAPI with RDF/OWL
- **Purpose**: Formal definitions of parking entities and relationships
- **Entities**: Spaces, Vehicles, Gates, Permits, Users, Transactions
- **Relationships**: Hierarchical and semantic relationships

### Data Lake
- **Technology**: Apache Iceberg on S3
- **Purpose**: Centralized storage for all parking data
- **Features**: ACID transactions, schema evolution, time travel
- **Partitioning**: By facility, date, and data type

## Consequences

### Positive

- **Data Consistency**: Centralized schemas ensure consistent data across services
- **Schema Evolution**: Backward and forward compatibility for schema changes
- **Data Discovery**: Easy discovery and understanding of available data
- **Data Lineage**: Clear tracking of data flow and transformations
- **Interoperability**: Standardized data formats enable easy integration
- **Governance**: Centralized data governance and compliance
- **Analytics**: Rich metadata enables advanced analytics and reporting
- **Third-party Integration**: Standardized schemas enable easy external integration

### Negative

- **Complexity**: Additional infrastructure and operational overhead
- **Performance**: Schema validation adds latency to data processing
- **Dependency**: Services depend on schema registry availability
- **Learning Curve**: Team needs to learn schema management concepts
- **Migration**: Existing data needs to be migrated to new schemas
- **Versioning**: Complex schema versioning and compatibility management

### Risks

- **Schema Registry Failure**: Single point of failure for data validation
- **Schema Drift**: Risk of schema inconsistencies across services
- **Performance Impact**: Schema validation may impact real-time processing
- **Data Migration**: Complex migration of existing data to new schemas

## Alternatives Considered

### No Schema Management
- **Rejected**: Would lead to data inconsistencies and integration issues
- **Reason**: Need centralized schema management for data quality

### Database-First Approach
- **Rejected**: Would not support real-time streaming and analytics
- **Reason**: Need event-driven architecture with schema validation

### API-First Approach
- **Partially Adopted**: For service APIs
- **Reason**: Data-first approach provides better data governance

## Implementation Strategy

### Schema Design
- **Avro Schemas**: For Kafka message serialization
- **JSON Schemas**: For API request/response validation
- **RDF/OWL**: For ontology definitions
- **Versioning**: Semantic versioning for schema evolution

### Data Flow
1. **Ingestion**: Data enters through standardized schemas
2. **Validation**: Schema Registry validates all incoming data
3. **Processing**: Services process validated data
4. **Storage**: Data stored in Data Lake with metadata
5. **Analytics**: Data available for analytics and reporting

### Schema Evolution
- **Backward Compatibility**: New schemas must be backward compatible
- **Forward Compatibility**: Old consumers must handle new data
- **Migration**: Gradual migration of services to new schemas
- **Testing**: Comprehensive testing of schema changes

## Schema Examples

### License Plate Detection Event
```json
{
  "type": "record",
  "name": "LicensePlateDetection",
  "namespace": "com.smartparking.events",
  "fields": [
    {"name": "camera_id", "type": "string"},
    {"name": "timestamp", "type": "long", "logicalType": "timestamp-millis"},
    {"name": "license_plate", "type": "string"},
    {"name": "confidence", "type": "float"},
    {"name": "bbox", "type": {"type": "array", "items": "int"}},
    {"name": "facility_id", "type": "string"}
  ]
}
```

### Parking Transaction
```json
{
  "type": "record",
  "name": "ParkingTransaction",
  "namespace": "com.smartparking.transactions",
  "fields": [
    {"name": "transaction_id", "type": "string"},
    {"name": "user_id", "type": "string"},
    {"name": "space_id", "type": "string"},
    {"name": "start_time", "type": "long", "logicalType": "timestamp-millis"},
    {"name": "end_time", "type": ["null", "long"], "logicalType": "timestamp-millis"},
    {"name": "amount", "type": "double"},
    {"name": "currency", "type": "string"},
    {"name": "status", "type": {"type": "enum", "symbols": ["active", "completed", "cancelled"]}}
  ]
}
```

## Data Governance

### Data Classification
- **Public**: Non-sensitive data (occupancy rates, facility info)
- **Internal**: Business data (transactions, user behavior)
- **Confidential**: Personal data (user info, license plates)
- **Restricted**: Payment data, security logs

### Data Retention
- **Real-time Data**: 7 days in Kafka
- **Transactional Data**: 7 years in Data Lake
- **Analytics Data**: Indefinite with archival
- **Log Data**: 1 year with compression

### Data Quality
- **Validation**: Schema validation for all incoming data
- **Monitoring**: Data quality metrics and alerts
- **Cleansing**: Automated data cleansing and normalization
- **Lineage**: Track data transformations and lineage

## Monitoring and Observability

### Metrics
- **Schema Usage**: Schema versions and usage patterns
- **Data Quality**: Validation success rates and error patterns
- **Data Volume**: Data ingestion and processing rates
- **Latency**: Schema validation and data processing latency

### Alerts
- **Schema Validation Failures**: > 1% validation failures
- **Data Quality Issues**: Data quality score < 95%
- **Schema Registry Down**: Schema registry unavailable
- **Data Lake Issues**: Data lake storage or processing issues

## Related ADRs

- ADR-001: Microservices Architecture
- ADR-004: Layered Asynchronous Messaging with Kafka and MQTT
- ADR-006: Zero-Trust Security Model
- ADR-008: AI/ML Integration Framework
