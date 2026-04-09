# ADR-004: Layered Asynchronous Messaging with Kafka and MQTT

**Date:** 2025-08-10  
**Status:** Accepted  
**Deciders:** Architecture Team  
**Technical Story:** Smart Parking System Event-Driven Communication  

## Context

The Smart Parking System requires asynchronous communication between services for:

- **Real-time Events**: License plate detections, gate operations, sensor readings
- **IoT Device Communication**: Cameras, sensors, gate controllers, payment terminals
- **Service Integration**: Loose coupling between microservices
- **Scalability**: Handle high-volume event streams from multiple parking facilities
- **Reliability**: Ensure message delivery even during network issues
- **Edge-to-Cloud**: Reliable communication between edge devices and cloud services

The architecture model shows two different asynchronous communication needs:

- **Platform and service eventing**: durable, replayable, schema-governed communication between cloud and platform services
- **Edge and device-adjacent messaging**: lightweight, low-overhead messaging close to cameras, gateways, and field integration points

The system therefore needs a layered messaging approach rather than a single protocol for all asynchronous communication.

## Decision

We will use a layered asynchronous messaging approach:

### Primary Event Backbone: Apache Kafka
- **Purpose**: service-to-service and platform eventing
- **Usage**: standardized business and operational events across the Smart Parking platform
- **Strengths**:
  - durable event streaming
  - replayability
  - schema-governed integration
  - strong support for analytics, data pipelines, and downstream consumers

### Edge Messaging: MQTT
- **Purpose**: lightweight edge and device-adjacent messaging
- **Usage**: low-overhead messaging around edge inference and gateway/device integration
- **Strengths**:
  - lightweight pub/sub
  - suitable for constrained and device-facing environments
  - useful close to the edge where low overhead matters

### Supporting Controls
- **Schema Registry**: schema validation for standardized event payloads
- **Gateway Controls**: security validation, translation, and filtering at the protocol boundary
- **Message Formats**: standardized event payloads and contract-led data exchange

### Architecture Alignment

This ADR aligns to the modeled architecture where:

- `Event Bus` is implemented as **Apache Kafka**
- the gateway contains an **MQTT Publisher** component
- MQTT is visible in edge-related relationships
- Kafka is the main event backbone for platform services

## Consequences

### Positive

- **Better fit to the actual architecture**: Kafka and MQTT are used where they are strongest
- **Durable platform eventing**: Kafka supports replayable event processing and downstream analytics
- **Edge efficiency**: MQTT remains available for lightweight edge-side communication
- **Cleaner separation of concerns**: device-adjacent traffic is distinguished from enterprise/platform events
- **Improved alignment with the DSL**: the ADR now reflects the modeled event architecture accurately

### Negative

- **Higher operational complexity**: two messaging patterns must be understood and operated
- **Integration complexity**: edge messaging and platform eventing need clear boundaries
- **Security complexity**: two messaging layers require different hardening strategies
- **Developer clarity required**: teams must know when to use Kafka versus MQTT

### Risks

- **Protocol misuse**: teams may use MQTT for platform events that belong on Kafka
- **Boundary confusion**: unclear separation between edge transport and platform eventing
- **Operational drift**: documentation may diverge if the protocol split is not enforced consistently

## Alternatives Considered

### Apache Kafka
- **Adopted as the primary event backbone**
- **Reason**: this best matches the modeled event bus and platform integration design

### RabbitMQ
- **Rejected**: Too heavyweight for IoT devices
- **Reason**: does not improve the current Kafka plus MQTT split for this architecture

### gRPC
- **Rejected**: Synchronous communication, not suitable for event-driven architecture
- **Reason**: Need asynchronous, fire-and-forget communication

### WebSockets
- **Rejected**: Not suitable for IoT devices and lacks message persistence
- **Reason**: does not provide the same fit for edge/device pub/sub

## Implementation Strategy

### Platform Eventing
- **Cloud**: Apache Kafka cluster for service and platform events
- **Schema Registry**: Confluent Schema Registry for event validation
- **Consumers**: ANPR, access control, parking, payment, analytics, and downstream data services

### Edge Messaging
- **Gateway Components**: MQTT-based publishing where lightweight edge messaging is appropriate
- **Edge Scope**: localized or device-adjacent message exchange
- **Security**: authentication, encryption, and validation at gateway boundaries

### Message Design
- **Schema-First**: Define Avro schemas for all message types
- **Versioning**: Use schema evolution for backward compatibility
- **Validation**: Validate all messages against schemas
- **Serialization**: Use Avro for efficient serialization

### Protocol Placement Rule

- Use **Kafka** for platform-wide asynchronous communication, replayable event streams, analytics ingestion, and service integration.
- Use **MQTT** for lightweight edge and device-facing messaging where the modeled architecture explicitly calls for it.

## Monitoring and Observability

### Metrics
- **Message Rate**: Messages per second by topic
- **Latency**: End-to-end message processing time
- **Error Rate**: Failed message deliveries
- **Queue Depth**: Number of pending messages

### Alerts
- **High Latency**: Message processing time > 1 second
- **High Error Rate**: > 1% message delivery failures
- **Queue Backlog**: > 1000 pending messages
- **Broker Down**: Message broker unavailable

## Related ADRs

- ADR-001: Microservices Architecture
- ADR-002: Hybrid Edge/Cloud Architecture
- ADR-005: Data-First Architecture with Schema Registry
- ADR-007: Observability Stack
