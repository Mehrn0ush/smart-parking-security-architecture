# DSL Security Views

This diagram is derived from the actual Structurizr model in [`workspace.dsl`](../model/workspace.dsl), especially:

- threat actors and containers at lines 15-301
- attack-path relationships at lines 617-642
- deployment at lines 659-770
- views at lines 775-850

```mermaid
flowchart LR
    EA["External Attacker"]
    SK["Script Kiddie"]
    MI["Malicious Insider"]
    NS["Nation State Actor"]

    subgraph Internet["Internet Zone"]
        APIGW["API Gateway"]
        EXT["External Systems"]
    end

    subgraph Edge["Edge Zone"]
        GW["Gateway Service"]
        ANPR["ANPR Service"]
        EAI["Edge AI Runtime"]
        SG["Security Gateway"]
        ES["Edge Storage"]
        CAM["Camera Network"]
        GATE["Gate Controller"]
    end

    subgraph Cloud["Cloud Zone"]
        IDP["Identity Provider"]
        CA["Certificate Authority"]
        OPA["Policy Engine"]
        SECMON["Security Monitoring"]
        SECRETS["Secrets Manager"]
        DATALAKE["Data Lake"]
        MLOPS["MLOps Pipeline"]
        REG["Model Registry"]
        SERVE["Model Serving"]
    end

    EA -->|HTTPS| APIGW
    EA -->|MQTT| GW
    SK -->|HTTPS| ANPR
    NS -->|HTTPS| EAI
    MI -->|HTTPS| IDP
    MI -->|mTLS| SECRETS
    MI -->|HTTPS| DATALAKE

    CA --> GW
    CA --> ANPR
    CA --> EAI
    OPA --> GW
    OPA --> ANPR
    SG --> GW
    SECMON --> GW
    SECMON --> ANPR
    SECMON --> IDP

    EAI --> GW
    GW --> GATE
    CAM --> ANPR
    ES --> GW
    MLOPS --> REG
    REG --> EAI
    REG --> ANPR
    SERVE --> ANPR
```

## Reading Notes

- The DSL’s highest-risk attack path is the one touching `Gateway Service` at the edge.
- The DSL’s clearest AI-specific threat path is `Nation State Actor -> Edge AI Runtime`.
- The DSL’s strongest insider-threat focus is identity, secrets, and data-lake compromise.
