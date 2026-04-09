# GitHub Packaging Notes

## What Should Be Published With This DSL-Centered Package

- the DSL-grounded analysis in this directory
- the original [`workspace.dsl`](../model/workspace.dsl)
- selected ADRs tied to security and AI security
- selected API contracts that support the model
- a small number of runnable examples

## What Should Not Be The Main Public Story

- local virtual environments
- generated result dumps
- repeated “summary of summary” files
- prototype outputs without clear labels

## Recommended Public Narrative

1. Start with the Structurizr model.
2. Explain threat actors and trust zones.
3. Explain why the gateway and edge AI runtime are high-risk.
4. Explain how identity, certificates, policy, encryption, and monitoring are modeled.
5. Show the production deployment and attack-path views.

## Important Caveat

This package should be presented as “analysis of the modeled architecture in `workspace.dsl`.” It should not claim that every modeled control is fully implemented in code unless that implementation is demonstrated separately.
