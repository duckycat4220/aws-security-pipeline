#!/usr/bin/env python3
"""
CDK entrypoint — instantiates the stack with per-environment configuration.

Usage:
  cdk deploy --context env=production
  cdk deploy  # default: development
"""
import aws_cdk as cdk

from infra.stack import SecurityIntelligencePipelineStack

app = cdk.App()

env_name = app.node.try_get_context("env") or "development"

SecurityIntelligencePipelineStack(
    app,
    f"SecurityIntelligencePipeline-{env_name}",
    env_name=env_name,
    env=cdk.Environment(
        region="us-east-1",
    ),
)

app.synth()
