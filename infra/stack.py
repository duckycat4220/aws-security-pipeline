"""
CDK Stack — AWS Security Intelligence Pipeline.

Defines the full pipeline infrastructure:
  - SQS (main queue + DLQ with redrive policy)
  - IAM roles with least-privilege per service
  - Secrets Manager for external credentials
  - Bedrock access (referential, ready for activation)
"""

from aws_cdk import (
    Duration,
    RemovalPolicy,
    Stack,
    Tags,
    aws_iam as iam,
    aws_secretsmanager as secretsmanager,
    aws_sqs as sqs,
    CfnOutput,
)
from constructs import Construct


class SecurityIntelligencePipelineStack(Stack):
    def __init__(
        self,
        scope: Construct,
        construct_id: str,
        env_name: str = "development",
        **kwargs,
    ) -> None:
        super().__init__(scope, construct_id, **kwargs)

        Tags.of(self).add("Project", "aws-security-intelligence-pipeline")
        Tags.of(self).add("Environment", env_name)

        # ----------------------------------------------------------------------
        # SQS: Dead-Letter Queue
        # ----------------------------------------------------------------------
        dlq = sqs.Queue(
            self,
            "SecurityEventsDLQ",
            queue_name=f"security-events-dlq-{env_name}",
            retention_period=Duration.days(14),
            removal_policy=RemovalPolicy.DESTROY if env_name == "development" else RemovalPolicy.RETAIN,
        )

        # ----------------------------------------------------------------------
        # SQS: Main queue with redrive policy
        # ----------------------------------------------------------------------
        main_queue = sqs.Queue(
            self,
            "SecurityEventsQueue",
            queue_name=f"security-events-queue-{env_name}",
            visibility_timeout=Duration.seconds(30),
            retention_period=Duration.days(14),
            dead_letter_queue=sqs.DeadLetterQueue(
                max_receive_count=3,
                queue=dlq,
            ),
        )

        # ----------------------------------------------------------------------
        # IAM: API service role (send-only access to SQS)
        # ----------------------------------------------------------------------
        api_role = iam.Role(
            self,
            "ApiServiceRole",
            role_name=f"sip-api-role-{env_name}",
            assumed_by=iam.ServicePrincipal("ecs-tasks.amazonaws.com"),
            description="API service role — send-only access to SQS",
        )
        main_queue.grant_send_messages(api_role)

        # ----------------------------------------------------------------------
        # IAM: Worker role (consumes SQS + invokes Bedrock)
        # ----------------------------------------------------------------------
        worker_role = iam.Role(
            self,
            "WorkerServiceRole",
            role_name=f"sip-worker-role-{env_name}",
            assumed_by=iam.ServicePrincipal("ecs-tasks.amazonaws.com"),
            description="Worker role — consumes SQS, invokes Bedrock, reads secrets",
        )
        main_queue.grant_consume_messages(worker_role)

        # Bedrock: referential access — ready for when the real LLM is activated.
        # Restricted to a specific model to prevent unexpected costs.
        worker_role.add_to_policy(
            iam.PolicyStatement(
                sid="BedrockInvokeModel",
                effect=iam.Effect.ALLOW,
                actions=["bedrock:InvokeModel"],
                resources=[
                    f"arn:aws:bedrock:{self.region}::foundation-model/anthropic.claude-haiku-4-5-20251001",
                ],
            )
        )

        # ----------------------------------------------------------------------
        # Secrets Manager: Callback URL and API keys
        # ----------------------------------------------------------------------
        # In production, the callback URL points to the real SIEM and may contain
        # authentication tokens. Secrets Manager enables automatic rotation
        # and avoids hardcoded credentials in .env or environment variables.
        callback_secret = secretsmanager.Secret(
            self,
            "CallbackConfig",
            secret_name=f"sip/callback-config/{env_name}",
            description="Callback URL and credentials for the target SIEM",
            generate_secret_string=secretsmanager.SecretStringGenerator(
                secret_string_template='{"callback_url": "https://your-siem.example.com/api/ingest", "api_key": ""}',
                generate_string_key="api_key",
                exclude_punctuation=True,
                password_length=32,
            ),
            removal_policy=RemovalPolicy.DESTROY if env_name == "development" else RemovalPolicy.RETAIN,
        )
        callback_secret.grant_read(worker_role)

        # Bedrock config — referential for when external API keys
        # or additional model configuration are needed.
        bedrock_secret = secretsmanager.Secret(
            self,
            "BedrockConfig",
            secret_name=f"sip/bedrock-config/{env_name}",
            description="Bedrock LLM configuration (model, parameters, limits)",
            generate_secret_string=secretsmanager.SecretStringGenerator(
                secret_string_template='{"model_id": "anthropic.claude-haiku-4-5-20251001", "max_tokens": 200, "temperature": 0.2}',
                generate_string_key="reserved",
                exclude_punctuation=True,
                password_length=16,
            ),
            removal_policy=RemovalPolicy.DESTROY if env_name == "development" else RemovalPolicy.RETAIN,
        )
        bedrock_secret.grant_read(worker_role)

        # ----------------------------------------------------------------------
        # Outputs
        # ----------------------------------------------------------------------
        CfnOutput(self, "QueueUrl", value=main_queue.queue_url)
        CfnOutput(self, "QueueArn", value=main_queue.queue_arn)
        CfnOutput(self, "DLQUrl", value=dlq.queue_url)
        CfnOutput(self, "DLQArn", value=dlq.queue_arn)
        CfnOutput(self, "ApiRoleArn", value=api_role.role_arn)
        CfnOutput(self, "WorkerRoleArn", value=worker_role.role_arn)
        CfnOutput(self, "CallbackSecretArn", value=callback_secret.secret_arn)
        CfnOutput(self, "BedrockSecretArn", value=bedrock_secret.secret_arn)
