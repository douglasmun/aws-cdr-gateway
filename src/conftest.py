"""
pytest configuration for the CDR test suite.

Sets dummy AWS credentials and region before any test module is imported, so
the module-level boto3 clients in lambda_function.py can be
constructed offline. Without these, botocore falls through to the login
credential provider and aborts collection with MissingDependencyException
(botocore[crt]). setdefault is used so real CI/AWS values are never overridden.
"""

import os

os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")
os.environ.setdefault("AWS_ACCESS_KEY_ID", "testing")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "testing")
os.environ.setdefault("AWS_SESSION_TOKEN", "testing")
os.environ.setdefault("AWS_EC2_METADATA_DISABLED", "true")
