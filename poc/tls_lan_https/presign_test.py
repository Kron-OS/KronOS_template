import boto3
from botocore.config import Config

# Mirrors src/adapter/storage/s3.py's _presign_client construction exactly:
# a client built against the PUBLIC endpoint, used only to sign URLs.
presign_client = boto3.client(
    "s3",
    endpoint_url="https://kronos.local:9444",
    aws_access_key_id="kronos_minio",
    aws_secret_access_key="kronos_minio_dev_password",
    config=Config(signature_version="s3v4"),
    verify="/tmp/kronos-tls-poc/root_ca.crt",
)

bucket = "kronos-poc-tls-test"
key = "tls-lan-https-poc-object.txt"

# Bucket must exist for the PUT to succeed -- create it via the INTERNAL
# endpoint (this script runs with --network host, so it can also reach the
# internal Docker network's published minio:9000 mapping... actually minio
# isn't reachable as "minio" from host network, use the host-published
# internal-equivalent port instead, which is also 9000, plain HTTP).
admin_client = boto3.client(
    "s3",
    endpoint_url="http://kronos.local:9000",
    aws_access_key_id="kronos_minio",
    aws_secret_access_key="kronos_minio_dev_password",
    config=Config(signature_version="s3v4"),
)
try:
    admin_client.create_bucket(Bucket=bucket)
    print(f"bucket {bucket} created")
except Exception as e:
    print(f"bucket create: {e}")

url = presign_client.generate_presigned_url(
    "put_object",
    Params={"Bucket": bucket, "Key": key},
    ExpiresIn=300,
)
print("PRESIGNED_URL:", url)
