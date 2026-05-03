import boto3


def _dynamodb_table(region: str, table_name: str):
    return boto3.resource("dynamodb", region_name=region).Table(table_name)


def _s3_client(region: str):
    return boto3.client("s3", region_name=region)


def store_public_key(email: str, public_pem: str, issued_at: str, region: str, table_name: str) -> None:
    table = _dynamodb_table(region, table_name)
    table.put_item(Item={
        "email": email,
        "public_key": public_pem,
        "issued_at": issued_at,
    })


def fetch_public_key(email: str, region: str, table_name: str) -> str | None:
    table = _dynamodb_table(region, table_name)
    resp = table.get_item(Key={"email": email})
    item = resp.get("Item")
    return item["public_key"] if item else None


def upload_to_s3(file_path: str, s3_key: str, bucket: str, region: str) -> str:
    s3 = _s3_client(region)
    s3.upload_file(file_path, bucket, s3_key)
    return f"s3://{bucket}/{s3_key}"
