import json
import boto3
import os

smr = boto3.client("sagemaker-runtime")

def lambda_handler(event, context):
    body = event.get("body") or "{}"
    if isinstance(body, str):
        payload = body.encode("utf-8")
    else:
        payload = json.dumps(body).encode("utf-8")

    resp = smr.invoke_endpoint(
        EndpointName=os.environ["ENDPOINT_NAME"],
        ContentType="application/json",
        Body=payload,
    )
    out = resp["Body"].read().decode("utf-8")
    return {"statusCode": 200, "headers": {"content-type": "application/json"}, "body": out}