import os, time
import boto3

rs = boto3.client("redshift-data")
sns = boto3.client("sns")

def lambda_handler(event, context):
    stmt = rs.execute_statement(
        WorkgroupName=os.environ["WORKGROUP_NAME"],
        Database=os.environ["DATABASE"],
        SecretArn=os.environ["SECRET_ARN"],
        Sql=os.environ["SQL"],
    )
    sid = stmt["Id"]

    # wait for completion (simple polling)
    for _ in range(30):
        d = rs.describe_statement(Id=sid)
        if d["Status"] in ("FINISHED", "FAILED", "ABORTED"):
            break
        time.sleep(1)

    d = rs.describe_statement(Id=sid)
    if d["Status"] != "FINISHED":
        sns.publish(
            TopicArn=os.environ["SNS_TOPIC_ARN"],
            Subject="Redshift scheduled query failed",
            Message=f"Status={d['Status']} Error={d.get('Error')}"
        )
        raise RuntimeError(d.get("Error", "Query did not finish"))

    # you can fetch results if you want; kept minimal
    sns.publish(
        TopicArn=os.environ["SNS_TOPIC_ARN"],
        Subject="Redshift scheduled query succeeded",
        Message=f"StatementId={sid} finished successfully"
    )
    return {"ok": True, "statement_id": sid}