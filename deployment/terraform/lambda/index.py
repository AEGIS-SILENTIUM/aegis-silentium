"""
AEGIS-SILENTIUM — Lambda Relay Terminator
Automatically terminates EC2 relay instances whose DestroyAfter tag
has passed. Triggered by CloudWatch Events every hour.

This ensures relays are short-lived and automatically cleaned up
even if the operator forgets to run `terraform destroy`.
"""

import json
import logging
import os
from datetime import datetime, timezone

import boto3

log = logging.getLogger()
log.setLevel(logging.INFO)

TAG_KEY = os.environ.get("TAG_KEY", "DestroyAfter")
REGION  = os.environ.get("REGION", "us-east-1")
DRY_RUN = os.environ.get("DRY_RUN", "false").lower() == "true"

ec2 = boto3.client("ec2", region_name=REGION)


def handler(event, context):
    """
    Lambda entrypoint. Finds and terminates expired AEGIS relay instances.
    """
    log.info("AEGIS relay terminator running. DRY_RUN=%s", DRY_RUN)
    now = datetime.now(timezone.utc)

    # Find all AEGIS relay instances with a DestroyAfter tag
    paginator = ec2.get_paginator("describe_instances")
    pages = paginator.paginate(
        Filters=[
            {"Name": "tag:Project",      "Values": ["aegis-silentium"]},
            {"Name": "instance-state-name", "Values": ["running", "stopped"]},
        ]
    )

    to_terminate = []
    checked = 0

    for page in pages:
        for reservation in page["Reservations"]:
            for instance in reservation["Instances"]:
                checked += 1
                instance_id = instance["InstanceId"]
                tags = {t["Key"]: t["Value"] for t in instance.get("Tags", [])}
                destroy_after_str = tags.get(TAG_KEY)

                if not destroy_after_str:
                    log.debug("Instance %s has no %s tag — skipping", instance_id, TAG_KEY)
                    continue

                try:
                    # Parse ISO 8601 timestamp
                    destroy_after = datetime.fromisoformat(
                        destroy_after_str.replace("Z", "+00:00")
                    )
                except ValueError:
                    log.warning("Instance %s has unparseable %s: %r",
                                instance_id, TAG_KEY, destroy_after_str)
                    continue

                if now >= destroy_after:
                    relay_id = tags.get("Name", instance_id)
                    log.info(
                        "Instance %s (%s) expired at %s — marking for termination",
                        instance_id, relay_id, destroy_after_str
                    )
                    to_terminate.append({
                        "instance_id": instance_id,
                        "relay_name":  relay_id,
                        "expired_at":  destroy_after_str,
                    })
                else:
                    remaining = destroy_after - now
                    log.debug("Instance %s expires in %s", instance_id, remaining)

    log.info("Checked %d instances. Terminating %d.", checked, len(to_terminate))

    terminated = []
    errors = []

    for entry in to_terminate:
        iid = entry["instance_id"]
        try:
            if DRY_RUN:
                log.info("[DRY RUN] Would terminate %s (%s)", iid, entry["relay_name"])
            else:
                resp = ec2.terminate_instances(InstanceIds=[iid])
                state = resp["TerminatingInstances"][0]["CurrentState"]["Name"]
                log.info("Terminated %s (%s) → state: %s",
                         iid, entry["relay_name"], state)
                terminated.append(iid)
        except ec2.exceptions.ClientError as e:
            log.error("Failed to terminate %s: %s", iid, e)
            errors.append({"instance_id": iid, "error": str(e)})

    result = {
        "timestamp":     now.isoformat(),
        "checked":       checked,
        "expired_count": len(to_terminate),
        "terminated":    terminated,
        "errors":        errors,
        "dry_run":       DRY_RUN,
    }
    log.info("Result: %s", json.dumps(result))
    return result
