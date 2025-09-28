#!/usr/bin/env python3
import sys
import os
import boto3
import requests
from datetime import datetime, timezone, date
import logging
from base64 import b64decode, b64encode

# For encrypting GitHub secrets
try:
    from nacl import encoding, public
except ImportError:
    print("PyNaCl is required. Install with: pip install pynacl")
    sys.exit(1)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

GITHUB_API = "https://api.github.com"

def get_public_key(owner: str, repo: str, token: str):
    """Fetch the repository public key used to encrypt secrets."""
    
    url = f"{GITHUB_API}/repos/{owner}/{repo}/actions/secrets/public-key"
    
    headers = {
        'Authorization': f'token {token}',
        'Accept': 'application/vnd.github+json',
        'X-GitHub-Api-Version': '2022-11-28',
        'Content-Type': 'application/json'
    }

    r = requests.get(url, headers=headers)
    if r.status_code != 200:
        raise RuntimeError(f"Failed to fetch repo public key: {r.status_code} - {r.text}")
    data = r.json()
    return data["key"], data["key_id"]

def encrypt_secret(public_key_b64: str, secret_value: str) -> str:
    """Encrypt a secret using the repo's public key (libsodium sealed box)."""
    
    public_key = public.PublicKey(public_key_b64.encode("utf-8"), encoding.Base64Encoder())
    sealed_box = public.SealedBox(public_key)
    encrypted = sealed_box.encrypt(secret_value.encode("utf-8"))
    return b64encode(encrypted).decode("utf-8")

def put_repo_secret(owner: str, repo: str, token: str, name: str, plaintext_value: str):
    """Create or update a repository secret."""
    key, key_id = get_public_key(owner, repo, token)
    encrypted_value = encrypt_secret(key, plaintext_value)

    url = f"{GITHUB_API}/repos/{owner}/{repo}/actions/secrets/{name}"
    headers = {"Authorization": f"token {token}", "Accept": "application/vnd.github+json"}
    payload = {"encrypted_value": encrypted_value, "key_id": key_id}

    r = requests.put(url, headers=headers, json=payload)
    if r.status_code not in (201, 204):
        raise RuntimeError(f"Failed to set secret {name}: {r.status_code} - {r.text}")
    logger.info(f"Secret {name} set/updated successfully at repo {owner}/{repo}")

def rotateawskey(aws_username: str, github_token: str, github_repo_fullname: str, rotation_days: int = 60):
    """
    Rotates AWS access keys for the given IAM user if the oldest key is older than rotation_days.
    Uses SELF-ROTATION: the user's current credentials to rotate their own keys.
    
    Updates GitHub repository secrets with the new keys:
      - AWS_ACCESS_KEY_ID
      - AWS_SECRET_ACCESS_KEY
    """
    logger.info("Starting AWS access key self-rotation for IAM user: %s", aws_username)

    # Parse owner/repo
    if "/" not in github_repo_fullname:
        raise ValueError("github_repo_fullname must be in the form 'owner/repo'")
    owner, repo = github_repo_fullname.split("/", 1)

    # Verify we can determine which AWS account we're working with
    try:
        sts = boto3.client("sts")
        account_info = sts.get_caller_identity()
        logger.info("Operating in AWS Account: %s", account_info["Account"])
        logger.info("Using credentials for: %s", account_info.get("Arn", "Unknown"))
    except Exception as e:
        logger.warning("Could not verify AWS account info: %s", e)

    client = boto3.client("iam")

    try:
        # Get current keys for the user
        res = client.list_access_keys(UserName=aws_username)
        metadata = res.get("AccessKeyMetadata", [])
        if not metadata:
            logger.info("No access keys found for user %s; nothing to rotate.", aws_username)
            return

        # Sort keys by CreateDate ascending (oldest first)
        metadata_sorted = sorted(metadata, key=lambda k: k["CreateDate"])
        
        oldest = metadata_sorted[0]
        oldest_created = oldest["CreateDate"].date()
        oldest_id = oldest["AccessKeyId"]
        
        # Get the current key being used by this script
        current_key_id = os.environ.get("AWS_ACCESS_KEY_ID")
        if current_key_id:
            logger.info("Script is currently using access key: %s", current_key_id)

        today = date.today()
        key_age_days = (today - oldest_created).days
        logger.info("Oldest key %s is %d days old (created %s).",
                    oldest_id, key_age_days, oldest_created.isoformat())

        if key_age_days <= rotation_days:
            logger.info("Key age (%d) <= rotation threshold (%d). No rotation needed.",
                        key_age_days, rotation_days)
            return

        logger.info("Key older than %d days. Proceeding with self-rotation.", rotation_days)

        # SELF-ROTATION SAFETY: If we have 2 keys, we need to be careful about which one to delete
        if len(metadata_sorted) == 2:
            # Always delete the oldest key (not necessarily the one we're using)
            logger.info("Two keys present. Will delete oldest key: %s after creating new one", oldest_id)
        
        # Create a new key FIRST (before deleting anything)
        logger.info("Creating new access key for user: %s", aws_username)
        create_resp = client.create_access_key(UserName=aws_username)
        new_access_key_id = create_resp["AccessKey"]["AccessKeyId"]
        new_secret_key = create_resp["AccessKey"]["SecretAccessKey"]
        logger.info("Created new access key: %s", new_access_key_id)

        # Update GitHub repo secrets with NEW credentials
        logger.info("Updating GitHub secrets with new credentials...")
        put_repo_secret(owner, repo, github_token, "AWS_ACCESS_KEY_ID", new_access_key_id)
        put_repo_secret(owner, repo, github_token, "AWS_SECRET_ACCESS_KEY", new_secret_key)
        logger.info("GitHub secrets updated successfully")

        # Now it's safe to delete the old key
        # Delete the oldest key to free up space (AWS allows max 2 keys per user)
        if len(metadata_sorted) == 2:
            logger.info("Deleting oldest key: %s", oldest_id)
            client.delete_access_key(UserName=aws_username, AccessKeyId=oldest_id)
            logger.info("Old key deleted: %s", oldest_id)

        logger.info("Self-rotation complete! Next workflow run will use the new credentials.")
        logger.info("Old key: %s -> New key: %s", oldest_id, new_access_key_id)

    except client.exceptions.NoSuchEntityException:
        logger.error("The IAM user %s does not exist.", aws_username)
        sys.exit(1)
    except client.exceptions.LimitExceededException as e:
        logger.error("AWS limit exceeded (likely too many access keys): %s", e)
        sys.exit(1)
    except client.exceptions.ClientError as e:
        logger.error("AWS ClientError: %s", e)
        sys.exit(1)
    except Exception as e:
        logger.error("Unexpected error during self-rotation: %s", e)
        raise

if __name__ == "__main__":
    if len(sys.argv) < 4:
        print("Usage: python rotate_aws_keys_github.py <aws_username> <github_token> <owner/repo> [rotation_days]")
        print("Example: python rotate_aws_keys_github.py terraform ghp_abc123 myorg/myrepo 60")
        sys.exit(1)

    aws_username = sys.argv[1]
    github_token = sys.argv[2]
    repo_full = sys.argv[3]
    rotation_days = int(sys.argv[4]) if len(sys.argv) > 4 else 60

    rotateawskey(aws_username, github_token, repo_full, rotation_days)
