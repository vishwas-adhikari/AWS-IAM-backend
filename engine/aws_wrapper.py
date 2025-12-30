import boto3
from botocore.exceptions import ClientError

def get_iam_client(access_key, secret_key):
    """Creates a Boto3 IAM client using provided credentials."""
    return boto3.client(
        'iam',
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        region_name='us-east-1' # IAM is global, but boto3 needs a region
    )

def fetch_account_data(access_key, secret_key):
    """
    Orchestrates the data collection:
    1. Verifies Identity (GetCallerIdentity)
    2. Downloads IAM snapshot (GetAccountAuthorizationDetails)
    3. Fetches Password Policy (Safe Mode)
    """
    try:
        # 1. Verification & Account ID
        sts = boto3.client(
            'sts',
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key
        )
        caller_id = sts.get_caller_identity()
        account_id = caller_id['Account']
        arn = caller_id['Arn']

        # 2. Main IAM Dump (Users, Roles, Policies)
        iam = get_iam_client(access_key, secret_key)
        
        print(f"Scanning Account: {account_id}...")
        auth_details = iam.get_account_authorization_details(
            Filter=['User', 'Role', 'LocalManagedPolicy']
        )

        # 3. Get Password Policy (Safely)
        # We initialize it as empty first so the variable always exists
        password_policy = {} 
        try:
            # Try to fetch the real policy
            response = iam.get_account_password_policy()
            password_policy = response.get('PasswordPolicy', {})
        except ClientError:
            # If no policy exists, AWS throws an error. We catch it and move on.
            print("No password policy found (or permission denied). Using default.")
            pass

        # 4. Return everything
        return {
            "account_id": account_id,
            "account_arn": arn,
            "users": auth_details.get('UserDetailList', []),
            "roles": auth_details.get('RoleDetailList', []),
            "policies": auth_details.get('Policies', []),
            "password_policy": password_policy 
        }

    except ClientError as e:
        print(f"AWS Error: {e}")
        raise Exception(f"Failed to connect to AWS: {str(e)}")
    except Exception as e:
        print(f"General Error: {e}")
        raise Exception(f"Scan failed: {str(e)}")