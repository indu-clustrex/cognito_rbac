import json
import boto3
import http.client
import jwt
import psycopg2

COGNITO_REGION = 'us-east-2'
USER_POOL_ID = 'us-east-2_xxxxxxxx'
APP_CLIENT_ID = 'xxxxxxxxxxxxxxxxxxxxxxxxx'

client = boto3.client('cognito-idp', region_name=COGNITO_REGION)

def get_secret(secret_name):
    region_name = "us-east-2"
    # Create a Secrets Manager client
    session = boto3.session.Session()
    client = session.client(
        service_name='secretsmanager',
        region_name=region_name
    )
    get_secret_value_response = client.get_secret_value(
            SecretId=secret_name
        )
    return json.loads(get_secret_value_response['SecretString'])


def get_conn():
    config = get_secret(f"crm/dev/dbcreds")['creds']
    try:
        return psycopg2.connect(config)
    except Exception as e:
        raise e

def get_jwks():
    """Retrieve the JWKS from Cognito."""
    conn = http.client.HTTPSConnection(f'cognito-idp.{COGNITO_REGION}.amazonaws.com')
    conn.request('GET', f'/{USER_POOL_ID}/.well-known/jwks.json')
    
    response = conn.getresponse()
    if response.status != 200:
        raise Exception(f'Failed to retrieve JWKS: {response.status} {response.reason}')
    
    jwks = response.read()
    conn.close()
    return json.loads(jwks)

def get_key(token):
    """Get the public key from Cognito JWKS"""
    jwks = get_jwks()
    kid = jwt.get_unverified_header(token)['kid']
    for key in jwks['keys']:
        if key['kid'] == kid:
            return key
    return None

def verify_token(token):
    """Verify the JWT token"""
    try:
        # Retrieve the public key for verifying the JWT
        public_key_data = get_key(token)
        if not public_key_data:
            raise Exception('Public key not found in JWKS')

        # Construct the public key in PEM format
        public_key = jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(public_key_data))

        # Decode and verify the token
        decoded = jwt.decode(
            token,
            key=public_key,  # Use the RSA public key
            algorithms=['RS256'],
            audience=APP_CLIENT_ID
        )
        print("decoded", decoded)
        return decoded
    except jwt.ExpiredSignatureError:
        raise Exception('Token has expired')
    except jwt.InvalidTokenError as e:
        raise Exception(f'Invalid token: {str(e)}')
        
        
def build_allow_all_policy(event, affect):
    tmp = event['methodArn'].split(':')
    api_gateway_arn_tmp = tmp[5].split('/')
    aws_account_id = tmp[4]
    aws_region = tmp[3]
    rest_api_id = api_gateway_arn_tmp[0]
    stage = api_gateway_arn_tmp[1]
    
    api_arn = f'arn:aws:execute-api:{aws_region}:{aws_account_id}:{rest_api_id}/{stage}/*/*'
    
    policy = {
        'principalId': 'done',
        'policyDocument': {
            'Version': '2012-10-17',
            'Statement': [
                {
                    'Effect': affect,
                    'Action': 'execute-api:Invoke',
                    'Resource': api_arn
                }
            ]
        }
    }
    return policy
    

def get_user_data_from_token(token, access_token):
    client = boto3.client('cognito-idp', region_name=COGNITO_REGION)
    userInfo = client.get_user(AccessToken=access_token)
    for item in userInfo['UserAttributes']:
        for key, value in item.items():
            print(key, value)
            if value == "email":
                return item['Value']
    
    
def verify_role(action_id, token, email_id, stage='dev'):
    try:
        conn = get_conn()
        cursor = conn.cursor()
        action_ids = (int(action_id),)
        # email_id = get_user_data_from_token(token, access_token)
        if ',' in action_id:
            action_ids = tuple(map(int, action_id.split(',')))
        print(email_id)
        print(action_ids)
        
        query = f"""
            SELECT r.id AS role_id, r.name AS role_name, u.id AS user_id, u.name AS user_name, 
                   p.action_id AS action_id, a2.name AS action_name
            FROM rbac_{stage}.user u
            JOIN rbac_{stage}.user_role_mapping urm ON u.id = urm.user_id
            JOIN rbac_{stage}.role r ON r.id = urm.role_id
            JOIN rbac_{stage}.permission p ON p.role_id = r.id
            JOIN rbac_{stage}.action a2 ON a2.id = p.action_id
            JOIN rbac_{stage}.application a ON a.id = r.application_id
            WHERE u.email = %s AND p.action_id IN %s AND a.id = '2';
        """
        
        cursor.execute(query, (email_id, action_ids))
        data = cursor.fetchall()
        return bool(data)
    
    except Exception as e:
        print(f"Database query failed: {e}")
        return False



def lambda_handler(event, context):
    try:
        token = event['headers']['Authorization']
        
        if not token:
            build_allow_all_policy(event, 'Deny')

        decoded_token = verify_token(token)
        # Authentication
        if(decoded_token):
            # Authorization
            action_id = event['headers']['action_id']
            if(verify_role(action_id, token, decoded_token['email'])):
                return build_allow_all_policy(event, 'Allow')
            else:
                return build_allow_all_policy(event, 'Deny')
            
    except Exception as e:
        print("error", e)
        return build_allow_all_policy(event, 'Deny')
