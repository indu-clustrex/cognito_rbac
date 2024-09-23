# Design the Authentication layer with AWS Cognito and Authorization layer with RBAC module

### Authentication vs. Authorization
Authentication : Authentication verifies a user's identity <br/> 
Authorization: Authorization determines the user's level of access and grants access based on that level <br/>

### AWS Cognito
AWS Cognito is a service provided by Amazon Web Services (AWS) that handles user authentication, authorization, and user management for web and mobile applications. It enables developers to add sign-up, sign-in, and access control to their applications quickly and securely.

### Key Benefits of AWS Cognito:
- User Authentication
- User Management
- Scalability
- Security
- Customization
- Social and Enterprise Identity Federation
- Seamless Integration
## Main Components:
- User pool
- Identity pool

### Cognito User pool
An Amazon Cognito user pool is a user directory. With a user pool, your users can sign in to your web or mobile app through Amazon Cognito, or federate through a third-party IdP. Federated and local users have a user profile in your user pool.

![Cognito User pool](https://github.com/indu-clustrex/cognito_rbac/blob/main/Screenshot%202024-09-01%20172413.png)

### Cognito User pool with Authentication
![Cognito User pool with Authentication](https://github.com/indu-clustrex/cognito_rbac/blob/main/Screenshot%202024-09-01%20185807.png)


### Cognito Authentication:
1. **Create a Cognito User Pool:**
  - Go to AWS Cognito and create a new User Pool.
  - Configure attributes such as email or phone number for user identity.
  - Set up password policies, MFA (if required), and verification settings.
2. **Create an App Client:**
  - Create an App Client within the User Pool to generate the "App Client ID."
  - Decide whether to enable or disable the client secret (disable in the case of SPA/web apps for security).
  - Configure OAuth 2.0 flows (such as implicit or authorization code flows) if required.
3. **Add Identity Providers (Optional):**
  - Integrate with external identity providers (like Google, Facebook, etc.) for federated identity.
4. **Configure Sign-in/Sign-up Mechanism:**
  - Use the Cognito Hosted UI or integrate the Cognito SDK into your frontend for sign-up and sign-in flows.
  - Once the user signs in, Cognito issues a JSON Web Token (JWT) that includes access, ID, and refresh tokens.
5. **Retrieve the Cognito Tokens:**
  - After successful authentication, the user receives an ID token, access token, and refresh token.
  - These tokens will be used to access protected APIs.

### Role Based Access Control
<div style="display: flex; align-items: center;">
  <div style="width: 50%;">
    <p>RBAC is a method for controlling user access to systems based on user roles and permissions.</p>
    <p>It allows us to improve our security posture, comply with relevant regulations, and reduce operational overhead.</p>
  </div>
  <div style="width: 50%;">
    <img src="https://github.com/indu-clustrex/cognito_rbac/blob/main/Screenshot%202024-09-01%20194146.png" alt="RBAC image" style="max-width:100%;">
  </div>
</div>


### Authorization Layer with RBAC Module
To implement an authorization layer using Role-Based Access Control (RBAC), we need to:

  1. Create the necessary database tables to manage users, roles, and permissions.
  2. Create a custom Lambda authorizer that checks the user's roles and permissions before granting access to API resources.

![RABA image2](https://github.com/indu-clustrex/cognito_rbac/blob/main/unnamed%20(1).png)

### Database Design for RBAC
1. **users:** Stores user details.
2. **roles:** Defines the roles in the system (e.g., Admin, Viewer, User).
3. **user_role_mapping:** Map the user and role
4. **actions:** Defines the actions(Read, Write, Download)
5. **Permissions:** Defines the permissions granted to each role for accessing resources.

### API Gateway Integration with Cognito
1. **Create an API**: Define API endpoints such as `/data`, `/data1`, `/login`.
2. **Create Cognito Authorizer**: In API Gateway, configure an authorizer linked to your Cognito User Pool.
3. **Enable Cognito Authorization on Endpoints**: Use Cognito to protect `/data`
4. **Enable Custom Authorization on Endpoints**: Use Cognito to protect `/data1`

### API Gateway Structure:
```bash
/
  /data     # Protected with Cognito
    GET
    OPTIONS
  /data1    # Protected with Custom Auth
    GET
    OPTIONS
  /login    # Unprotected
    POST
    OPTIONS
```

**Login.py** (/login)
```python
import json
import boto3

def lambda_handler(event, context):
    payload = json.loads(event['body'])
    client = boto3.client('cognito-idp', region_name='us-east-2')
    client_id = 'xxxxxxxxxxxxxxxx'
    response = client.initiate_auth(ClientId=client_id, AuthFlow='USER_PASSWORD_AUTH', AuthParameters={'USERNAME': payload['email'], 'PASSWORD': payload['password']})
    return {
        'statusCode': 200,
        'body': json.dumps(response)
    }
```

**test.py(/data)** and **test1.py(/data1)**
```python
import json

def lambda_handler(event, context):
    # TODO implement
    return {
        'statusCode': 200,
        'body': json.dumps('Hello from Lambda!')
    }

```

**Custom_auth.py**
```python
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

```