import json
import boto3

def lambda_handler(event, context):
    payload = json.loads(event['body'])
    client = boto3.client('cognito-idp', region_name='us-east-2')
    client_id = '18s91fqh3mqajqqa4duodkrgf4'
    response = client.initiate_auth(ClientId=client_id, AuthFlow='USER_PASSWORD_AUTH', AuthParameters={'USERNAME': payload['email'], 'PASSWORD': payload['password']})
    return {
        'statusCode': 200,
        'body': json.dumps(response)
    }

