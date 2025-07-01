import boto3
import hashlib
import json
import os

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def lambda_handler(event, context):
    try:
        body = json.loads(event['body'])

        tenant_id = body.get('tenant_id')
        user_id = body.get('user_id')
        password = body.get('password')

        if not all([tenant_id, user_id, password]):
            return {
                'statusCode': 400,
                'body': json.dumps({'error': 'Missing tenant_id, user_id or password'})
            }

        hashed_password = hash_password(password)
        dynamodb = boto3.resource('dynamodb')
        table_name = os.environ['USERS_TABLE']
        t_usuarios = dynamodb.Table(table_name)

        # Guarda con clave compuesta tenant_id + user_id
        t_usuarios.put_item(
            Item={
                'tenant_id': tenant_id,
                'user_id': user_id,
                'password': hashed_password
            }
        )

        return {
            'statusCode': 200,
            'body': json.dumps({
                'message': 'User registered successfully',
                'tenant_id': tenant_id,
                'user_id': user_id
            })
        }

    except Exception as e:
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }
