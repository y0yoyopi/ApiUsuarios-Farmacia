import boto3
import hashlib
import json
import os
import uuid
from datetime import datetime, timedelta

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def lambda_handler(event, context):
    try:
        # Asegura que body sea un dict
        if isinstance(event['body'], str):
            body = json.loads(event['body'])
        else:
            body = event['body']

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
        users_table = dynamodb.Table(os.environ['USERS_TABLE'])

        # Buscar por tenant_id + user_id
        response = users_table.get_item(
            Key={
                'tenant_id': tenant_id,
                'user_id': user_id
            }
        )

        if 'Item' not in response:
            return {
                'statusCode': 403,
                'body': json.dumps({'error': 'Usuario no existe'})
            }

        stored_hash = response['Item']['password']
        if hashed_password != stored_hash:
            return {
                'statusCode': 403,
                'body': json.dumps({'error': 'Password incorrecto'})
            }

        # Generar token
        token = str(uuid.uuid4())
        expires = (datetime.utcnow() + timedelta(hours=1)).strftime('%Y-%m-%dT%H:%M:%SZ')

        tokens_table = dynamodb.Table(os.environ['TOKENS_TABLE'])
        tokens_table.put_item(
            Item={
                'token': token,
                'tenant_id': tenant_id,
                'user_id': user_id,
                'expires': expires
            }
        )

        return {
            'statusCode': 200,
            'body': json.dumps({
                'token': token,
                'expires': expires
            })
        }

    except Exception as e:
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }

