import boto3
import hashlib
import json
import os

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

        dynamodb = boto3.resource('dynamodb')
        table_name = os.environ['USERS_TABLE']
        t_usuarios = dynamodb.Table(table_name)

        # Verificar si ya existe ese usuario
        existing_user = t_usuarios.get_item(
            Key={
                'tenant_id': tenant_id,
                'user_id': user_id
            }
        )
        if 'Item' in existing_user:
            return {
                'statusCode': 409,
                'body': json.dumps({'error': 'User already exists in this tenant'})
            }

        # Si no existe, se crea
        hashed_password = hash_password(password)

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
