# docpilot-backend/src/handlers/email/ses_configurator.py
import json
import os
import boto3
import logging
from datetime import datetime
import uuid

# Configuración de servicios
logger = logging.getLogger()
logger.setLevel(logging.INFO)

s3 = boto3.client('s3')
ses = boto3.client('ses')
route53 = boto3.client('route53')
dynamodb = boto3.resource('dynamodb')
tenants_table = dynamodb.Table(os.environ.get('TENANTS_TABLE'))
MAIN_BUCKET = os.environ.get('MAIN_BUCKET')

def lambda_handler(event, context):
    """Maneja operaciones para configuración de SES para tenants"""
    # Determinar operación basada en la ruta y método HTTP
    http_method = event.get('httpMethod', '')
    path = event.get('path', '')
    
    logger.info(f"Solicitud recibida: método {http_method}, ruta {path}")
    
    if http_method == 'POST' and '/email/domain' in path:
        return configure_email_domain(event, context)
    elif http_method == 'GET' and '/email/domain/status' in path:
        return check_domain_verification_status(event, context)
    elif http_method == 'POST' and '/email/receipt-rule' in path:
        return create_receipt_rule(event, context)
    elif http_method == 'GET' and '/email/domains' in path:
        return list_verified_domains(event, context)
    elif http_method == 'DELETE' and '/email/domain' in path:
        return remove_domain(event, context)
    else:
        logger.warning(f"Operación no válida: {http_method} {path}")
        return {
            'statusCode': 400,
            'headers': {'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*'},
            'body': json.dumps({'error': 'Operación no válida'})
        }

def configure_email_domain(event, context):
    """
    Configura un dominio para uso con SES para un tenant específico
    """
    try:
        # Obtener datos del body
        body = json.loads(event.get('body', '{}'))
        tenant_id = body.get('tenant_id')
        domain = body.get('domain')
        manage_dns = body.get('manage_dns', False)
        route53_hosted_zone_id = body.get('hosted_zone_id') if manage_dns else None
        
        if not tenant_id or not domain:
            logger.error("Faltan campos obligatorios: tenant_id o domain")
            return {
                'statusCode': 400,
                'headers': {'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*'},
                'body': json.dumps({'error': 'tenant_id y domain son campos obligatorios'})
            }
        
        logger.info(f"Configurando dominio para tenant {tenant_id}: {domain}")
        
        # Verificar que el tenant existe
        tenant_response = tenants_table.get_item(Key={'tenant_id': tenant_id})
        if 'Item' not in tenant_response:
            logger.error(f"Tenant no encontrado: {tenant_id}")
            return {
                'statusCode': 404,
                'headers': {'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*'},
                'body': json.dumps({'error': 'Tenant no encontrado'})
            }
        
        tenant = tenant_response['Item']
        
        # Verificar el plan del tenant permite dominio personalizado
        if not tenant.get('features', {}).get('custom_domain', False):
            logger.warning(f"El plan del tenant {tenant_id} no permite dominio personalizado")
            return {
                'statusCode': 403,
                'headers': {'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*'},
                'body': json.dumps({'error': 'Su plan actual no permite configurar dominios personalizados. Actualice a un plan premium o superior.'})
            }
        
        # Verificar si el dominio ya está verificado en SES
        try:
            domain_status = ses.get_identity_verification_attributes(
                Identities=[domain]
            ).get('VerificationAttributes', {}).get(domain, {})
            
            if domain_status.get('VerificationStatus') == 'Success':
                logger.info(f"Dominio ya verificado en SES: {domain}")
                
                # Actualizar el tenant con la información del dominio
                update_tenant_domain(tenant_id, domain)
                
                return {
                    'statusCode': 200,
                    'headers': {'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*'},
                    'body': json.dumps({
                        'message': 'Dominio ya está verificado',
                        'domain': domain,
                        'status': 'VERIFIED'
                    })
                }
        except Exception as e:
            logger.warning(f"Error verificando dominio existente: {str(e)}")
            # Continuamos con el proceso normal
        
        # Iniciar verificación del dominio en SES
        try:
            verification_response = ses.verify_domain_identity(
                Domain=domain
            )
            
            verification_token = verification_response.get('VerificationToken')
            
            logger.info(f"Solicitud de verificación enviada para dominio: {domain}")
            
            # Configurar DKIM para el dominio
            dkim_response = ses.verify_domain_dkim(
                Domain=domain
            )
            
            dkim_tokens = dkim_response.get('DkimTokens', [])
            
            # Si se solicitó manejo de DNS y se proporcionó un ID de zona alojada
            dns_records = []
            
            if manage_dns and route53_hosted_zone_id:
                try:
                    # Registrar el registro TXT para verificación
                    route53.change_resource_record_sets(
                        HostedZoneId=route53_hosted_zone_id,
                        ChangeBatch={
                            'Changes': [
                                {
                                    'Action': 'UPSERT',
                                    'ResourceRecordSet': {
                                        'Name': f'_amazonses.{domain}',
                                        'Type': 'TXT',
                                        'TTL': 300,
                                        'ResourceRecords': [
                                            {'Value': f'"{verification_token}"'}
                                        ]
                                    }
                                }
                            ]
                        }
                    )
                    
                    # Registrar los registros CNAME para DKIM
                    dkim_changes = []
                    for token in dkim_tokens:
                        dkim_changes.append({
                            'Action': 'UPSERT',
                            'ResourceRecordSet': {
                                'Name': f'{token}._domainkey.{domain}',
                                'Type': 'CNAME',
                                'TTL': 300,
                                'ResourceRecords': [
                                    {'Value': f'{token}.dkim.amazonses.com'}
                                ]
                            }
                        })
                    
                    if dkim_changes:
                        route53.change_resource_record_sets(
                            HostedZoneId=route53_hosted_zone_id,
                            ChangeBatch={
                                'Changes': dkim_changes
                            }
                        )
                    
                    logger.info(f"Registros DNS creados automáticamente para dominio: {domain}")
                    
                    # Crear registro MX para recepción de correos (opcional)
                    route53.change_resource_record_sets(
                        HostedZoneId=route53_hosted_zone_id,
                        ChangeBatch={
                            'Changes': [
                                {
                                    'Action': 'UPSERT',
                                    'ResourceRecordSet': {
                                        'Name': domain,
                                        'Type': 'MX',
                                        'TTL': 300,
                                        'ResourceRecords': [
                                            {'Value': f'10 inbound-smtp.{ses.meta.region_name}.amazonaws.com'}
                                        ]
                                    }
                                }
                            ]
                        }
                    )
                    
                except Exception as e:
                    logger.error(f"Error creando registros DNS automáticamente: {str(e)}")
                    # Se maneja como advertencia, no como error fatal
            
            # Preparar la lista de registros DNS para la respuesta
            dns_records = [
                {
                    'type': 'TXT',
                    'name': f'_amazonses.{domain}',
                    'value': verification_token
                }
            ]
            
            for token in dkim_tokens:
                dns_records.append({
                    'type': 'CNAME',
                    'name': f'{token}._domainkey.{domain}',
                    'value': f'{token}.dkim.amazonses.com'
                })
            
            dns_records.append({
                'type': 'MX',
                'name': domain,
                'value': f'10 inbound-smtp.{ses.meta.region_name}.amazonaws.com'
            })
            
            # Actualizar el tenant con la información del dominio pendiente
            update_tenant_domain(tenant_id, domain, 'PENDING')
            
            # Crear regla de recepción por defecto (si es la primera vez)
            try:
                create_default_receipt_rule_set()
            except Exception as e:
                logger.warning(f"Error al crear regla de recepción por defecto: {str(e)}")
            
            return {
                'statusCode': 202,
                'headers': {'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*'},
                'body': json.dumps({
                    'message': 'Verificación de dominio iniciada',
                    'domain': domain,
                    'status': 'PENDING',
                    'dns_records': dns_records,
                    'dns_managed': manage_dns and route53_hosted_zone_id is not None
                })
            }
            
        except Exception as e:
            logger.error(f"Error configurando dominio en SES: {str(e)}")
            return {
                'statusCode': 500,
                'headers': {'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*'},
                'body': json.dumps({'error': f'Error configurando dominio: {str(e)}'})
            }
    
    except Exception as e:
        logger.error(f"Error en configure_email_domain: {str(e)}")
        return {
            'statusCode': 500,
            'headers': {'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*'},
            'body': json.dumps({'error': str(e)})
        }

def check_domain_verification_status(event, context):
    """
    Verifica el estado de verificación de un dominio en SES
    """
    try:
        # Obtener tenant_id y domain de los query params
        query_params = event.get('queryStringParameters', {}) or {}
        tenant_id = query_params.get('tenant_id')
        domain = query_params.get('domain')
        
        if not tenant_id:
            logger.error("Falta parámetro tenant_id")
            return {
                'statusCode': 400,
                'headers': {'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*'},
                'body': json.dumps({'error': 'Se requiere tenant_id como parámetro'})
            }
        
        # Si no se proporciona un dominio, obtenerlo del tenant
        if not domain:
            # Obtener información del tenant
            tenant_response = tenants_table.get_item(Key={'tenant_id': tenant_id})
            if 'Item' not in tenant_response:
                logger.error(f"Tenant no encontrado: {tenant_id}")
                return {
                    'statusCode': 404,
                    'headers': {'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*'},
                    'body': json.dumps({'error': 'Tenant no encontrado'})
                }
            
            tenant = tenant_response['Item']
            domain = tenant.get('settings', {}).get('email_domain')
            
            if not domain:
                logger.error(f"No hay dominio configurado para tenant: {tenant_id}")
                return {
                    'statusCode': 404,
                    'headers': {'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*'},
                    'body': json.dumps({'error': 'No hay dominio configurado para este tenant'})
                }
        
        logger.info(f"Verificando estado de dominio para tenant {tenant_id}: {domain}")
        
        # Verificar estado de verificación en SES
        verification_response = ses.get_identity_verification_attributes(
            Identities=[domain]
        )
        
        domain_attributes = verification_response.get('VerificationAttributes', {}).get(domain, {})
        verification_status = domain_attributes.get('VerificationStatus', 'NotStarted')
        
        # Verificar estado de DKIM
        dkim_response = ses.get_identity_dkim_attributes(
            Identities=[domain]
        )
        
        dkim_attributes = dkim_response.get('DkimAttributes', {}).get(domain, {})
        dkim_status = {
            'enabled': dkim_attributes.get('DkimEnabled', False),
            'verified': dkim_attributes.get('DkimVerificationStatus', 'NotStarted')
        }
        
        # Si el dominio está verificado, actualizar el tenant
        if verification_status == 'Success' and dkim_status['verified'] == 'Success':
            update_tenant_domain(tenant_id, domain, 'VERIFIED')
        elif verification_status == 'Failed' or dkim_status['verified'] == 'Failed':
            update_tenant_domain(tenant_id, domain, 'FAILED')
        
        return {
            'statusCode': 200,
            'headers': {'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*'},
            'body': json.dumps({
                'domain': domain,
                'tenant_id': tenant_id,
                'domain_verification': verification_status,
                'dkim': dkim_status,
                'status': get_consolidated_status(verification_status, dkim_status['verified'])
            })
        }
        
    except Exception as e:
        logger.error(f"Error verificando estado de dominio: {str(e)}")
        return {
            'statusCode': 500,
            'headers': {'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*'},
            'body': json.dumps({'error': str(e)})
        }

def create_receipt_rule(event, context):
    """
    Crea una regla de recepción para un tenant específico
    """
    try:
        # Obtener datos del body
        body = json.loads(event.get('body', '{}'))
        tenant_id = body.get('tenant_id')
        domain = body.get('domain')
        
        if not tenant_id or not domain:
            logger.error("Faltan campos obligatorios: tenant_id o domain")
            return {
                'statusCode': 400,
                'headers': {'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*'},
                'body': json.dumps({'error': 'tenant_id y domain son campos obligatorios'})
            }
        
        logger.info(f"Creando regla de recepción para tenant {tenant_id} dominio: {domain}")
        
        # Verificar que el tenant existe
        tenant_response = tenants_table.get_item(Key={'tenant_id': tenant_id})
        if 'Item' not in tenant_response:
            logger.error(f"Tenant no encontrado: {tenant_id}")
            return {
                'statusCode': 404,
                'headers': {'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*'},
                'body': json.dumps({'error': 'Tenant no encontrado'})
            }
        
        # Verificar si el dominio está verificado
        verification_response = ses.get_identity_verification_attributes(
            Identities=[domain]
        )
        
        domain_attributes = verification_response.get('VerificationAttributes', {}).get(domain, {})
        verification_status = domain_attributes.get('VerificationStatus')
        
        if verification_status != 'Success':
            logger.warning(f"Dominio no verificado: {domain}")
            return {
                'statusCode': 400,
                'headers': {'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*'},
                'body': json.dumps({
                    'error': 'El dominio debe estar verificado antes de crear reglas de recepción',
                    'verification_status': verification_status
                })
            }
        
        # Crear o actualizar regla de recepción
        rule_name = f"{tenant_id}-{domain.replace('.', '-')}"
        
        # Verificar si existe un conjunto de reglas activo
        rule_sets_response = ses.list_receipt_rule_sets()
        active_rule_set = None
        
        for rule_set in rule_sets_response.get('RuleSets', []):
            if rule_set.get('IsActive', False):
                active_rule_set = rule_set.get('Name')
                break
        
        # Si no hay conjunto de reglas activo, usar el conjunto por defecto
        if not active_rule_set:
            active_rule_set = 'default-rule-set'
            create_default_receipt_rule_set()
        
        # Definir la regla para escribir en el bucket S3
        rule_definition = {
            'Name': rule_name,
            'Enabled': True,
            'TlsPolicy': 'Optional',
            'Recipients': [domain],  # Recibir correos para todo el dominio
            'Actions': [
                {
                    'S3Action': {
                        'BucketName': os.environ.get('SES_BUCKET'),
                        'ObjectKeyPrefix': f'tenants/{tenant_id}/inbound/',
                        'TopicArn': ''  # Opcional: SNS para notificaciones
                    }
                }
            ]
        }
        
        # Crear o actualizar la regla
        try:
            # Primero intentar eliminar si existe
            try:
                ses.delete_receipt_rule(
                    RuleSetName=active_rule_set,
                    RuleName=rule_name
                )
                logger.info(f"Regla anterior eliminada: {rule_name}")
            except Exception as e:
                # Si no existe, ignorar el error
                pass
            
            # Crear la nueva regla
            ses.create_receipt_rule(
                RuleSetName=active_rule_set,
                Rule=rule_definition,
                After=''  # Añadir al inicio del conjunto
            )
            
            logger.info(f"Regla de recepción creada exitosamente: {rule_name}")
            
            return {
                'statusCode': 200,
                'headers': {'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*'},
                'body': json.dumps({
                    'message': 'Regla de recepción creada exitosamente',
                    'rule_name': rule_name,
                    'rule_set': active_rule_set,
                    'domain': domain
                })
            }
            
        except Exception as e:
            logger.error(f"Error creando regla de recepción: {str(e)}")
            return {
                'statusCode': 500,
                'headers': {'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*'},
                'body': json.dumps({'error': f'Error creando regla de recepción: {str(e)}'})
            }
        
    except Exception as e:
        logger.error(f"Error en create_receipt_rule: {str(e)}")
        return {
            'statusCode': 500,
            'headers': {'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*'},
            'body': json.dumps({'error': str(e)})
        }

def list_verified_domains(event, context):
    """
    Lista todos los dominios verificados en SES para un tenant
    """
    try:
        # Obtener tenant_id de los query params
        query_params = event.get('queryStringParameters', {}) or {}
        tenant_id = query_params.get('tenant_id')
        
        if not tenant_id:
            logger.error("Falta parámetro tenant_id")
            return {
                'statusCode': 400,
                'headers': {'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*'},
                'body': json.dumps({'error': 'Se requiere tenant_id como parámetro'})
            }
        
        logger.info(f"Listando dominios para tenant: {tenant_id}")
        
        # Obtener información del tenant
        tenant_response = tenants_table.get_item(Key={'tenant_id': tenant_id})
        if 'Item' not in tenant_response:
            logger.error(f"Tenant no encontrado: {tenant_id}")
            return {
                'statusCode': 404,
                'headers': {'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*'},
                'body': json.dumps({'error': 'Tenant no encontrado'})
            }
        
        tenant = tenant_response['Item']
        
        # Obtener dominios configurados para el tenant
        email_domains = tenant.get('email_domains', [])
        primary_domain = tenant.get('settings', {}).get('email_domain')
        
        # Si hay un dominio principal y no está en la lista, añadirlo
        if primary_domain and primary_domain not in [d.get('domain') for d in email_domains]:
            email_domains.append({
                'domain': primary_domain,
                'status': 'PENDING',  # Estado por defecto, se actualizará a continuación
                'is_primary': True
            })
        
        # Verificar el estado actual de cada dominio en SES
        if email_domains:
            domains_to_check = [d.get('domain') for d in email_domains]
            
            # Verificar estado de verificación
            verification_response = ses.get_identity_verification_attributes(
                Identities=domains_to_check
            )
            
            # Verificar estado de DKIM
            dkim_response = ses.get_identity_dkim_attributes(
                Identities=domains_to_check
            )
            
            # Actualizar información de cada dominio
            for domain_info in email_domains:
                domain = domain_info.get('domain')
                domain_attributes = verification_response.get('VerificationAttributes', {}).get(domain, {})
                domain_info['verification_status'] = domain_attributes.get('VerificationStatus', 'NotStarted')
                
                dkim_attributes = dkim_response.get('DkimAttributes', {}).get(domain, {})
                domain_info['dkim_enabled'] = dkim_attributes.get('DkimEnabled', False)
                domain_info['dkim_status'] = dkim_attributes.get('DkimVerificationStatus', 'NotStarted')
                
                # Actualizar estado consolidado
                domain_info['status'] = get_consolidated_status(
                    domain_info['verification_status'],
                    domain_info['dkim_status']
                )
        
        return {
            'statusCode': 200,
            'headers': {'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*'},
            'body': json.dumps({
                'tenant_id': tenant_id,
                'domains': email_domains,
                'primary_domain': primary_domain
            })
        }
        
    except Exception as e:
        logger.error(f"Error listando dominios: {str(e)}")
        return {
            'statusCode': 500,
            'headers': {'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*'},
            'body': json.dumps({'error': str(e)})
        }

def remove_domain(event, context):
    """
    Elimina un dominio de SES y de la configuración del tenant
    """
    try:
        # Obtener tenant_id y domain de los path params
        tenant_id = event['pathParameters'].get('tenant_id')
        domain = event['pathParameters'].get('domain')
        
        if not tenant_id or not domain:
            logger.error("Faltan parámetros de ruta: tenant_id o domain")
            return {
                'statusCode': 400,
                'headers': {'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*'},
                'body': json.dumps({'error': 'Se requieren tenant_id y domain como parámetros'})
            }
        
        logger.info(f"Eliminando dominio {domain} para tenant: {tenant_id}")
        
        # Verificar que el tenant existe
        tenant_response = tenants_table.get_item(Key={'tenant_id': tenant_id})
        if 'Item' not in tenant_response:
            logger.error(f"Tenant no encontrado: {tenant_id}")
            return {
                'statusCode': 404,
                'headers': {'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*'},
                'body': json.dumps({'error': 'Tenant no encontrado'})
            }
        
        tenant = tenant_response['Item']
        
        # Verificar si es el dominio principal
        primary_domain = tenant.get('settings', {}).get('email_domain')
        
        if domain == primary_domain:
            logger.warning(f"Intento de eliminar dominio principal: {domain}")
            return {
                'statusCode': 400,
                'headers': {'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*'},
                'body': json.dumps({'error': 'No se puede eliminar el dominio principal. Cambie el dominio principal primero.'})
            }
        
        # Eliminar dominio de la lista de dominios del tenant
        email_domains = tenant.get('email_domains', [])
        updated_domains = [d for d in email_domains if d.get('domain') != domain]
        
        # Actualizar el tenant
        tenants_table.update_item(
            Key={'tenant_id': tenant_id},
            UpdateExpression="set email_domains = :d, updated_at = :t",
            ExpressionAttributeValues={
                ':d': updated_domains,
                ':t': datetime.now().isoformat()
            }
        )
        
        # Eliminar regla de recepción si existe
        rule_name = f"{tenant_id}-{domain.replace('.', '-')}"
        
        try:
            # Buscar el conjunto de reglas activo
            rule_sets_response = ses.list_receipt_rule_sets()
            active_rule_set = None
            
            for rule_set in rule_sets_response.get('RuleSets', []):
                if rule_set.get('IsActive', False):
                    active_rule_set = rule_set.get('Name')
                    break
            
            if active_rule_set:
                # Eliminar la regla
                ses.delete_receipt_rule(
                    RuleSetName=active_rule_set,
                    RuleName=rule_name
                )
                logger.info(f"Regla de recepción eliminada: {rule_name}")
        except Exception as e:
            logger.warning(f"Error eliminando regla de recepción: {str(e)}")
            # Ignorar errores en esta parte
        
        # Eliminar identidad en SES (opcional)
        # Comentado porque no es necesario eliminar la identidad y podría afectar a otros tenants
        # try:
        #     ses.delete_identity(
        #         Identity=domain
        #     )
        #     logger.info(f"Identidad eliminada en SES: {domain}")
        # except Exception as e:
        #     logger.warning(f"Error eliminando identidad en SES: {str(e)}")
        
        return {
            'statusCode': 200,
            'headers': {'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*'},
            'body': json.dumps({
                'message': 'Dominio eliminado correctamente',
                'domain': domain,
                'tenant_id': tenant_id
            })
        }
        
    except Exception as e:
        logger.error(f"Error eliminando dominio: {str(e)}")
        return {
            'statusCode': 500,
            'headers': {'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*'},
            'body': json.dumps({'error': str(e)})
        }

def update_tenant_domain(tenant_id, domain, status='PENDING'):
    """
    Actualiza la información de dominio de email en el tenant
    
    Args:
        tenant_id (str): ID del tenant
        domain (str): Dominio a configurar
        status (str): Estado del dominio (PENDING, VERIFIED, FAILED)
    """
    try:
        # Obtener información actual del tenant
        tenant_response = tenants_table.get_item(Key={'tenant_id': tenant_id})
        
        if 'Item' not in tenant_response:
            logger.error(f"Tenant no encontrado: {tenant_id}")
            return False
        
        tenant = tenant_response['Item']
        
        # Verificar si ya existe configuración de dominios
        email_domains = tenant.get('email_domains', [])
        
        # Buscar si el dominio ya existe en la lista
        domain_exists = False
        for domain_info in email_domains:
            if domain_info.get('domain') == domain:
                domain_exists = True
                domain_info['status'] = status
                domain_info['updated_at'] = datetime.now().isoformat()
                break
        
        # Si no existe, añadirlo
        if not domain_exists:
            email_domains.append({
                'domain': domain,
                'status': status,
                'created_at': datetime.now().isoformat(),
                'updated_at': datetime.now().isoformat(),
                'is_primary': len(email_domains) == 0  # Es primario si es el primero
            })
        
        # Si es el primer dominio o está marcado como primario, actualizar la configuración principal
        if len(email_domains) == 1 or any(d.get('is_primary', False) and d.get('domain') == domain for d in email_domains):
            settings = tenant.get('settings', {})
            settings['email_domain'] = domain
            
            # Actualizar el tenant con el nuevo dominio y configuraciones
            # Actualizar el tenant con el nuevo dominio y configuraciones
            tenants_table.update_item(
                Key={'tenant_id': tenant_id},
                UpdateExpression="set email_domains = :d, settings = :s, updated_at = :t",
                ExpressionAttributeValues={
                    ':d': email_domains,
                    ':s': settings,
                    ':t': datetime.now().isoformat()
                }
            )
        else:
            # Actualizar solo la lista de dominios
            tenants_table.update_item(
                Key={'tenant_id': tenant_id},
                UpdateExpression="set email_domains = :d, updated_at = :t",
                ExpressionAttributeValues={
                    ':d': email_domains,
                    ':t': datetime.now().isoformat()
                }
            )
        
        logger.info(f"Información de dominio actualizada para tenant {tenant_id}: {domain}, status: {status}")
        return True
        
    except Exception as e:
        logger.error(f"Error actualizando información de dominio: {str(e)}")
        return False

def create_default_receipt_rule_set():
    """
    Crea un conjunto de reglas de recepción predeterminado si no existe
    """
    try:
        # Verificar si ya existe un conjunto activo
        rule_sets_response = ses.list_receipt_rule_sets()
        
        for rule_set in rule_sets_response.get('RuleSets', []):
            if rule_set.get('Name') == 'default-rule-set':
                logger.info("Conjunto de reglas predeterminado ya existe")
                return
        
        # Crear el conjunto de reglas
        ses.create_receipt_rule_set(
            RuleSetName='default-rule-set'
        )
        
        logger.info("Conjunto de reglas predeterminado creado")
        
        # Activar el conjunto (opcional, dependiendo de la configuración existente)
        try:
            ses.set_active_receipt_rule_set(
                RuleSetName='default-rule-set'
            )
            logger.info("Conjunto de reglas predeterminado activado")
        except Exception as e:
            logger.warning(f"No se pudo activar el conjunto de reglas: {str(e)}")
        
    except Exception as e:
        logger.error(f"Error creando conjunto de reglas predeterminado: {str(e)}")
        raise

def get_consolidated_status(verification_status, dkim_status):
    """
    Obtiene un estado consolidado basado en el estado de verificación y DKIM
    
    Args:
        verification_status (str): Estado de verificación del dominio
        dkim_status (str): Estado de verificación DKIM
        
    Returns:
        str: Estado consolidado (VERIFIED, PENDING, FAILED)
    """
    # Si ambos están verificados, el estado es verificado
    if verification_status == 'Success' and dkim_status == 'Success':
        return 'VERIFIED'
    # Si alguno falló, el estado es fallido
    elif verification_status == 'Failed' or dkim_status == 'Failed':
        return 'FAILED'
    # En cualquier otro caso, el estado es pendiente
    else:
        return 'PENDING'