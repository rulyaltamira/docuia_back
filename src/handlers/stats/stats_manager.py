# docpilot-backend/src/handlers/stats/stats_manager.py
# Gestión de estadísticas para DocPilot - Archivo Consolidado

import json
import os
import boto3
import logging
from datetime import datetime, timedelta 
import decimal
import math 

from src.utils.cors_middleware import add_cors_headers
from src.utils.auth_utils import extract_tenant_id

logger = logging.getLogger()
logger.setLevel(logging.INFO)

dynamodb = boto3.resource('dynamodb')
contracts_table = dynamodb.Table(os.environ.get('CONTRACTS_TABLE'))
users_table = dynamodb.Table(os.environ.get('USERS_TABLE'))
tenants_table = dynamodb.Table(os.environ.get('TENANTS_TABLE'))
alerts_table = dynamodb.Table(os.environ.get('ALERTS_TABLE'))

statistics_table = None
statistics_table_name = os.environ.get('STATISTICS_TABLE')
if statistics_table_name:
    try:
        statistics_table = dynamodb.Table(statistics_table_name)
        logger.info(f"Tabla de estadísticas inicializada: {statistics_table_name}")
    except Exception as e:
        logger.warning(f"No se pudo inicializar tabla de estadísticas: {str(e)}")

class DecimalEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, decimal.Decimal): return float(obj)
        if isinstance(obj, datetime): return obj.isoformat()
        return super(DecimalEncoder, self).default(obj)

def lambda_handler(event, context):
    function_name = context.function_name if hasattr(context, 'function_name') else 'local_test'
    print(f"Evento recibido en {function_name}: {json.dumps(event)}")
    
    # TODO: Implementar la lógica del handler.
    # Recuerda reemplazar este placeholder con el código de tu archivo en la carpeta 'faltantes' o desarrollar la nueva lógica.
    
    response_body = {
        'message': f'Handler {function_name} ejecutado exitosamente (placeholder)',
        'input_event': event
    }
    
    return {
        'statusCode': 200,
        'body': json.dumps(response_body),
        'headers': {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*' # Ajustar según necesidad
        }
    }

# Para pruebas locales (opcional)
# if __name__ == '__main__':
#     # Simular un objeto context básico para pruebas locales
#     class MockContext:
#         function_name = "local_test_handler"
#     
#     mock_event = {"key": "value"}
#     # os.environ['MI_VARIABLE_DE_ENTORNO'] = 'valor_test'
#     print(lambda_handler(mock_event, MockContext()))

# --- Funciones auxiliares (combinadas y/o de statistics_api.py) ---
def calculate_start_date(end_date, period):
    if period == 'day': return end_date - timedelta(days=1)
    elif period == 'week': return end_date - timedelta(days=7)
    elif period == 'month': return end_date - timedelta(days=30)
    elif period == 'year': return end_date - timedelta(days=365)
    else: return datetime(2000, 1, 1) 

def calculate_percentage(value, limit):
    if limit is None or limit <= 0: return 0
    percentage = (value / limit) * 100
    return round(min(percentage, 100), 2)

def generate_document_time_series(documents, period):
    time_series = {}
    if not documents: return time_series
    for doc in documents:
        created_at_str = doc.get('created_at') # Usar created_at, no timestamp
        if not created_at_str: continue
        key = ""
        try: # Asegurar que created_at_str sea parseable
            dt_obj = datetime.fromisoformat(created_at_str.replace('Z', '+00:00'))
            if period == 'day': key = dt_obj.strftime('%Y-%m-%dT%H') 
            elif period == 'week' or period == 'month': key = dt_obj.strftime('%Y-%m-%d')
            elif period == 'year' or period == 'all': key = dt_obj.strftime('%Y-%m')
            else: key = dt_obj.strftime('%Y-%m')
        except ValueError:
            logger.warning(f"Invalid date format for created_at: {created_at_str} in doc {doc.get('id')}")
            continue

        if key not in time_series: time_series[key] = {'count': 0, 'by_status': {}, 'by_source': {}}
        time_series[key]['count'] += 1
        status = doc.get('status', 'unknown'); source = doc.get('source', 'unknown')
        time_series[key]['by_status'][status] = time_series[key]['by_status'].get(status, 0) + 1
        time_series[key]['by_source'][source] = time_series[key]['by_source'].get(source, 0) + 1
    return dict(sorted(time_series.items()))

def get_median(numbers):
    if not numbers: return 0
    sorted_numbers = sorted(numbers); n = len(sorted_numbers)
    if n % 2 == 0: return (sorted_numbers[n//2 - 1] + sorted_numbers[n//2]) / 2
    else: return sorted_numbers[n//2]

def count_processed_documents_in_month(tenant_id, month_str): # YYYY-MM
    try:
        count = 0; exclusive_start_key = None
        while True:
            scan_params = {
                'FilterExpression': "tenant_id = :t AND begins_with(processed_at, :m) AND #st = :s",
                'ExpressionAttributeValues': {":t": tenant_id, ":m": month_str, ":s": "processed"},
                'ExpressionAttributeNames': {"#st": "status"}}
            if exclusive_start_key: scan_params['ExclusiveStartKey'] = exclusive_start_key
            response = contracts_table.scan(**scan_params)
            count += len(response.get('Items', [])); exclusive_start_key = response.get('LastEvaluatedKey')
            if not exclusive_start_key: break
        return count
    except Exception as e:
        logger.error(f"Error contando docs procesados mes: {str(e)}"); return 0

def get_time_series_stats(tenant_id, metric_type, period):
    try:
        if not statistics_table: 
            logger.warning("statistics_table no configurada.")
            return {'tenant_id':tenant_id,'metric_type':metric_type,'period':period,'time_series':[],'error':'Statistics table not set'}
        
        metric_map={'documents':'documents_count_total','users':'users_count_total','storage':'storage_used_mb'}
        if metric_type not in metric_map: raise ValueError(f"Métrica inválida: {metric_type}")
        
        target_metric_name = metric_map[metric_type] # Nombre de la métrica como se guarda en la tabla
        end_dt=datetime.now(); start_dt=calculate_start_date(end_dt,period)
        logger.info(f"Querying statistics_table: tenant={tenant_id}, metric_name={target_metric_name}, start={start_dt.isoformat()}, end={end_dt.isoformat()}")
        
        # Asumimos que statistics_table tiene un GSI 'tenant-metric-time-index' en (tenant_id, metric_name, timestamp)
        # O una clave primaria compuesta que permita esta query eficiente.
        # La consulta debe adaptarse al esquema exacto de 'statistics_table'
        response = statistics_table.query(
            IndexName='tenant-index', # O el nombre correcto del GSI
            KeyConditionExpression="tenant_id = :tid AND #ts BETWEEN :start AND :end",
            FilterExpression="metric_name = :mname", 
            ExpressionAttributeNames={"#ts": "timestamp"}, # 'timestamp' es palabra reservada
            ExpressionAttributeValues={
                ":tid":tenant_id, 
                ":start":start_dt.isoformat(), 
                ":end":end_dt.isoformat(), 
                ":mname":target_metric_name
            }
        )
        items=response.get('Items',[])
        time_series=[{'timestamp':i['timestamp'],'value':i.get('value',0)} for i in items]
        time_series.sort(key=lambda x:x['timestamp'])
        return {'tenant_id':tenant_id,'metric_type':metric_type,'period':period,'time_series':time_series}
    except Exception as e:
        logger.error(f"Error get_time_series_stats: {str(e)}")
        return {'tenant_id':tenant_id,'metric_type':metric_type,'period':period,'time_series':[],'error':str(e)}

# --- Funciones de Endpoints (Versiones _api_version con lógica de statistics_api.py) ---

def get_document_stats_api_version(event, context):
    try:
        tenant_id = extract_tenant_id(event)
        if not tenant_id: return {'statusCode': 400, 'headers': add_cors_headers({'Content-Type': 'application/json'}), 'body': json.dumps({'error': 'No se pudo determinar tenant_id'})}
        
        query_params = event.get('queryStringParameters', {}) or {}
        period = query_params.get('period', 'month')
        end_date = datetime.now(); start_date = calculate_start_date(end_date, period)
        start_date_str, end_date_str = start_date.isoformat(), end_date.isoformat()

        response = contracts_table.scan(FilterExpression="tenant_id = :t AND created_at BETWEEN :start AND :end", ExpressionAttributeValues={':t': tenant_id, ':start': start_date_str, ':end': end_date_str})
        documents = response.get('Items', [])
        
        status_counts, source_counts, type_counts = {}, {}, {}
        for doc in documents:
            status_counts[doc.get('status','unknown')] = status_counts.get(doc.get('status','unknown'),0)+1
            source_counts[doc.get('source','unknown')] = source_counts.get(doc.get('source','unknown'),0)+1
            type_counts[doc.get('document_type','unclassified')] = type_counts.get(doc.get('document_type','unclassified'),0)+1
        
        time_series = generate_document_time_series(documents, period)
        processing_times = []
        for doc in documents:
            if doc.get('processed_at') and doc.get('created_at'):
                try: 
                    p_dt=datetime.fromisoformat(doc['processed_at'].replace('Z','+00:00'))
                    c_dt=datetime.fromisoformat(doc['created_at'].replace('Z','+00:00'))
                    processing_times.append((p_dt-c_dt).total_seconds()/60)
                except ValueError: logger.warning(f"Date error doc {doc.get('id')}")
        
        avg_processing_time = sum(processing_times)/len(processing_times) if processing_times else 0
        stats = {'tenant_id':tenant_id,'period':period,'total_documents':len(documents),'by_status':status_counts,'by_source':source_counts,'by_type':type_counts,'time_series':time_series,'processing':{'average_minutes':round(avg_processing_time,2),'count_processed':len(processing_times)}}
        
        return {'statusCode':200,'headers':add_cors_headers({'Content-Type':'application/json'}),'body':json.dumps(stats,cls=DecimalEncoder)}
    except Exception as e: 
        logger.error(f"Err get_document_stats_api_version: {str(e)}")
        return {'statusCode':500,'headers':add_cors_headers({'Content-Type':'application/json'}),'body':json.dumps({'error':str(e)})}

def get_user_stats_api_version(event, context):
    try:
        tenant_id = extract_tenant_id(event)
        if not tenant_id: return {'statusCode':400,'headers':add_cors_headers({'Content-Type':'application/json'}),'body':json.dumps({'error':'No se pudo determinar tenant_id'})}
        
        response = users_table.scan(FilterExpression="tenant_id = :t", ExpressionAttributeValues={':t': tenant_id})
        users = response.get('Items',[]); role_counts, status_counts = {}, {}
        for user in users: 
            role_counts[user.get('role','unknown')]=role_counts.get(user.get('role','unknown'),0)+1
            status_counts[user.get('status','unknown')]=status_counts.get(user.get('status','unknown'),0)+1
        
        now, act7, act30 = datetime.now(),0,0
        w_ago,m_ago = now-timedelta(days=7),now-timedelta(days=30)
        for user in users:
            last_login_str = user.get('last_login')
            if last_login_str:
                try: 
                    ll_dt=datetime.fromisoformat(last_login_str.replace('Z','+00:00'));
                    if ll_dt>w_ago:act7+=1
                    if ll_dt>m_ago:act30+=1
                except ValueError: logger.warning(f"Date err last_login: {last_login_str} for user {user.get('user_id')}")
        
        stats = {'tenant_id':tenant_id,'total_users':len(users),'by_role':role_counts,'by_status':status_counts,'activity':{'active_last_7days':act7,'active_last_30days':act30,'inactive_users':len(users)-act30}}
        return {'statusCode':200,'headers':add_cors_headers({'Content-Type':'application/json'}),'body':json.dumps(stats,cls=DecimalEncoder)}
    except Exception as e: 
        logger.error(f"Err get_user_stats_api_version: {str(e)}")
        return {'statusCode':500,'headers':add_cors_headers({'Content-Type':'application/json'}),'body':json.dumps({'error':str(e)})}

def get_summary_stats_api_version(event, context):
    try:
        tenant_id = extract_tenant_id(event)
        if not tenant_id: return {'statusCode':400,'headers':add_cors_headers({'Content-Type':'application/json'}),'body':json.dumps({'error':'No se pudo determinar tenant_id'})}
        
        tenant_res = tenants_table.get_item(Key={'tenant_id':tenant_id})
        if 'Item' not in tenant_res: return {'statusCode':404,'headers':add_cors_headers({'Content-Type':'application/json'}),'body':json.dumps({'error':'Tenant no encontrado'})}
        
        t=tenant_res['Item']; usage,limits_data=t.get('usage',{}),t.get('limits',{}) # Renombrado limits a limits_data
        
        summary={'tenant_id':tenant_id,'tenant_name':t.get('name','Unknown'),'plan':t.get('plan','Unknown'),
            'usage':{'documents':{'total':usage.get('documents_count',0),'limit':limits_data.get('max_documents',-1),'%':calculate_percentage(usage.get('documents_count',0),limits_data.get('max_documents',-1))},
                     'users':{'total':usage.get('users_count',0),'limit':limits_data.get('max_users',-1),'%':calculate_percentage(usage.get('users_count',0),limits_data.get('max_users',-1))},
                     'storage':{'total_mb':usage.get('storage_used_mb',0),'limit_mb':limits_data.get('max_storage_mb',-1),'%':calculate_percentage(usage.get('storage_used_mb',0),limits_data.get('max_storage_mb',-1))}},
            'last_update':usage.get('last_updated','Never')}
        proc_month=count_processed_documents_in_month(tenant_id,datetime.now().strftime("%Y-%m"))
        summary['processing'] = {'this_month':proc_month,'limit':limits_data.get('max_monthly_processing',-1),'%':calculate_percentage(proc_month,limits_data.get('max_monthly_processing',-1))}
        summary['features']=t.get('features',{})
        
        return {'statusCode':200,'headers':add_cors_headers({'Content-Type':'application/json'}),'body':json.dumps(summary,cls=DecimalEncoder)}
    except Exception as e: 
        logger.error(f"Err get_summary_stats_api_version: {str(e)}")
        return {'statusCode':500,'headers':add_cors_headers({'Content-Type':'application/json'}),'body':json.dumps({'error':str(e)})}

def get_processing_stats_api_version(event, context):
    try:
        tenant_id = extract_tenant_id(event)
        if not tenant_id: 
            return {'statusCode': 400, 'headers': add_cors_headers({'Content-Type': 'application/json'}), 'body': json.dumps({'error': 'No se pudo determinar tenant_id'})}

        query_params = event.get('queryStringParameters', {}) or {}
        period = query_params.get('period', 'month')
        end_date, start_date = datetime.now(), calculate_start_date(datetime.now(), period)
        s_str, e_str = start_date.isoformat(), end_date.isoformat()
        
        filter_expression = "tenant_id = :t AND attribute_exists(processed_at) AND attribute_exists(created_at) AND processed_at BETWEEN :s AND :e"
        expression_values = {':t': tenant_id, ':s': s_str, ':e': e_str}
        
        response = contracts_table.scan(FilterExpression=filter_expression, ExpressionAttributeValues=expression_values)
        docs = response.get('Items', [])
        times = []
        for d_item in docs: # Renombrar d a d_item para evitar conflicto con módulo decimal
            try: 
                c = datetime.fromisoformat(d_item['created_at'].replace('Z','+00:00'))
                p = datetime.fromisoformat(d_item['processed_at'].replace('Z','+00:00'))
                times.append((p-c).total_seconds()/60)
            except ValueError: logger.warning(f"Date error doc {d_item.get('id')}")
            except KeyError: logger.warning(f"Missing created_at or processed_at in doc {d_item.get('id')} despite filter.")

        stats = {'tenant_id': tenant_id, 'period': period, 'total_processed': len(docs),
                 'processing_times': {'average_minutes': round(sum(times)/len(times) if times else 0,2), 
                                      'min_minutes': round(min(times) if times else 0,2), 
                                      'max_minutes': round(max(times) if times else 0,2), 
                                      'median_minutes': round(get_median(times) if times else 0,2)},
                 'processing_distribution': {'under_1min':sum(1 for t_item in times if t_item<1), # Renombrar t a t_item
                                           '1_5min':sum(1 for t_item in times if 1<=t_item<5),
                                           '5_15min':sum(1 for t_item in times if 5<=t_item<15),
                                           '15_60min':sum(1 for t_item in times if 15<=t_item<60),
                                           'over_60min':sum(1 for t_item in times if t_item>=60)}}
        daily = {}
        for d_item in docs: 
            if d_item.get('processed_at'): 
                day_key = d_item['processed_at'][:10]
                daily[day_key] = daily.get(day_key,{'count':0})
                daily[day_key]['count']+=1
        stats['daily_stats'] = daily
        
        return {'statusCode':200,'headers':add_cors_headers({'Content-Type':'application/json'}),'body':json.dumps(stats,cls=DecimalEncoder)}
    except Exception as e: 
        logger.error(f"Err get_processing_stats_api_version: {str(e)}")
        return {'statusCode':500,'headers':add_cors_headers({'Content-Type':'application/json'}),'body':json.dumps({'error':str(e)})}

def get_storage_stats_api_version(event, context):
    try:
        tenant_id = extract_tenant_id(event)
        if not tenant_id: return {'statusCode':400,'headers':add_cors_headers({'Content-Type':'application/json'}),'body':json.dumps({'error':'No se pudo determinar tenant_id'})}
        
        t_res=tenants_table.get_item(Key={'tenant_id':tenant_id})
        if 'Item' not in t_res: return {'statusCode':404,'headers':add_cors_headers({'Content-Type':'application/json'}),'body':json.dumps({'error':'Tenant no encontrado'})}
        
        tenant_item = t_res['Item'] # Renombrar t a tenant_item
        limit_val = tenant_item.get('limits',{}).get('max_storage_mb',-1) # Renombrar limit a limit_val
        
        d_res=contracts_table.scan(FilterExpression="tenant_id=:t AND #st<>:del", ExpressionAttributeValues={':t':tenant_id,':del':'deleted'}, ExpressionAttributeNames={'#st':'status'})
        docs=d_res.get('Items',[]);by_type={}
        
        for d_item in docs:  # Renombrar d a d_item
            ft=d_item.get('content_type','unknown') 
            ft_simple = 'pdf' if 'pdf' in ft else 'word' if 'word' in ft else 'text' if 'text' in ft or 'html' in ft else ft
            by_type[ft_simple]=by_type.get(ft_simple,{'count':0,'size_bytes':0})
            by_type[ft_simple]['count']+=1
            by_type[ft_simple]['size_bytes']+=d_item.get('file_size',0)
            
        total_b=sum(d_item.get('file_size',0) for d_item in docs);total_mb=total_b/(1024*1024);avg_b=total_b/len(docs) if docs else 0
        dist={'under_1mb':sum(1 for d_item in docs if d_item.get('file_size',0)<1024*1024),
              '1_5mb':sum(1 for d_item in docs if 1024*1024<=d_item.get('file_size',0)<5*1024*1024),
              '5_10mb':sum(1 for d_item in docs if 5*1024*1024<=d_item.get('file_size',0)<10*1024*1024),
              'over_10mb':sum(1 for d_item in docs if d_item.get('file_size',0)>=10*1024*1024)}
        stats={'tenant_id':tenant_id,
               'storage':{'total_bytes':total_b,'total_mb':round(total_mb,2),'limit_mb':limit_val,
                          'usage_percentage':round((total_mb/limit_val)*100,2)if limit_val != -1 and limit_val > 0 else 0,
                          'average_file_size_bytes':round(avg_b,2),'average_file_size_kb':round(avg_b/1024,2),
                          'by_type':by_type,'size_distribution':dist},
               'files_count':len(docs)}
        return {'statusCode':200,'headers':add_cors_headers({'Content-Type':'application/json'}),'body':json.dumps(stats,cls=DecimalEncoder)}
    except Exception as e: 
        logger.error(f"Err get_storage_stats_api_version: {str(e)}")
        return {'statusCode':500,'headers':add_cors_headers({'Content-Type':'application/json'}),'body':json.dumps({'error':str(e)})}

def get_critical_documents_api_version(event, context):
    try:
        tenant_id = extract_tenant_id(event)
        if not tenant_id: return {'statusCode':400,'headers':add_cors_headers({'Content-Type':'application/json'}),'body':json.dumps({'error':'No se pudo determinar tenant_id'})}
        
        q_params=event.get('queryStringParameters',{})or{};limit_val=int(q_params.get('limit',10)) # Renombrar limit
        today,future_30d=datetime.now(),(datetime.now()+timedelta(days=30)).isoformat()
        today_s=today.isoformat()
        
        res=contracts_table.scan(
            FilterExpression="tenant_id=:t AND #st<>:del AND attribute_exists(expiration_date) AND expiration_date BETWEEN :today AND :future", 
            ExpressionAttributeValues={':t':tenant_id,':del':'deleted',':today':today_s,':future':future_30d}, 
            ExpressionAttributeNames={'#st':'status'}
        )
        docs=res.get('Items',[]);
        
        for doc_item in docs:
            exp_date_str = doc_item.get('expiration_date')
            if exp_date_str:
                try:
                    # Asegurar que la fecha sea comparable, convirtiendo a objeto datetime si es string
                    if isinstance(exp_date_str, str):
                        dt_obj = datetime.fromisoformat(exp_date_str.replace('Z', '+00:00'))
                        doc_item['expiration_date_sortable'] = dt_obj
                    elif isinstance(exp_date_str, datetime):
                         doc_item['expiration_date_sortable'] = exp_date_str
                    else: # Si no es string ni datetime, no se puede ordenar confiablemente
                        doc_item['expiration_date_sortable'] = datetime.max # Poner al final
                except ValueError:
                     doc_item['expiration_date_sortable'] = datetime.max # Error de parseo, poner al final
            else:
                doc_item['expiration_date_sortable'] = datetime.max

        docs.sort(key=lambda x:x.get('expiration_date_sortable'))
        crit_docs=docs[:limit_val]
        
        for doc_item in crit_docs: # Limpiar el campo temporal
            if 'expiration_date_sortable' in doc_item:
                del doc_item['expiration_date_sortable']

        return {'statusCode':200,'headers':add_cors_headers({'Content-Type':'application/json'}),'body':json.dumps({'critical_documents':crit_docs,'count':len(crit_docs),'total_found':len(docs)},cls=DecimalEncoder)}
    except Exception as e: 
        logger.error(f"Err get_critical_documents_api_version: {str(e)}")
        return {'statusCode':500,'headers':add_cors_headers({'Content-Type':'application/json'}),'body':json.dumps({'error':str(e)})}

def get_trends_stats_api_version(event, context):
    try:
        tenant_id = extract_tenant_id(event)
        if not tenant_id: return {'statusCode':400,'headers':add_cors_headers({'Content-Type':'application/json'}),'body':json.dumps({'error':'No se pudo determinar tenant_id'})}
        
        q_params=event.get('queryStringParameters',{})or{};metric=q_params.get('metric','documents');period=q_params.get('period','month')
        stats=get_time_series_stats(tenant_id,metric,period)
        
        return {'statusCode':200,'headers':add_cors_headers({'Content-Type':'application/json'}),'body':json.dumps(stats,cls=DecimalEncoder)}
    except Exception as e: 
        logger.error(f"Err get_trends_stats_api_version: {str(e)}")
        return {'statusCode':500,'headers':add_cors_headers({'Content-Type':'application/json'}),'body':json.dumps({'error':str(e)})}

def get_key_dates_api_version(event, context):
    try:
        tenant_id = extract_tenant_id(event)
        if not tenant_id: return {'statusCode':400,'headers':add_cors_headers({'Content-Type':'application/json'}),'body':json.dumps({'error':'No se pudo determinar tenant_id'})}
        
        q_params=event.get('queryStringParameters',{})or{};days_param=int(q_params.get('days',30));limit_param=int(q_params.get('limit',10)) # Renombrar days, limit
        today,future_d_str=datetime.now(),(datetime.now()+timedelta(days=days_param)).isoformat();today_s_str=today.isoformat();k_dates_list=[]
        
        res=contracts_table.scan(
            FilterExpression="tenant_id=:t AND #st<>:del AND attribute_exists(expiration_date) AND expiration_date BETWEEN :today AND :future", 
            ExpressionAttributeValues={':t':tenant_id,':del':'deleted',':today':today_s_str,':future':future_d_str}, 
            ExpressionAttributeNames={'#st':'status'}
        )
        for d_item in res.get('Items',[]): # Renombrar d a d_item
            if d_item.get('expiration_date'):
                try: 
                    exp_dt=datetime.fromisoformat(d_item['expiration_date'].replace('Z','+00:00'));days_rem=(exp_dt-today).days
                    k_dates_list.append({'document_id':d_item.get('id'),'document_name':d_item.get('filename','N/A'),'date_type':'expiration','date':d_item['expiration_date'],'days_remaining':days_rem,'description':f"Vence: {d_item.get('filename','N/A')}"})
                except ValueError: pass
        
        k_dates_list.sort(key=lambda x:x.get('days_remaining',float('inf')));k_dates_list=k_dates_list[:limit_param]
        return {'statusCode':200,'headers':add_cors_headers({'Content-Type':'application/json'}),'body':json.dumps({'key_dates':k_dates_list,'count':len(k_dates_list)},cls=DecimalEncoder)}
    except Exception as e: 
        logger.error(f"Err get_key_dates_api_version: {str(e)}")
        return {'statusCode':500,'headers':add_cors_headers({'Content-Type':'application/json'}),'body':json.dumps({'error':str(e)})}

def get_risk_stats_api_version(event, context): # Placeholder
    try:
        tenant_id = extract_tenant_id(event)
        # if not tenant_id: return {'statusCode':400, 'headers': add_cors_headers({'Content-Type': 'application/json'}), 'body': json.dumps({'error': 'No se pudo determinar tenant_id'})}
        stats={'tenant_id':tenant_id,'risk_score':75,'critical_risks':[{'id':'r1','desc':'Vence X'}],'medium_risks':[{'id':'r2','desc':'Falta Y'}]}
        return {'statusCode':200,'headers':add_cors_headers({'Content-Type':'application/json'}),'body':json.dumps(stats,cls=DecimalEncoder)}
    except Exception as e: 
        logger.error(f"Err get_risk_stats_api_version: {str(e)}")
        return {'statusCode':500,'headers':add_cors_headers({'Content-Type':'application/json'}),'body':json.dumps({'error':str(e)})}

# --- Funciones originales de stats_manager.py que se mantienen --- 

def get_alert_stats_manager_version(event, context):
    try:
        tenant_id = extract_tenant_id(event)
        if not tenant_id: return {'statusCode': 400, 'headers': add_cors_headers({'Content-Type': 'application/json'}), 'body': json.dumps({'error': 'No se pudo determinar tenant_id'})}
        alert_summary = get_alert_summary_data_manager_helper(tenant_id)
        return {'statusCode': 200, 'headers': add_cors_headers({'Content-Type': 'application/json'}), 'body': json.dumps({'statistics': alert_summary}, cls=DecimalEncoder)}
    except Exception as e:
        logger.error(f"Error en get_alert_stats_manager_version: {str(e)}")
        return {'statusCode': 500, 'headers': add_cors_headers({'Content-Type': 'application/json'}), 'body': json.dumps({'error': f"Error interno: {str(e)}"}) }

def get_alert_summary_data_manager_helper(tenant_id):
    try:
        response = alerts_table.scan(FilterExpression="tenant_id = :t", ExpressionAttributeValues={':t': tenant_id})
        alerts = response.get('Items', [])
        total_alerts=len(alerts);sev_counts={'critical':0,'high':0,'medium':0,'low':0,'info':0};st_counts={'new':0,'acknowledged':0,'resolved':0,'dismissed':0};last_7=0;now=datetime.now()
        for alert in alerts:
            sev=alert.get('severity');st=alert.get('status');
            if sev in sev_counts:sev_counts[sev]+=1
            if st in st_counts:st_counts[st]+=1
            try:
                cat_s=alert.get('created_at','');
                if cat_s:cat_dt=datetime.fromisoformat(cat_s.replace('Z','+00:00'));
                if(now-cat_dt).days<=7:last_7+=1
            except ValueError:pass
        return {'total':total_alerts,'unresolved':st_counts['new']+st_counts['acknowledged'],'by_severity':sev_counts,'by_status':st_counts,'last_7_days':last_7}
    except Exception as e:
        logger.error(f"Error en get_alert_summary_data_manager_helper: {str(e)}")
        return {'total':0,'unresolved':0,'by_severity':{},'by_status':{},'last_7_days':0,'error':str(e)}