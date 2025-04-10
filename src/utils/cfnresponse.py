# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

import json
import urllib.request
import urllib.parse
import logging

logger = logging.getLogger()
logger.setLevel(logging.INFO)

SUCCESS = "SUCCESS"
FAILED = "FAILED"

def send(event, context, responseStatus, responseData, physicalResourceId=None, noEcho=False, reason=None):
    """
    Envía una respuesta al recurso personalizado de CloudFormation
    """
    responseUrl = event['ResponseURL']

    logger.info(f"URL de respuesta: {responseUrl}")

    responseBody = {
        'Status': responseStatus,
        'Reason': reason or f"Ver CloudWatch Logs: {context.log_stream_name}",
        'PhysicalResourceId': physicalResourceId or context.log_stream_name,
        'StackId': event['StackId'],
        'RequestId': event['RequestId'],
        'LogicalResourceId': event['LogicalResourceId'],
        'NoEcho': noEcho,
        'Data': responseData
    }

    json_responseBody = json.dumps(responseBody)

    logger.info(f"Cuerpo de respuesta: {json_responseBody}")

    headers = {
        'content-type': '',
        'content-length': str(len(json_responseBody))
    }

    try:
        req = urllib.request.Request(responseUrl,
                                     data=json_responseBody.encode('utf-8'),
                                     headers=headers,
                                     method='PUT')
        response = urllib.request.urlopen(req)
        logger.info(f"Código de estado: {response.getcode()}")
        logger.info(f"Mensaje de estado: {response.msg}")
        return True
    except Exception as e:
        logger.error(f"Error enviando respuesta: {str(e)}")
        return False