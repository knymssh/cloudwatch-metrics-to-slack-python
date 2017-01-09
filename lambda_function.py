# -*- coding: utf-8 -*-

'''
Follow these steps to configure the webhook in Slack:

  1. Navigate to https://<your-team-domain>.slack.com/services/new

  2. Search for and select "Incoming WebHooks".

  3. Choose the default channel where messages will be sent and click "Add Incoming WebHooks Integration".

  4. Copy the webhook URL from the setup instructions and use it in the next section.

To encrypt your secrets use the following steps:

  1. Create or use an existing KMS Key - http://docs.aws.amazon.com/kms/latest/developerguide/create-keys.html

  2. Click the "Enable Encryption Helpers" checkbox

  3. Paste <SLACK_HOOK_URL> into the kmsEncryptedHookUrl environment variable and click encrypt

  Note: You must exclude the protocol from the URL (e.g. "hooks.slack.com/services/abc123").

  4. Give your function's role permission for the kms:Decrypt action.

     Example:

{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "Stmt1443036478000",
            "Effect": "Allow",
            "Action": [
                "kms:Decrypt"
            ],
            "Resource": [
                "<your KMS key ARN>"
            ]
        }
    ]
}
'''
from __future__ import print_function

import datetime
import json
import logging
import os
import pprint

from base64 import b64decode
from urllib2 import Request, urlopen, URLError, HTTPError

import boto3

# The base-64 encoded, encrypted key (CiphertextBlob) stored in the kmsEncryptedHookUrl environment variable
ENCRYPTED_HOOK_URL = os.environ['kmsEncryptedHookUrl']
# The Slack channel to send a message to stored in the slackChannel environment variable
SLACK_CHANNEL = os.environ['slackChannel']

HOOK_URL = "https://" + boto3.client('kms').decrypt(
    CiphertextBlob=b64decode(ENCRYPTED_HOOK_URL))['Plaintext']

logger = logging.getLogger()
logger.setLevel(logging.INFO)

REGION_NAME = 'ap-northeast-1'

cloud_watch = boto3.client('cloudwatch', region_name=REGION_NAME)
s3 = boto3.resource('s3')

pp = pprint.PrettyPrinter(indent=4)

def post_message(text):
    slack_message = {
        'channel': SLACK_CHANNEL,
        'text': text
    }
    req = Request(HOOK_URL, json.dumps(slack_message))
    try:
        response = urlopen(req)
        response.read()
        logger.info("Message posted to %s", slack_message['channel'])
    except HTTPError as e:
        logger.error("Request failed: %d %s", e.code, e.reason)
    except URLError as e:
        logger.error("Server connection failed: %s", e.reason)

def get_list_metrics():
    result = []
    next_token = None
    while True:
        if next_token is None:
            list_metrics = cloud_watch.list_metrics(
                #Namespace=name_space,
                #MetricName=metric_name
                #Dimensions=dimensions
            )
        else:
            list_metrics = cloud_watch.list_metrics(
                #Namespace=name_space,
                #MetricName=metric_name,
                #Dimensions=dimensions,
                NextToken=list_metrics['NextToken']
            )
        for i in range(len(list_metrics['Metrics'])):
            p_name_space = list_metrics['Metrics'][i]['Namespace']
            p_metric_name = list_metrics['Metrics'][i]['MetricName']
            p_dimension_name = ''
            p_dimension_value = ''
            for dimension in list_metrics['Metrics'][i]['Dimensions']:
                p_dimension_name = dimension['Name']
                p_dimension_value = dimension['Value']
            result.append({
                "Namespace": p_name_space,
                "Metricname": p_metric_name,
                "Dimensions": {
                    "Name": p_dimension_name,
                    "Value": p_dimension_value
                }
            })
        if 'NextToken' in list_metrics:
            next_token = list_metrics['NextToken']
        else:
            break
    return result

SUPPORT_DIMENTION = {
    'AWS/Lambda': 'FunctionName',
    'AWS/ApiGateway': 'ApiName',
    'AWS/CloudFront': 'DistributionId'
}

SUPPORT_METRICS = {
    'AWS/Lambda': [
        'Invocations',
        'Errors',
        'Throttles'
    ],
    'AWS/ApiGateway': [
        '4XXError',
        '5XXError'
    ],
    'AWS/CloudFront': [
        '4xxErrorRate',
        '5xxErrorRate'
    ]
}

def get_targets():
    json_src = """
    [
        {
            "Namespace": "AWS/Lambda",
            "FunctionName": "cloudwatch-metrics-to-slack"
        },
        {
            "Namespace": "AWS/ApiGateway",
            "ApiName": "phonecat"
        },
        {
            "Namespace": "AWS/CloudFront",
            "DistributionId": "E2F78R29BHCFHE"
        }
    ]
    """
    return json.loads(json_src)

def get_metrics_statistics(targets, start, end):
    results = []
    for target in targets:
        # Namespace
        name_space = target['Namespace']
        if name_space not in SUPPORT_METRICS:
            continue
        # Metricname
        metric_names = SUPPORT_METRICS[name_space]
        # Dimension
        if name_space not in SUPPORT_DIMENTION:
            continue
        dimension_name = SUPPORT_DIMENTION[name_space]
        if dimension_name not in target:
            continue
        dimension_value = target[dimension_name]
        # Get metrics statistics
        for metric_name in metric_names:
            metric = cloud_watch.get_metric_statistics(
                Namespace=name_space,
                MetricName=metric_name,
                Dimensions=[
                    {
                        'Name': dimension_name,
                        'Value': dimension_value
                    }
                ],
                StartTime=start,
                EndTime=end,
                Period=60,
                Statistics=['SampleCount', 'Average', 'Sum', 'Minimum', 'Maximum'])
            results.append({
                #"Label": metric['Label'],
                "Namespace": name_space,
                "MetricName": metric_name,
                "Dimensions": {
                    "Name": dimension_name,
                    "Value": dimension_value
                },
                "Datapoints": {
                    "SampleCount": metric['Datapoints'][0]['SampleCount'] if len(metric['Datapoints']) > 0 else 0,
                    "Average": metric['Datapoints'][0]['Average'] if len(metric['Datapoints']) > 0 else 0,
                    "Sum": metric['Datapoints'][0]['Sum'] if len(metric['Datapoints']) > 0 else 0,
                    "Minimum": metric['Datapoints'][0]['Minimum'] if len(metric['Datapoints']) > 0 else 0,
                    "Maximum": metric['Datapoints'][0]['Maximum'] if len(metric['Datapoints']) > 0 else 0,
                    "Unit": metric['Datapoints'][0]['Unit'] if len(metric['Datapoints']) > 0 else 0,
                    "Timestamp": metric['Datapoints'][0]['Timestamp'].strftime("%Y/%m/%d %H:%M:%S") if len(metric['Datapoints']) > 0 else 0
                }
            })
    
    return results

def lambda_handler(event, context):
    logger.info("Event: " + str(event))
    '''
    message = json.loads(event['Records'][0]['Sns']['Message'])
    logger.info("Message: " + str(message))

    alarm_name = message['AlarmName']
    #old_state = message['OldStateValue']
    new_state = message['NewStateValue']
    reason = message['NewStateReason']

    text = "%s state is now %s: %s" % (alarm_name, new_state, reason)
    post_message(text)
    '''

    end_time = datetime.datetime.utcnow()
    start_time = end_time - datetime.timedelta(seconds=300)
    
    metrics = get_list_metrics()
    logger.info("Metrics: "+json.dumps(metrics))
    
    targets = get_targets()
    logger.info("Targets: "+json.dumps(targets))
    statistics = get_metrics_statistics(targets, start_time, end_time)
    logger.info("Results: "+json.dumps(statistics))
    #pp.pprint(statistics)
