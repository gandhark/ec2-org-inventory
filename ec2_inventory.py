#!/usr/bin/env python
import itertools
import sys
import pprint
import csv
from array import *


import logging
import boto3
import json
import datetime
import re
import os
import pandas as pd
from botocore.exceptions import ClientError

## used from sg public report
role_name="reporting-lambda-assume-role"
bucket="reporting-ec2-inventory"
region="eu-west-1"
err = ["888888888888"]

#table_name = 'gk-demo-ec2-inventory'
file_name_postfix = datetime.datetime.now().strftime("%Y-%m-%d-%H-%M-%S")
report_file_name_json = f"EC2_inventory_Report-{file_name_postfix}.json"


def get_account_numbers_ddb(table_name):
    ddb_client = boto3.client('dynamodb',region)

    try:
        response = ddb_client.scan(TableName=table_name)
        accounts = []
        if "root" in table_name:
            for each_item in response['Items']:
                dict = {}
                if each_item['AccountID']['N'] not in err:
                #if each_item['AccountID']['N']  in err:

                    if len(each_item['AccountID']['N']) > 1:
                        if len(each_item['AccountID']['N']) == 10:
                            dict['Accounts'] = "00{0}".format(each_item['AccountID']['N'])
                        elif len(each_item['AccountID']['N']) == 11:
                            dict['Accounts'] = "0{0}".format(each_item['AccountID']['N'])
                        else:
                            dict['Accounts'] = each_item['AccountID']['N']
                        dict['Regions'] =  each_item['Active_Regions']['L']
                        accounts.append(dict)
        else:
            for each_item in response['Items']:
                dict = {}
                if each_item['AccountID']['S'] not in err:
                    if len(each_item['AccountID']['S']) == 12:
                        dict['Accounts'] = each_item['AccountID']['S']
                        dict['Regions'] =  each_item['Active_Regions']['L']
                        accounts.append(dict)
        return accounts
    except Exception as e:
        print(f'ERROR :: Get Account Numbers Error: {e}')
        return e


def get_account_name(account_number):
    org_client = boto3.client('organizations')
    try:
        response = org_client.describe_account(AccountId=account_number)
        logging.info(response['Account']['Name'])
        return response['Account']['Name']
    except Exception as e:
        print(f'ERROR :: Get Account Name Error: {e}')
        return None




def assume_role(account_number, role_name, region):
    """
    Assumes the provided role in each account and returns a SecurityHub client
    :param account_number: AWS Account Number
    :param role_name: Role to assume in target account
    :return: Session object for assume role in the specified AWS Account
    """

    # Beginning the assume role process for account
    sts_client = boto3.client('sts')

    # Get the current partition
    partition = sts_client.get_caller_identity()['Arn'].split(":")[1]

    try:
        response = sts_client.assume_role(
            RoleArn='arn:{}:iam::{}:role/{}'.format(
                partition,
                account_number,
                role_name
            ),
            RoleSessionName='EnableSecurityHub'
        )

    except sts_client.exceptions.MalformedPolicyDocumentException as e:
        print(f'{e}')
        # logging.info('Error : {}'.format(e))
        response = None
    except sts_client.exceptions.PackedPolicyTooLargeException as e:
        print(f'{e}')
        # logging.info('Error : {}'.format(e))
        response = None
    except sts_client.exceptions.RegionDisabledException as e:
        print(f'{e}')
        # logging.info('Error : {}'.format(e))
        response = None
    except sts_client.exceptions.ExpiredTokenException as e:
        print(f'{e}')
        # logging.info('Error : {}'.format(e))
        response = None
    except Exception as e:
        print(f'{e}')
        # logging.info('Error : {}'.format(e))
        response = None

    # Storing STS credentials
    if response != None:
        try:
            session = boto3.Session(
                aws_access_key_id=response['Credentials']['AccessKeyId'],
                aws_secret_access_key=response['Credentials']['SecretAccessKey'],
                aws_session_token=response['Credentials']['SessionToken'],
                region_name=region
            )
        except Exception as e:
            print('ERROR :: Error in creating session : {}'.format(e))
            logging.info('Error in creating session : {}'.format(e))
            return None
        return session
    else:
        return None


"""
# Assume shared-service account IAM role
sts_connection = boto3.client('sts')
IAM_ROLE = "arn:aws:iam::{}:role/OrganizationAccountAccessRole".format(account_id)
assume_role_object = sts_connection.assume_role(RoleArn=IAM_ROLE, RoleSessionName="Ec2_Inventory", DurationSeconds=3600)
session = boto3.Session(
aws_access_key_id=assume_role_object['Credentials']['AccessKeyId'],
aws_secret_access_key=assume_role_object['Credentials']['SecretAccessKey'],
aws_session_token=assume_role_object['Credentials']['SessionToken'])
# List Transit Gateway VPC attachments of Child Accounts
#ec2_client = session.client('ec2')
"""


def get_value_for_tag_key(tags,key):
    print('@@@@@@@@@@@@@@@@@@@@@@@')

    for tag in tags:
        #print(tag)
        if tag["Key"] == str(key):
           print(tag["Value"])
           return tag["Value"]

    #print(tags)
    #val = [ sub[key] for sub in tags if key in tags ]
    #print(str(val))





    #print([d[key] for d in tags if key in d])




def get_account_numbers():
    org_client = boto3.client('organizations')
    sts_client = boto3.client('sts')

    paginator = org_client.get_paginator('list_accounts')
    account_iterator = paginator.paginate()

    account_list = []
    for accounts_itr in account_iterator:
        for account in accounts_itr['Accounts']:
            #print(json.dumps( account, indent=4, sort_keys=True, default=str))
            if account['Status'] == 'ACTIVE':
               #account_list[ account['Id'] ] = {'Name' : account['Name'], 'Email': account['Email']}
               account_list.append(account['Id'])

    #print(json.dumps(account_list,  indent=4, sort_keys=True, default=str))
    return account_list

def get_resource_obj(resource, session, region):
    '''
    return boto3 client object of resource
    '''
    return session.client(resource, region_name = region)

def get_ec2_details(account_number,account_region,ec2):
    ec2_details = []
    print( "yupppppppppppppp" + account_number)
    session_var = assume_role(account_number, role_name, account_region)
    ec2_instances=[]
    #resource=session.resource(service_name="ec2") #Create a resource service client by name
    print("List of EC2 Instances from the region:")
    response=ec2.describe_instances()
    #print(response)
    #instance1={}
    for each_in in response['Reservations']:
        instance1={}
        for instance in each_in['Instances']:

            if instance["State"]["Name"] == "terminated":
                privateIp = "NA"
                vpcId = "NA"
            else:
                privateIp = instance['PrivateIpAddress']
                vpcId = instance['VpcId']


            if "Tags" in instance:
               account_name = get_value_for_tag_key(instance['Tags'],'Account_Name')
               application  = get_value_for_tag_key(instance['Tags'],'Application')
               name         = get_value_for_tag_key(instance['Tags'],'Name')
               backup       = get_value_for_tag_key(instance['Tags'],'Backup')
               patch_group  = get_value_for_tag_key(instance['Tags'],'Patch Group')
               os_name      = get_value_for_tag_key(instance['Tags'],'OS_Name')
               os_version   = get_value_for_tag_key(instance['Tags'],'OS_Version')
            else:
               account_name = "not added"
               application  = "not added"
               name         = "not added"
               backup       = "not added"
               patch_group  = "not added"
               os_name      = "not added"
               os_version   = "not added"


            #print(instance)
            print('##################################')
            print(json.dumps(instance, indent=4, sort_keys=True, default=str))
            print('##################################')
            instance1['account_number'] = account_number
            instance1['private_ip'] = privateIp
            instance1['AMIid'] = instance['ImageId']
            instance1['InstanceId'] = instance['InstanceId']
            instance1['state'] = instance["State"]["Name"]
            instance1['InstanceType'] = instance['InstanceType']
            instance1['Platform'] = instance['PlatformDetails']
            instance1['Application'] = application
            instance1['account_name'] = account_name
            instance1['Name'] = name
            instance1['region'] = account_region
            instance1['vpcid'] = vpcId
            instance1['Backup'] = backup
            instance1['Patch Group'] = patch_group
            instance1['OS_Name'] = os_name
            instance1['OS_Version']  = os_version

            #instance1['env_type'] = env_type
            ec2_instances.append(instance1)
            print('########### ec2 list #######################')
            print(json.dumps(ec2_instances, indent=4, sort_keys=True, default=str ))
            print('############ ec2 list ######################')


    #ec2_details.append(describe_ec2_instances)
    return ec2_instances



def send_notifications(URL,report_bucket,environment):   

    try:
        
        topic_arn = "arn:aws:sns:eu-west-1:88888888888:support-notification"
        message = f"Hi Team, \n\t Please find below S3 file path for ec2 inventory report in aws-org-uk account  : \n\n s3://{report_bucket}/{URL}"
        subject = f"ec2 inventory report {environment} | Date : {datetime.datetime.now().strftime('%Y-%m-%d')}"
        sns_client.publish(TopicArn=topic_arn, Message=message, Subject=subject)
        print("INFO :: Notification sent successfuly.")

    except Exception as e:
        print(f"ERROR :: Failed to send notifications ,{e}")



def put_file_to_s3(file_name, bucket, environment):
    s3_client = boto3.client('s3')
    object_name = None
    dt = datetime.datetime.today()

    # If S3 object_name was not specified, use file_name
    if object_name is None:
        object_name = os.path.basename(file_name)

    s3_path_report = 'year_' + str(dt.year) + '/' + 'month_' + str(dt.month) + '/' + 'day_' + str(dt.day) + '/' + object_name

    # Upload the file
    try:
        s3_client.upload_file(file_name, bucket, s3_path_report)
        send_notifications(s3_path_report,bucket,environment)
    except ClientError as e:
        logging.error(e)
        return False
    return True


def lambda_handler(event, context):

    environment = event["environment"]
    file_name_postfix = datetime.datetime.now().strftime("%Y-%m-%d-%H-%M-%S")
    report_file_name_json = f"EC2_inventory_Report-{file_name_postfix}.json"
    print("INFO :: Start of Report")
    try:
        if environment == "prod":
             table_name = "prod-control-tower-inventory"
             report_file_name_csv = f"CT-Prod_EC2_inventory_Report-{file_name_postfix}.csv"

        elif environment == "nonprod":
             table_name = "nonprod-control-tower-inventory"
             report_file_name_csv = f"CT-NonProd_EC2_inventory_Report-{file_name_postfix}.csv"

        elif environment == "lz-prod":
             table_name = "prod-root-inventory"
             report_file_name_csv = f"LZ-Prod_EC2_inventory_Report-{file_name_postfix}.csv"

        elif environment == "lz-nonprod":
             table_name = "nonprod-root-inventory"
             report_file_name_csv = f"LZ-NonProd_EC2_inventory_Report-{file_name_postfix}.csv"

        else:
            print("ERROR :: Environment not found")
            exit(1)   



        results=[]
        accounts = get_account_numbers_ddb(table_name)

        for each_account in accounts:
            for each_region in each_account['Regions']:
                account_num = each_account['Accounts']
                account_region = each_region['S']
                print("INFO :: Account %s in Region %s" % (account_num,account_region))
                session_var = assume_role(account_num,role_name,account_region)
                if session_var != None:
                    ec2_obj = get_resource_obj('ec2', session_var,account_region)
                    ec2_result=get_ec2_details(account_num,account_region,ec2_obj)

                    for each_result in ec2_result:
                        results.append(each_result)
                        #print(results)

        data = []
        print(results)
        for result in results:
            data.append(result)

        print(data)


        #report_file_name_csv='gk-inv'
        print("INFO :: Dumping to json file to ",report_file_name_json)
        with open("/tmp/"+ report_file_name_json, "w") as outfile:
            json.dump(data, outfile)
        df = pd.read_json("/tmp/"+ report_file_name_json)
        print("INFO :: Converting to csv...")
        df.to_csv("/tmp/"+ report_file_name_csv, index = None)

        print('INFO :: Saving Report')
        if put_file_to_s3( "/tmp/"+ report_file_name_csv, bucket, environment):
            print(f'INFO :: EC2 inventory report successfully uploaded to s3')
            table_name = ""
            report_file_name_csv = ""
        else:
            print(f'ERROR :: Error in uploading EC2 inventory report to s3')
            table_name = ""
            report_file_name_csv = ""
            exit(1)
        table_name = ""
        report_file_name_csv = ""
    except Exception as e:
        print(f'ERROR :: Handler Error: {e}')
        return e
