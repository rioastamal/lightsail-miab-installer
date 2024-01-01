#!/bin/sh
#
# @author Rio Astamal <rio@rioastamal.net>
# @desc Script to automate Open Source mail server package Mail-in-a-Box on
#       a single Amazon Lightsail instance

readonly LMIAB_SCRIPT_NAME=$( basename "$0" )
LMIAB_BASEDIR=$( cd -P -- "$( dirname "$0" )" && pwd -P )
LMIAB_VERSION="1.0"
LC_CTYPE="C"

# Path to directory to store application outputs
LMIAB_OUTPUT_DIR="$LMIAB_BASEDIR/.out"
LMIAB_CACHE_DIR="$LMIAB_OUTPUT_DIR/caches"

# Default config
# --------------
[ -z "$LMIAB_CLOUDFORMATION_STACKNAME_PREFIX" ] && LMIAB_CLOUDFORMATION_STACKNAME_PREFIX="miab"
[ -z "$LMIAB_NODE_PREFIX" ] && LMIAB_NODE_PREFIX="miab"
[ -z "$LMIAB_SSH_LIGHTSAIL_KEYPAIR_NAME" ] && LMIAB_SSH_LIGHTSAIL_KEYPAIR_NAME="id_rsa"
[ -z "$LMIAB_SSH_PRIVATE_KEY_FILE" ] && LMIAB_SSH_PRIVATE_KEY_FILE="$HOME/.ssh/id_rsa"
[ -z "$LMIAB_FIREWALL_SSH_ALLOW_CIDR" ] && LMIAB_FIREWALL_SSH_ALLOW_CIDR="0.0.0.0/0"
[ -z "$LMIAB_DRY_RUN" ] && LMIAB_DRY_RUN="no"
[ -z "$LMIAB_AZ" ] && LMIAB_AZ="us-east-1a"
[ -z "$LMIAB_PLAN" ] && LMIAB_PLAN="5_usd"
[ -z "$LMIAB_DEBUG" ] && LMIAB_DEBUG="true"
[ -z "$LMIAB_IS_RESTORE" ] && LMIAB_IS_RESTORE="no"
[ -z "$LMIAB_PACKAGE_URL" ] && LMIAB_PACKAGE_URL="https://github.com/mail-in-a-box/mailinabox/archive/refs/tags/v67.tar.gz"
[ -z "$LMIAB_SMTP_RELAY_ENDPOINT" ] && LMIAB_SMTP_RELAY_ENDPOINT=""
[ -z "$LMIAB_SMTP_RELAY_PORT" ] && LMIAB_SMTP_RELAY_PORT="587"
[ -z "$LMIAB_SMTP_RELAY_USER" ] && LMIAB_SMTP_RELAY_USER=""
[ -z "$LMIAB_SMTP_RELAY_PASSWORD" ] && LMIAB_SMTP_RELAY_PASSWORD=""
[ -z "$LMIAB_ADMIN_EMAIL" ] && LMIAB_ADMIN_EMAIL=""
[ -z "$LMIAB_EMAIL_DOMAIN" ] && LMIAB_EMAIL_DOMAIN=""
[ -z "$LMIAB_ADMIN_PASSWORD" ] && LMIAB_ADMIN_PASSWORD=""
[ -z "$LMIAB_BOX_HOSTNAME" ] && LMIAB_BOX_HOSTNAME=""

[ -z "$LMIAB_DISABLE_SMTP_RELAY" ] && LMIAB_DISABLE_SMTP_RELAY="no"
[ -z "$LMIAB_DISABLE_S3_BACKUP" ] && LMIAB_DISABLE_S3_BACKUP="no"

[ -z "$LMIAB_MAIL_BACKUP_BUCKET" ] && LMIAB_MAIL_BACKUP_BUCKET=""
[ -z "$LMIAB_NEXTCLOUD_BACKUP_BUCKET" ] && LMIAB_NEXTCLOUD_BACKUP_BUCKET=""

# See all available OS/Blueprint ID using: `aws lightsail get-blueprints`
# Only Ubuntu 22.04 is supported at the moment.
LMIAB_NODE_OS_ID="ubuntu_22_04"
LMIAB_OS_USERNAME="ubuntu"

# Required tools to perform tasks
LMIAB_REQUIRED_TOOLS="awk aws base64 cat cut date jq openssl sed ssh tee tr wc"

# WARNING! Undocumented flag for destroying all resources
# Only can be activated by --destroy-all-resources flag
LMIAB_DESTROY_ALL_RESOURCES="no"
# Environment below only used in conjunction with LMIAB_DESTROY_ALL_RESOURCES
[ -z "$LMIAB_DELETE_S3_BUCKET" ] && LMIAB_DELETE_S3_BUCKET="yes"

# In memory cache
LMIAB_CACHE_NODE_PUBLIC_IP=""

# Function to show the help message
lmiab_help()
{
    echo "\
Usage: $0 [OPTIONS]

Where OPTIONS:
  --az AZ                 Instance availability zone specified by AZ. Default to
                          'us-east-1a'.
  --destroy               Destroy installation specified by --installation-id.
  --disable-s3-backup     Do not configure Mail-in-a-Box to backup mailserver
                          data to Amazon S3.
  --disable-smtp-relay    Do not configure Postfix to use Amazon SES as SMTP 
                          relay.
  --dry-run               Dry run mode, print CloudFormation template and exit.
  --email EMAIL           Mail-in-a-Box administrator email specified by EMAIL.
                          An example 'admin@example.com'.
  --help                  Print this help and exit.
  --hostname HOSTNAME     Mail-in-a-Box primary hostname specified by HOSTNAME.
                          An example 'box.example.com'.
  --installation-id ID    Installation identifier by ID, e.g 'demo'.
  --instance-type TYPE    Amazon Lightsail plan specified by TYPE. Valid value:
                          '5_usd', '10_usd', '20_usd', '40_usd', '80_usd', or 
                          '160_usd'. Default is '5_usd'.
  --password PASSWD       Mail-in-a-Box administrator password specified by 
                          PASSWD.
  --restore               Restore installation data from backup which stored on
                          S3 bucket. See --restore-help for more info.
  --restore-help          Print help information how to restore from backup.
  --version               Print script version.

--------------------------- lightsail-miab-installer ---------------------------

lightsail-miab-installer is a powerful command line tool powered by 
Mail-in-a-Box, designed to simplify the setup of a complete mail server on 
Amazon Lightsail.

lightsail-miab-installer is free software licensed under MIT. Visit the project 
homepage at http://github.com/rioastamal/lightsail-miab-installer."
}

lmiab_restore_help()
{
  echo "\
In order to restore Mail-in-a-Box data from previous installation you need to
set several environment variables.

LMIAB_MAIL_BACKUP_BUCKET=
  S3 bucket name which stores mail backup from previous installation.
  
LMIAB_NEXTCLOUD_BACKUP_BUCKET=
  S3 Bucket name which stores Nextcloud backup from previous installation.

LMIAB_BACKUP_SECRET_KEY=
  Mail-in-a-Box backup secret key from previous installation, which you can find 
  it at /home/user-data/backup/secret_key.txt or via AWS System Manager 
  Parameter Stores."
}

lmiab_write_log()
{
  _LOG_MESSAGE="$@"
  _SYSLOG_DATE_STYLE="$( date +"%b %e %H:%M:%S" )"

  # Date Hostname AppName[PID]: MESSAGE
  printf "[%s LMIAB]: %s\n" \
    "$_SYSLOG_DATE_STYLE" \
    "${_LOG_MESSAGE}">> "$LMIAB_LOG_FILE"
}

lmiab_log()
{
  [ "$LMIAB_DEBUG" = "true" ] && printf "[LMIAB]: %s\n" "$@"
  lmiab_write_log "$@"
}

lmiab_log_waiting()
{
  [ "$LMIAB_DEBUG" = "true" ] && printf "\r[LMIAB]: %s\033[K" "$@"
  lmiab_write_log "$@"
}

lmiab_err() {
  printf "[LMIAB ERROR]: %s\n" "$@" >&2
  lmiab_write_log "$@"
}

lmiab_missing_tool()
{
  for tool in $( echo "$LMIAB_REQUIRED_TOOLS" )
  do
    command -v $tool >/dev/null || {
      echo "$tool"
      return 1
    }
  done
  
  echo ""
  return 0
}

lmiab_is_ssh_keypair_valid()
{
  aws lightsail get-key-pair --key-pair-name $LMIAB_SSH_LIGHTSAIL_KEYPAIR_NAME >/dev/null 2>/dev/null || {
    lmiab_err "Can not find SSH key pair '$LMIAB_SSH_LIGHTSAIL_KEYPAIR_NAME' in region $LMIAB_REGION"
    return 1
  }
  
  return 0
}

lmiab_gen_random_chars()
{
  local _LENGTH=$1
  tr -dc 'a-z0-9' </dev/urandom | head -c $_LENGTH; echo
  
  return 0
}

lmiab_sign_hmac_sha256()
{
  while [ $# -gt 0 ]; do
    case $1 in
      # --key) local _KEY="$( echo -n "$2" | base64 -d -i )"; shift ;;
      --key) local _KEY="$( echo -n "$2" | sed 's/[^A-Za-z0-9+/=]//g' | base64 -d | xxd -p | tr -d '\n' )"; shift ;;
      --message) local _MESSAGE="$2"; shift ;;
      *) echo "Unrecognised option passed: $1" 2>&2; return 1;;
    esac
    shift
  done
  
  echo -n "$_MESSAGE" | openssl dgst -sha256 -mac HMAC -macopt hexkey:"$_KEY" -binary && return 0
  
  return 1
}

lmiab_iam_key_to_ses_credentials()
{
  while [ $# -gt 0 ]; do
    case $1 in
      --secret-key) local _SECRET_KEY="$2"; shift ;;
      --region) local _REGION="$2"; shift ;;
      *) echo "Unrecognised option passed: $1" 2>&2; return 1;;
    esac
    shift
  done
  
  # Magic variables for calculating signature
  # See https://docs.aws.amazon.com/ses/latest/dg/smtp-credentials.html
  local _DATE="11111111"
  local _SERVICE="ses"
  local _MESSAGE="SendRawEmail"
  local _TERMINAL="aws4_request"
  local _VERSION="\x04"
  
  local _SIGNATURE="$( lmiab_sign_hmac_sha256 --key "$( echo -n "AWS4${_SECRET_KEY}" | base64 )" --message "$_DATE" | base64 )"
  _SIGNATURE="$( lmiab_sign_hmac_sha256 --key "$_SIGNATURE" --message "$_REGION" | base64 )"
  _SIGNATURE="$( lmiab_sign_hmac_sha256 --key "$_SIGNATURE" --message "$_SERVICE" | base64 )"
  _SIGNATURE="$( lmiab_sign_hmac_sha256 --key "$_SIGNATURE" --message "$_TERMINAL" | base64 )"
  _SIGNATURE="$( lmiab_sign_hmac_sha256 --key "$_SIGNATURE" --message "$_MESSAGE" )"
  
  local _SIGNATURE_AND_VERSION=$( printf $_VERSION )
  _SIGNATURE_AND_VERSION="${_SIGNATURE_AND_VERSION}${_SIGNATURE}"
  
  echo -n "$_SIGNATURE_AND_VERSION" | base64
  
  return 0
}

lmiab_get_bundle_ids()
{
  cat <<EOF
{
  "5_usd": "micro_2_0",
  "10_usd": "small_2_0",
  "20_usd": "medium_2_0",
  "40_usd": "large_2_0",
  "80_usd": "xlarge_2_0",
  "160_usd": "2xlarge_2_0"
}
EOF
}

lmiab_is_package_valid()
{
  local _PACKAGE=$1
  (lmiab_get_bundle_ids | jq -r -e ".[\"$_PACKAGE\"]" 2>/dev/null) || return 1
  
  return 0
}

lmiab_get_lightsail_regions()
{
  local _CACHEDATE="$( date +%Y%m%d )"
  local _CACHEFILE="$LMIAB_CACHE_DIR/lightsail-regions-$_CACHEDATE"
  local _REGIONS=""
  
  [ -f "$_CACHEFILE" ] && _REGIONS="$( cat $_CACHEFILE )"
  ( [ ! -f "$_CACHEFILE" ] || [ -z "$_REGIONS" ] ) && {
    _REGIONS="$( aws lightsail get-regions | jq -r '.regions[] | (.name + "\t" + .displayName)' )"
    echo "$_REGIONS" > $_CACHEFILE
  }
  
  echo "$_REGIONS"
  
  return 0
}

lmiab_is_region_valid()
{
  local _REGION_NAME=$1
  local _REGIONS="$( lmiab_get_lightsail_regions 2>/dev/null )"
  local _VALID="false"
  
  for region in $( echo "$_REGIONS" | awk '{print $1}' )
  do
    region="$( echo $region | tr -d '[:space:]' )"
    [ "$region" = "$_REGION_NAME" ] && {
      _VALID="true"
      break
    }
  done
  
  [ "$_VALID" = "false" ] && return 1
  
  return 0
}

lmiab_get_region_az()
{
  local _REGION_NAME=$1
  local _CACHEDATE="$( date +%Y%m%d )"
  local _CACHEFILE="$LMIAB_CACHE_DIR/lightsail-$_REGION_NAME-azs-$_CACHEDATE"
  local _AZ=""
  
  [ -f "$_CACHEFILE" ] && _AZ="$( cat $_CACHEFILE )"
  [ ! -f "$_CACHEFILE" ] && {
    local _AZ="$( aws ec2 describe-availability-zones --region $_REGION_NAME | \
      jq -r '.AvailabilityZones[].ZoneName' )"
    echo "$_AZ" > $_CACHEFILE
  }
  
  echo "$_AZ"
}

lmiab_get_region_display_name()
{
  local _REGION_ID=$1
  local _REGIONS="$( lmiab_get_lightsail_regions 2>/dev/null )"
  
  echo "$_REGIONS" | grep "$_REGION_ID" | awk '{print $2}'
}

lmiab_is_az_valid()
{
  local _REGION=$1
  local _AZ="$2"
  local _AZ_LIST="$( lmiab_get_region_az $_REGION )"
  local _NUMBER_OF_AZ=$( echo "$_AZ" | wc -w | tr -d ' ' )
  local _VALID=0
  
  for our_az in $( echo "$_AZ" )
  do
    our_az="$( echo $our_az | tr -d '[:space:]' )"
    for their_az in $( echo "$_AZ_LIST" )
    do
      their_az="$( echo $their_az | tr -d '[:space:]' )"
      [ "$our_az" = "$their_az" ] && _VALID=$(( $_VALID + 1 ))
    done
  done
  
  [ "$_VALID" = "$_NUMBER_OF_AZ" ] && return 0
  
  return 1
}

lmiab_is_region_and_az_valid()
{
  lmiab_is_region_valid $LMIAB_REGION || {
    echo "[ERROR]: Region is not valid." >&2
    return 1
  }
  
  lmiab_is_az_valid $LMIAB_REGION "$LMIAB_AZ" || {
    echo "[ERROR]: Value of availability zone is not valid." >&2
    return 1
  }
  
  return 0
}

lmiab_char_repeat()
{
  # $1 -> char
  # $2 -> number of repeat
  for i in $( seq 1 $2 )
  do
    printf "%s" "$1"
  done
}

lmiab_cf_template_header()
{
  echo "AWSTemplateFormatVersion: '2010-09-09'"
  
  return 0
}

lmiab_cf_template_node()
{
  while [ $# -gt 0 ]; do
    case $1 in
      --az-id) local _AZ_ID="$2"; shift ;;
      --bundle-id) local _BUNDLE_ID="$2"; shift ;;
      --cf-stackname) local _CF_STACKNAME="$2"; shift ;;
      --installation-id) local _INSTALLATION_ID="$2"; shift ;;
      --instance-name) local _INSTANCE_NAME="$2"; shift ;;
      --keypair-name) local _KEYPAIR_NAME="$2"; shift ;;
      --resource-name) local _RESOURCE_NAME="$2"; shift ;;
      --ssh-allow-cidr) local _SSH_ALLOW_CIDR="$2"; shift ;;
      --node-type) local _NODE_TYPE="$2"; shift ;;
      --os-id) local _OS_ID="$2"; shift ;;
      *) echo "Unrecognised option passed: $1" 2>&2; return 1;;
    esac
    shift
  done
  
  [ -z "$_KEYPAIR_NAME" ] && _KEYPAIR_NAME=$LMIAB_SSH_LIGHTSAIL_KEYPAIR_NAME
  local _NETWORKING_RULES="$(cat <<EOF
        Ports:
          - Protocol: tcp
            FromPort: 22
            ToPort: 22
            Cidrs:
              - $_SSH_ALLOW_CIDR
          # HTTP
          - FromPort: 80
            ToPort: 80
            Protocol: tcp
            Cidrs:
              - 0.0.0.0/0
          # HTTPS
          - FromPort: 443
            ToPort: 443
            Protocol: tcp
            Cidrs:
              - 0.0.0.0/0
          # SMTP (STARTTLS)
          - FromPort: 25
            ToPort: 25
            Protocol: tcp
            Cidrs:
              - 0.0.0.0/0
          # SMTPS
          - FromPort: 465
            ToPort: 465
            Protocol: tcp
            Cidrs:
              - 0.0.0.0/0
          # SMTP Submission
          - FromPort: 587
            ToPort: 587
            Protocol: tcp
            Cidrs:
              - 0.0.0.0/0
          # IMAP (STARTTLS)
          - FromPort: 143
            ToPort: 143
            Protocol: tcp
            Cidrs:
              - 0.0.0.0/0
          # IMAPS
          - FromPort: 993
            ToPort: 993
            Protocol: tcp
            Cidrs:
              - 0.0.0.0/0
          # DNS over TCP
          - FromPort: 53
            ToPort: 53
            Protocol: tcp
            Cidrs:
              - 0.0.0.0/0
          # DNS over UDP
          - FromPort: 53
            ToPort: 53
            Protocol: udp
            Cidrs:
              - 0.0.0.0/0
          # Sieve mail filtering
          - FromPort: 4190
            ToPort: 4190
            Protocol: tcp
            Cidrs:
              - 0.0.0.0/0
EOF
)"

  cat <<EOF
Parameters:
  IsRestoreParam:
    Type: String
    Default: 'no'
    AllowedValues:
      - 'yes'
      - 'no'
Conditions:
  IsNotRestoreCondition: !Equals
    - !Ref IsRestoreParam
    - 'no'
Resources:
  $_RESOURCE_NAME:
    Type: AWS::Lightsail::Instance
    Properties:
      AvailabilityZone: $_AZ_ID
      BlueprintId: $_OS_ID
      BundleId: $_BUNDLE_ID
      KeyPairName: $_KEYPAIR_NAME
      InstanceName: $_INSTANCE_NAME
      Networking:
$_NETWORKING_RULES
      Tags:
        - Key: cf-$_CF_STACKNAME
        - Key: lightsail-miab-installer
        - Key: installation-id-$_INSTALLATION_ID
        - Key: installer
          Value: lightsail-miab-installer
        - Key: cfstackname
          Value: $_CF_STACKNAME
  ${_RESOURCE_NAME}SesUser:
    Type: AWS::IAM::User
    Properties:
      UserName: $_CF_STACKNAME-user
      Policies:
        - PolicyName: $_CF_STACKNAME-policy
          PolicyDocument:
            Version: 2012-10-17
            Statement:
              - Sid: AllowSendEmailSes
                Effect: Allow
                Action:
                  - 'ses:SendRawEmail'
                Resource: '*'
              - Sid: AllowListAllBuckets
                Effect: Allow
                Action:
                  - 's3:ListAllMyBuckets'
                Resource: '*'
              - Sid: AllowFullAccessToBackupBuckets
                Effect: Allow
                Action:
                  - 's3:*'
                Resource:
                  - 'arn:aws:s3:::$LMIAB_MAIL_BACKUP_BUCKET'
                  - 'arn:aws:s3:::$LMIAB_MAIL_BACKUP_BUCKET/*'
                  - 'arn:aws:s3:::$LMIAB_NEXTCLOUD_BACKUP_BUCKET'
                  - 'arn:aws:s3:::$LMIAB_NEXTCLOUD_BACKUP_BUCKET/*'
      Tags:
        - Key: installer
          Value: lightsail-miab-installer
        - Key: cfstackname
          Value: $_CF_STACKNAME
  ${_RESOURCE_NAME}MailBackup:
    Type: AWS::S3::Bucket
    DeletionPolicy: Retain
    Condition: IsNotRestoreCondition
    Properties:
      BucketName: $LMIAB_MAIL_BACKUP_BUCKET
      LifecycleConfiguration:
        Rules:
          - Id: IntelligentTieringRule
            Status: Enabled
            Transitions:
              - StorageClass: INTELLIGENT_TIERING
                TransitionInDays: 0
  ${_RESOURCE_NAME}NextCloudBackup:
    Type: AWS::S3::Bucket
    DeletionPolicy: Retain
    Condition: IsNotRestoreCondition
    Properties:
      BucketName: $LMIAB_NEXTCLOUD_BACKUP_BUCKET
      LifecycleConfiguration:
        Rules:
          - Id: IntelligentTieringRule
            Status: Enabled
            Transitions:
              - StorageClass: INTELLIGENT_TIERING
                TransitionInDays: 0
  ${_RESOURCE_NAME}AccessKey:
    Type: AWS::IAM::AccessKey
    Properties:
      UserName: !Ref ${_RESOURCE_NAME}SesUser
      Status: Active
  ${_RESOURCE_NAME}SesIdentity:
    Type: AWS::SES::EmailIdentity
    DeletionPolicy: Retain
    Properties:
      EmailIdentity: $LMIAB_EMAIL_DOMAIN
      DkimAttributes: 
        SigningEnabled: true
  ${_RESOURCE_NAME}AdminPasswordSsm:
    Type: AWS::SSM::Parameter
    Properties:
      Name: /MailInABox/$_CF_STACKNAME/AdminPassword
      Type: String
      Value: UpdatedByInstaller
  ${_RESOURCE_NAME}SesUserSsm:
    Type: AWS::SSM::Parameter
    Properties:
      Name: /MailInABox/$_CF_STACKNAME/Ses/SmtpUser
      Type: String
      Value: !Ref ${_RESOURCE_NAME}AccessKey
  ${_RESOURCE_NAME}SesSecretKeySsm:
    Type: AWS::SSM::Parameter
    Properties:
      Name: /MailInABox/$_CF_STACKNAME/Ses/SecretKey
      Type: String
      Value: !GetAtt ${_RESOURCE_NAME}AccessKey.SecretAccessKey
  ${_RESOURCE_NAME}SesPasswordSsm:
    Type: AWS::SSM::Parameter
    Properties:
      Name: /MailInABox/$_CF_STACKNAME/Ses/SmtpPassword
      Type: String
      Value: UpdatedByInstaller
  ${_RESOURCE_NAME}BackupSecretKeySsm:
    Type: AWS::SSM::Parameter
    DeletionPolicy: Retain
    Properties:
      Name: /MailInABox/$_CF_STACKNAME/BackupSecretKey
      Type: String
      Value: UpdatedByInstaller
  ${_RESOURCE_NAME}StaticIP:
    Type: AWS::Lightsail::StaticIp
    DeletionPolicy: Retain
    Properties:
      AttachedTo: !Ref $_RESOURCE_NAME
      StaticIpName: ${_INSTANCE_NAME}-Ip
Outputs:
  LightsailInstance:
    Value: !Ref $_RESOURCE_NAME
  LightsailInstanceUrl:
    Value: !Sub
      - 'https://lightsail.aws.amazon.com/ls/webapp/\${AWS::Region}/instances/\${INSTANCE_NAME}/connect'
      - REGION: !Ref AWS::Region
        INSTANCE_NAME: !Ref $_RESOURCE_NAME
  LightsailIP:
    Value: !Ref ${_RESOURCE_NAME}StaticIP
  LightsailIPUrl:
    Value: !Sub
      - 'https://lightsail.aws.amazon.com/ls/webapp/\${REGION}/static-ips/\${IP_NAME}/connect'
      - REGION: !Ref AWS::Region
        IP_NAME: !Ref ${_RESOURCE_NAME}StaticIP
  S3MailBackupBucket:
    Condition: IsNotRestoreCondition
    Value: !Ref ${_RESOURCE_NAME}MailBackup
  S3MailBackupBucketUrl:
    Condition: IsNotRestoreCondition
    Value: !Sub
      - 'https://s3.console.aws.amazon.com/s3/buckets/\${BUCKET_NAME}?region=\${REGION}&tab=objects'
      - BUCKET_NAME: !Ref ${_RESOURCE_NAME}MailBackup
        REGION: !Ref AWS::Region
  S3NextCloudBackupBucket:
    Condition: IsNotRestoreCondition
    Value: !Ref ${_RESOURCE_NAME}NextCloudBackup
  S3NextCloudBackupBucketUrl:
    Condition: IsNotRestoreCondition
    Value: !Sub
      - 'https://s3.console.aws.amazon.com/s3/buckets/\${BUCKET_NAME}?region=\${REGION}&tab=objects'
      - BUCKET_NAME: !Ref ${_RESOURCE_NAME}NextCloudBackup
        REGION: !Ref AWS::Region
  SesIdentity:
    Value: !Ref ${_RESOURCE_NAME}SesIdentity
  SesIdentityUrl:
    Value: !Sub
      - 'https://console.aws.amazon.com/ses/home?region=\${REGION}#/verified-identities/\${DOMAIN}'
      - REGION: !Ref AWS::Region
        DOMAIN: '$LMIAB_EMAIL_DOMAIN'
  AdminPasswordSsm:
    Value: !Ref ${_RESOURCE_NAME}AdminPasswordSsm
  AdminPasswordSsmUrl:
    Value: !Sub
      - 'https://console.aws.amazon.com/systems-manager/parameters\${PARAM_NAME}/description?region=\${REGION}'
      - PARAM_NAME: !Ref ${_RESOURCE_NAME}AdminPasswordSsm
        REGION: !Ref AWS::Region
  SesUserSsm:
    Value: !Ref ${_RESOURCE_NAME}SesUserSsm
  SesUserSsmUrl:
    Value: !Sub
      - 'https://console.aws.amazon.com/systems-manager/parameters\${PARAM_NAME}/description?region=\${REGION}'
      - PARAM_NAME: !Ref ${_RESOURCE_NAME}SesUserSsm
        REGION: !Ref AWS::Region
  SesSecretKeySsm:
    Value: !Ref ${_RESOURCE_NAME}SesSecretKeySsm
  SesSecretKeySsmUrl:
    Value: !Sub
      - 'https://console.aws.amazon.com/systems-manager/parameters\${PARAM_NAME}/description?region=\${REGION}'
      - PARAM_NAME: !Ref ${_RESOURCE_NAME}SesSecretKeySsm
        REGION: !Ref AWS::Region
  SesPasswordSsm:
    Value: !Ref ${_RESOURCE_NAME}SesPasswordSsm
  SesPasswordSsmUrl:
    Value: !Sub
      - 'https://console.aws.amazon.com/systems-manager/parameters\${PARAM_NAME}/description?region=\${REGION}'
      - PARAM_NAME: !Ref ${_RESOURCE_NAME}SesPasswordSsm
        REGION: !Ref AWS::Region
  BackupSecretKeySsm:
    Value: !Ref ${_RESOURCE_NAME}BackupSecretKeySsm
  BackupSecretKeySsmUrl:
    Value: !Sub
      - 'https://console.aws.amazon.com/systems-manager/parameters\${PARAM_NAME}/description?region=\${REGION}'
      - PARAM_NAME: !Ref ${_RESOURCE_NAME}BackupSecretKeySsm
        REGION: !Ref AWS::Region

EOF
  
  return 0
}

lmiab_gen_cloudformation_template()
{
  lmiab_cf_template_header && \
  lmiab_cf_template_node --az-id "$LMIAB_AZ" \
    --bundle-id "$LMIAB_BUNDLE_ID" \
    --cf-stackname "$LMIAB_CLOUDFORMATION_STACKNAME" \
    --installation-id "$LMIAB_INSTALLATION_ID" \
    --instance-name "$( lmiab_gen_node_name )" \
    --keypair-name "$LMIAB_SSH_LIGHTSAIL_KEYPAIR_NAME" \
    --resource-name "MailInABoxNode${LMIAB_RANDOM_ID}" \
    --ssh-allow-cidr "$LMIAB_FIREWALL_SSH_ALLOW_CIDR" \
    --os-id "$LMIAB_NODE_OS_ID"

  return 0
}

lmiab_gen_node_name()
{
  echo "$LMIAB_NODE_PREFIX-$LMIAB_INSTALLATION_ID-$LMIAB_RANDOM_ID"
  
  return 0
}

lmiab_run_cloudformation()
{
  lmiab_is_region_and_az_valid || return 1
  
  [ "$LMIAB_DRY_RUN" = "yes" ] && {
    lmiab_gen_cloudformation_template
    return 1
  }

  local _ANSWER="no"
  local _TITLE="lightsail-miab-installer v${LMIAB_VERSION}"
  local _ANY_KEY=""
  
  echo
  lmiab_char_repeat "-" $( echo $_TITLE | wc -c ) && echo
  echo $_TITLE
  lmiab_char_repeat "-" $( echo $_TITLE | wc -c ) && echo
  cat <<EOF
This process will install Mail-in-a-Box on an Amazon Lightsail instance.

      CloudFormation stack: $LMIAB_CLOUDFORMATION_STACKNAME
                    Region: $LMIAB_REGION_DISPLAY_NAME
         Availability Zone: $LMIAB_AZ
                 Node plan: $LMIAB_PLAN
    Lightsail SSH key pair: $LMIAB_SSH_LIGHTSAIL_KEYPAIR_NAME
      SSH private key file: $LMIAB_SSH_PRIVATE_KEY_FILE
Amazon SES domain identity: $LMIAB_EMAIL_DOMAIN
    Mail-in-a-Box hostname: $LMIAB_BOX_HOSTNAME
 Mail-in-a-Box Admin email: $LMIAB_ADMIN_EMAIL
EOF

  [ "$LMIAB_IS_RESTORE" = "yes" ] && {
    cat <<EOF

Data will be restored from following S3 buckets:
       Mail data: s3://$LMIAB_MAIL_BACKUP_BUCKET
  Nextcloud data: s3://$LMIAB_NEXTCLOUD_BACKUP_BUCKET
EOF
  }

  [ ! -z "$LMIAB_ADMIN_PASSWORD" ] && {
    cat <<EOF
    Mail-in-a-Box password: $( echo "$LMIAB_ADMIN_PASSWORD" | sed 's/./*/g' )
EOF
  }

  echo
  printf "Press any key to continue or CTRL-C to abort: "
  read _ANY_KEY

  [ -z "$LMIAB_ADMIN_PASSWORD" ] && {
    printf "Enter Mail-in-a-Box Admin password: "
    read -s LMIAB_ADMIN_PASSWORD
  }
  
  echo "This may take several minutes, please wait..."
  echo "To view detailed log, run following command on another terminal:"
  echo "  tail -f $LMIAB_LOG_FILE"
  echo
  
  lmiab_log "Checking SSH key pair '$LMIAB_SSH_LIGHTSAIL_KEYPAIR_NAME' in region '$LMIAB_REGION'"
  lmiab_is_ssh_keypair_valid || return 1
  
  lmiab_log "Checking existing stack '${LMIAB_CLOUDFORMATION_STACKNAME}'"
  # Do not create when the stack already exists
  aws cloudformation describe-stacks --stack-name=$LMIAB_CLOUDFORMATION_STACKNAME >>$LMIAB_LOG_FILE 2>&1 && {
    lmiab_err "Stack already exists. Aborted!"
    return 1
  }
  
  # Validating template
  local _TEMPLATE_OUT_FILE="$LMIAB_OUTPUT_DIR/cf-${LMIAB_CLOUDFORMATION_STACKNAME}.yaml"

  lmiab_log "Validating template of stack '${LMIAB_CLOUDFORMATION_STACKNAME}'"
  lmiab_gen_cloudformation_template > $_TEMPLATE_OUT_FILE && \
  aws cloudformation validate-template \
    --template-body file://$_TEMPLATE_OUT_FILE >> $LMIAB_LOG_FILE 2>&1 || {
    lmiab_err "CloudFormation generated template is not valid. Aborted!"
    return 1
  }

  lmiab_log "Creating stack '${LMIAB_CLOUDFORMATION_STACKNAME}'"
  aws cloudformation create-stack \
    --capabilities "CAPABILITY_NAMED_IAM" \
    --stack-name "$LMIAB_CLOUDFORMATION_STACKNAME" \
    --parameters ParameterKey=IsRestoreParam,ParameterValue=$LMIAB_IS_RESTORE \
    --template-body file://$_TEMPLATE_OUT_FILE >> $LMIAB_LOG_FILE 2>&1

  local STACK_STATUS=""
  local _WAIT_COUNTER=1
  
  while [ "$STACK_STATUS" != "CREATE_COMPLETE" ]
  do
    lmiab_log_waiting "Waiting stack '$LMIAB_CLOUDFORMATION_STACKNAME' to be ready$( lmiab_char_repeat '.' $_WAIT_COUNTER )"
    STACK_STATUS="$( aws cloudformation describe-stacks \
                    --stack-name "$LMIAB_CLOUDFORMATION_STACKNAME" 2>>$LMIAB_LOG_FILE | \
                    jq -r '.Stacks[0].StackStatus' )"

    [ $_WAIT_COUNTER -ge 3 ] && _WAIT_COUNTER=0
    _WAIT_COUNTER=$(( $_WAIT_COUNTER + 1 ))
    sleep 2
  done
  
  echo
  lmiab_log "Stack '$LMIAB_CLOUDFORMATION_STACKNAME' is ready"

  return 0
}

lmiab_wait_for_node_to_be_ready()
{
  local _NODE_IP="$1"
  local _NODE_STATUS=""
  
  local _WAIT_COUNTER=1
  while [ "$_NODE_STATUS" != "ubuntu" ]
  do
    _NODE_STATUS="$( lmiab_ssh_to_node $_NODE_IP whoami 2>>$LMIAB_LOG_FILE | tr -d '[:space:]' )"
    lmiab_log_waiting "Waiting SSH connection to '$_NODE_IP' to be ready$( lmiab_char_repeat '.' $_WAIT_COUNTER )"
    
    [ $_WAIT_COUNTER -ge 3 ] && _WAIT_COUNTER=0
    _WAIT_COUNTER=$(( $_WAIT_COUNTER + 1 ))
    
    sleep 1
  done

  echo
  lmiab_log "SSH to node $_NODE_IP is ready."
  
  return 0
}

lmiab_init_script_commands()
{
  local _CMD="$( cat <<INIT_SCRIPT
#!/bin/bash
export LMIAB_PACKAGE_URL="$LMIAB_PACKAGE_URL"

export NONINTERACTIVE=true
export SKIP_NETWORK_CHECKS=true
export STORAGE_ROOT=/home/user-data
export STORAGE_USER=user-data
export PRIVATE_IP="\$( ec2metadata --local-ipv4 )"
export PUBLIC_IP="\$( ec2metadata --public-ipv4 )"
export PRIVATE_IPV6=""
export PUBLIC_IPV6=""
export PRIMARY_HOSTNAME="$LMIAB_BOX_HOSTNAME"
export MTA_STS_MODE=enforce
export EMAIL_ADDR="$LMIAB_ADMIN_EMAIL"
export EMAIL_PW="$LMIAB_ADMIN_PASSWORD"

echo "[LMIAB Init Script]: Creating user and storage directory"
useradd -m \$STORAGE_USER
mkdir -p \$STORAGE_ROOT

rm /tmp/mail-in-a-box.tar.gz 2>/dev/null
mkdir -p /opt/mailinabox

echo "[LMIAB Init Script]: Downloading Mail-in-a-Box from $LMIAB_PACKAGE_URL"
curl -s -L "$LMIAB_PACKAGE_URL" -o /tmp/mail-in-a-box.tar.gz && \
  tar xf /tmp/mail-in-a-box.tar.gz --strip-components=1 -C /opt/mailinabox

# Write hostname and it's associate public IP address to /etc/hosts. So
# it can be resolved without having to rely on DNS server. Some tools such as
# 'sudo' trying to resolv the hostname and could cause timeout.
echo "[LMIAB Init Script]: Adding hostname '\$PRIMARY_HOSTNAME' to /etc/hosts"
grep "\$PRIMARY_HOSTNAME" /etc/hosts >/dev/null 2>/dev/null || {
  echo "127.0.0.1 \$PRIMARY_HOSTNAME" >> /etc/hosts
}

echo "[LMIAB Init Script]: Running setup/start.sh"
cd /opt/mailinabox/ && setup/start.sh

echo "[LMIAB Init Script]: Disabling ufw and fail2ban..."
fail2ban-client stop
ufw disable

INIT_SCRIPT
)"

  echo "$_CMD" | sed 's/EMAIL_PW=.*/EMAIL_PW=******/g'  >> $LMIAB_LOG_FILE 2>&1
  echo "$_CMD"
}

lmiab_ssh_to_node()
{
  local _NODE_IP=$1

  # Remove the $1
  shift

  ssh -i $LMIAB_SSH_PRIVATE_KEY_FILE -o ConnectTimeout=3 \
    -o StrictHostKeyChecking=no -o LogLevel=error \
    $LMIAB_OS_USERNAME@$_NODE_IP $@
}

lmiab_run_post_installation_commands()
{
  lmiab_log "Uploading dummy object to bucket ${LMIAB_MAIL_BACKUP_BUCKET}"
  lmiab_put_dummy_object_to_bucket "$LMIAB_MAIL_BACKUP_BUCKET" >> $LMIAB_LOG_FILE
  
  lmiab_log "Writing admin password to SSM Parameter Store"
  lmiab_put_admin_password_to_ssm "$LMIAB_ADMIN_PASSWORD" >> $LMIAB_LOG_FILE

  local _USERNAME="${LMIAB_CLOUDFORMATION_STACKNAME}-user"
  
  # Get current value of SMTP AccessKeyId and SecretAccessKey
  local _ACCESS_KEY="$( aws ssm get-parameter \
    --name "/MailInABox/$LMIAB_CLOUDFORMATION_STACKNAME/Ses/SmtpUser" \
    --query Parameter.Value --output text
  )"
  local _SECRET_KEY="$( aws ssm get-parameter \
    --name "/MailInABox/$LMIAB_CLOUDFORMATION_STACKNAME/Ses/SecretKey" \
    --query Parameter.Value --output text
  )"
  
  lmiab_log "Creating Amazon SES SMTP password"
  local _SMTP_PASSWORD="$( lmiab_iam_key_to_ses_credentials --secret-key "$_SECRET_KEY" --region "$LMIAB_REGION" )"
  
  [ -z "$LMIAB_SMTP_RELAY_USER" ] && LMIAB_SMTP_RELAY_USER="$_ACCESS_KEY"
  [ -z "$LMIAB_SMTP_RELAY_PASSWORD" ] && LMIAB_SMTP_RELAY_PASSWORD="$_SMTP_PASSWORD"
  
  lmiab_log "Writing SES SMTP user and password to SSM Parameter Store"
  lmiab_put_smtp_user_to_ssm "$_ACCESS_KEY" >> $LMIAB_LOG_FILE
  lmiab_put_smtp_password_to_ssm "$_SMTP_PASSWORD" >> $LMIAB_LOG_FILE
  lmiab_put_smtp_secretkey_to_ssm "$_SECRET_KEY" >> $LMIAB_LOG_FILE
  
  local _NODE_NAME="$( lmiab_gen_node_name )"
  local _NODE_IP="$( lmiab_get_node_public_ip $_NODE_NAME )"
  
  lmiab_wait_for_node_to_be_ready "$_NODE_IP"
  
  lmiab_log "Installing Mail-in-a-Box"
  
  # Init script to install Mail-in-a-Box
  cat <<EOF | lmiab_ssh_to_node $_NODE_IP sudo bash | tee -a $LMIAB_LOG_FILE
$( lmiab_init_script_commands )
EOF
  
  [ "$LMIAB_DISABLE_SMTP_RELAY" = "no" ] && {
    lmiab_log "Creating CNAME records for Amazon SES identity verification"
    lmiab_create_dns_records_for_ses_dkim \
      --identity "$LMIAB_EMAIL_DOMAIN" \
      --api-server "$_NODE_IP" \
      --api-user "$LMIAB_ADMIN_EMAIL" \
      --api-password "$LMIAB_ADMIN_PASSWORD" | tee -a $LMIAB_LOG_FILE
      
    lmiab_configure_smtp_relay \
      --relay-endpoint "$LMIAB_SMTP_RELAY_ENDPOINT" \
      --relay-port "$LMIAB_SMTP_RELAY_PORT" \
      --relay-user "$LMIAB_SMTP_RELAY_USER" \
      --relay-password "$LMIAB_SMTP_RELAY_PASSWORD" | tee -a $LMIAB_LOG_FILE
  }

  # Check the existence of backup secret key
  ( lmiab_ssh_to_node $_NODE_IP ls /home/user-data/backup/secret_key.txt >/dev/null 2>/dev/null ) && {
    lmiab_log "Updating SSM Parameter Store of backup_secret.txt value"
    local _BACKUP_SECRET_KEY="$( lmiab_ssh_to_node $_NODE_IP sudo cat '/home/user-data/backup/secret_key.txt' )"
    lmiab_put_backup_secret_key_to_ssm "$_BACKUP_SECRET_KEY" >> $LMIAB_LOG_FILE
  }
  
  [ "$LMIAB_DISABLE_S3_BACKUP" = "no" ] && {
    lmiab_log "Updating config for S3 backup (Mail and Nextcloud)"
    lmiab_create_custom_s3_backup_config \
      --aws-accesskey "$_ACCESS_KEY" \
      --aws-secretkey "$_SECRET_KEY" \
      --mail-bucket "$LMIAB_MAIL_BACKUP_BUCKET" \
      --nextcloud-bucket "$LMIAB_NEXTCLOUD_BACKUP_BUCKET" \
      --node-ip "$_NODE_IP" \
      --region "$LMIAB_REGION" | tee -a $LMIAB_LOG_FILE
  }

  lmiab_log "Disabling postgrey configuration" 
  lmiab_disable_postgrey $_NODE_IP | tee -a $LMIAB_LOG_FILE
  
  [ "$LMIAB_IS_RESTORE" = "yes" ] && {
    lmiab_log "Restoring data from previous installation..."
    lmiab_restore_from_backup \
      --aws-accesskey "$_ACCESS_KEY" \
      --aws-secretkey "$_SECRET_KEY" \
      --backup-key "$LMIAB_BACKUP_SECRET_KEY" \
      --hostname "$LMIAB_BOX_HOSTNAME" \
      --mail-bucket "$LMIAB_MAIL_BACKUP_BUCKET" \
      --node-ip "$_NODE_IP" \
      --region "$LMIAB_REGION"
    
    lmiab_log "Overwriting secret_key.txt..."
      cat <<SECRET_TXT | lmiab_ssh_to_node $_NODE_IP sudo bash
cp /home/user-data/backup/secret_key.txt /home/user-data/backup/secret_key.txt.orig
echo "$LMIAB_BACKUP_SECRET_KEY" > /home/user-data/backup/secret_key.txt
SECRET_TXT

    lmiab_log "Reconfiguring S3 backup because it should be overridden by previous restore process..."
    lmiab_create_custom_s3_backup_config \
      --aws-accesskey "$_ACCESS_KEY" \
      --aws-secretkey "$_SECRET_KEY" \
      --mail-bucket "$LMIAB_MAIL_BACKUP_BUCKET" \
      --nextcloud-bucket "$LMIAB_NEXTCLOUD_BACKUP_BUCKET" \
      --node-ip "$_NODE_IP" \
      --region "$LMIAB_REGION" | tee -a $LMIAB_LOG_FILE
  }
  
  lmiab_log "Re-enabling ufw and fail2ban..."
  cat << ENABLE_SSH | lmiab_ssh_to_node $_NODE_IP sudo bash
ufw --force enable
fail2ban-client status >/dev/null 2>&1 || fail2ban-client start
ENABLE_SSH
  
  lmiab_log "Installation COMPLETED.

Notes: Please make sure to update nameserver of your domain to point to this 
box (IP address $_NODE_IP). It may take several hours for domain to propagate
accross the Internet."

  return 0
}

lmiab_put_admin_password_to_ssm()
{
  lmiab_put_ssm_secure_string \
    --name "/MailInABox/$LMIAB_CLOUDFORMATION_STACKNAME/AdminPassword" \
    --value "$1"
}

lmiab_put_smtp_user_to_ssm()
{
  lmiab_put_ssm_secure_string \
    --name "/MailInABox/$LMIAB_CLOUDFORMATION_STACKNAME/Ses/SmtpUser" \
    --value "$1"
}

lmiab_put_smtp_password_to_ssm()
{
  lmiab_put_ssm_secure_string \
    --name "/MailInABox/$LMIAB_CLOUDFORMATION_STACKNAME/Ses/SmtpPassword" \
    --value "$1"
}

lmiab_put_smtp_secretkey_to_ssm()
{
  lmiab_put_ssm_secure_string \
    --name "/MailInABox/$LMIAB_CLOUDFORMATION_STACKNAME/Ses/SecretKey" \
    --value "$1"
}

lmiab_put_backup_secret_key_to_ssm()
{
  lmiab_put_ssm_secure_string \
    --name "/MailInABox/$LMIAB_CLOUDFORMATION_STACKNAME/BackupSecretKey" \
    --value "$1"
}

lmiab_put_ssm_secure_string()
{
  while [ $# -gt 0 ]; do
    case $1 in
      --name) local _NAME="$2"; shift ;;
      --value) local _VALUE="$2"; shift ;;
      *) echo "Unrecognised option passed: $1" 2>&2; return 1;;
    esac
    shift
  done
  
  aws ssm put-parameter --overwrite --type SecureString \
    --name "$_NAME" --value "$_VALUE"
}

lmiab_get_node_public_ip()
{
  local _NAME="$1"
  [ ! -z "$LMIAB_CACHE_NODE_PUBLIC_IP" ] && {
    echo "$LMIAB_CACHE_NODE_PUBLIC_IP"
    return 0
  }
  
  LMIAB_CACHE_NODE_PUBLIC_IP="$( aws lightsail get-instance --instance-name $_NAME | \
    jq -r '.instance.publicIpAddress' || return 1 )"
  
  echo "$LMIAB_CACHE_NODE_PUBLIC_IP"
}

lmiab_get_domain_from_email()
{
  local _EMAIL="$1"
  
  echo "$_EMAIL" | awk -F'@' '{print $2}'
}

lmiab_get_ses_dkim_attributes()
{
  local _IDENTITY="$1"
  aws ses get-identity-dkim-attributes --identities "$_IDENTITY" | \
    jq -r ".DkimAttributes.\"$_IDENTITY\".DkimTokens[]"
}

lmiab_create_dns_records_for_ses_dkim()
{
  while [ $# -gt 0 ]; do
    case $1 in
      --identity) local _IDENTITY="$2"; shift ;;
      --api-server) local _API_SERVER="$2"; shift ;;
      --api-user) local _USERNAME="$2"; shift ;;
      --api-password) local _PASSWORD="$2"; shift ;;
      *) echo "Unrecognised option passed: $1" 2>&2; return 1;;
    esac
    shift
  done

  local _BASE_API_URL="https://$_API_SERVER/admin/dns/custom"
  local _BASE_SES_DKIM_DOMAIN="dkim.amazonses.com"
  for _record in $( lmiab_get_ses_dkim_attributes "$_IDENTITY" )
  do
    curl -k -s \
      -u "${_USERNAME}:${_PASSWORD}" \
      -d "${_record}.${_BASE_SES_DKIM_DOMAIN}" \
      "$_BASE_API_URL/${_record}._domainkey.${_IDENTITY}/cname"
  done
}

lmiab_create_custom_s3_backup_config()
{
  while [ $# -gt 0 ]; do
    case $1 in
      --aws-accesskey) local _ACCESSKEY="$2"; shift ;;
      --aws-secretkey) local _SECRETKEY="$2"; shift ;;
      --mail-bucket) local _MAIL_BUCKET="$2"; shift ;;
      --nextcloud-bucket) local _NEXTCLOUD_BUCKET="$2"; shift ;;
      --node-ip) local _NODE_IP="$2"; shift ;;
      --region) local _REGION="$2"; shift ;;
      *) echo "Unrecognised option passed: $1" 2>&2; return 1;;
    esac
    shift
  done

  # This custom YAML file will be override the default behavior of 
  # Mail-in-a-Box backup
  cat <<CMD | lmiab_ssh_to_node $_NODE_IP sudo bash
cat <<BACKUP > /home/user-data/backup/custom.yaml
min_age_in_days: 7
target: 's3://s3.$_REGION.amazonaws.com/${_MAIL_BUCKET}/'
target_user: '$_ACCESSKEY'
target_pass: '$_SECRETKEY'
BACKUP

chmod 0600 /home/user-data/backup/custom.yaml
CMD

  # Nextcloud external storage (S3) config
  # | lmiab_ssh_to_node $_NODE_IP sudo bash
  # > /tmp/nextcloud.config.tmp && mv /tmp/nextcloud.config.tmp /home/user-data/owncloud/config.php
  cat <<NEXTCLOUD | lmiab_ssh_to_node $_NODE_IP sudo -u www-data bash
echo -n '<?php 
\$CONFIG = ' > /tmp/nextcloud.config.tmp

php <<'EOF' >> /tmp/nextcloud.config.tmp
<?php
require '/home/user-data/owncloud/config.php';

\$CONFIG['objectstore'] = array(
  'class' => '\\\\OC\\\\Files\\\\ObjectStore\\\\S3',
    'arguments' => array(
        'bucket' => '$_NEXTCLOUD_BUCKET',
        'region' => '$_REGION',
        'key' => '$_ACCESSKEY',
        'secret' => '$_SECRETKEY',
        'autocreate' => false,
        'use_ssl' => true
  ),
);

var_export(\$CONFIG);
EOF
echo ';' >> /tmp/nextcloud.config.tmp

mv /tmp/nextcloud.config.tmp /home/user-data/owncloud/config.php
chown www-data:www-data /home/user-data/owncloud/config.php
NEXTCLOUD
}

lmiab_configure_smtp_relay()
{
  while [ $# -gt 0 ]; do
    case $1 in
      --relay-endpoint) local _RELAY_ENDPOINT="$2"; shift ;;
      --relay-port) local _RELAY_PORT="$2"; shift ;;
      --relay-user) local _RELAY_USER="$2"; shift ;;
      --relay-password) local _RELAY_PASSWORD="$2"; shift ;;
      --node-ip) local _NODE_IP="$2"; shift ;;
      *) echo "Unrecognised option passed: $1" 2>&2; return 1;;
    esac
    shift
  done
  
  cat <<RELAY | lmiab_ssh_to_node $_NODE_IP sudo bash
postconf -e "relayhost = [$_RELAY_ENDPOINT]:$_RELAY_PORT" \
  "smtp_sasl_auth_enable = yes" \
  "smtp_sasl_security_options = noanonymous" \
  "smtp_sasl_password_maps = hash:/etc/postfix/sasl_passwd" \
  "smtp_use_tls = yes" \
  "smtp_tls_security_level = encrypt" \
  "smtp_tls_note_starttls_offer = yes"
  
echo "[$_RELAY_ENDPOINT]:$_RELAY_PORT $_RELAY_USER:$_RELAY_PASSWORD" >> /etc/postfix/sasl_passwd

postmap hash:/etc/postfix/sasl_passwd
chown root:root /etc/postfix/sasl_passwd /etc/postfix/sasl_passwd.db
chmod 0600 /etc/postfix/sasl_passwd /etc/postfix/sasl_passwd.db

postconf -e 'smtp_tls_CAfile = /etc/ssl/certs/ca-certificates.crt'

service postfix restart
RELAY
}

lmiab_disable_postgrey()
{
  local _NODE_IP="$1"
cat <<EOF | lmiab_ssh_to_node $_NODE_IP sudo bash
echo "/.*/" > /etc/postgrey/whitelist_clients.local

service postgrey restart
EOF
}

lmiab_restore_from_backup()
{
  while [ $# -gt 0 ]; do
    case $1 in
      --aws-accesskey) local _ACCESS_KEY="$2"; shift ;;
      --aws-secretkey) local _SECRET_KEY="$2"; shift ;;
      --backup-key) local _BACKUP_KEY="$2"; shift ;;
      --hostname) local _HOSTNAME="$2"; shift ;;
      --mail-bucket) local _MAIL_BUCKET="$2"; shift ;;
      --node-ip) local _NODE_IP="$2"; shift ;;
      --region) local _REGION="$2"; shift ;;
      *) echo "Unrecognised option passed: $1" 2>&2; return 1;;
    esac
    shift
  done
  
  cat <<RESTORE | lmiab_ssh_to_node $_NODE_IP sudo bash
export NONINTERACTIVE=1
export PRIMARY_HOSTNAME="$_HOSTNAME"

rm -rf /home/user-data/ssl/* 

export AWS_ACCESS_KEY_ID="$_ACCESS_KEY"
export AWS_SECRET_ACCESS_KEY="$_SECRET_KEY"
export PASSPHRASE="$_BACKUP_KEY"

duplicity restore --force --s3-region-name=$_REGION s3://$_MAIL_BUCKET /home/user-data/

mailinabox
RESTORE
}

lmiab_put_dummy_object_to_bucket()
{
  # There is small bug on Mail-in-a-Box Python script management/backup.py which
  # return error when bucket is empty. It does not do conditional checking and
  # assuming S3 API always return a response with key name 'Contents'.
  #
  # To overcome those issue is upload an object to the Bucket.
  #
  local _BUCKET="$1"
  cat <<EOF > $LMIAB_CACHE_DIR/$LMIAB_CLOUDFORMATION_STACKNAME-README.txt
This is dummy file generated by lightsail-miab-installer on $( date )
EOF

  aws s3 cp $LMIAB_CACHE_DIR/$LMIAB_CLOUDFORMATION_STACKNAME-README.txt s3://$_BUCKET/README.txt
}

lmiab_destroy_installation()
{
  local _CMD_TO_RUN="aws cloudformation delete-stack --region \"$LMIAB_REGION\" --stack-name \"$LMIAB_CLOUDFORMATION_STACKNAME\""
  
  [ "$LMIAB_DRY_RUN" = "yes" ] && {
    echo "[DRY RUN] $_CMD_TO_RUN"
    return 0
  }
  
  local _ANSWER="no"
  
  echo "This action will destroy CloudFormation stack '$LMIAB_CLOUDFORMATION_STACKNAME' ($LMIAB_REGION)."
  printf "Type 'yes' to continue: "
  read _ANSWER
  
  [ "$_ANSWER" != "yes" ] && {
    echo "Aborted."
    return 0
  }
  
  lmiab_is_region_valid $LMIAB_REGION || {
    echo "[ERROR]: Region is not valid." >&2
    return 1
  }
  
  echo
  lmiab_log "Checking CloudFormation stack '$LMIAB_CLOUDFORMATION_STACKNAME'"
  
  local _CF_DESCRIBE_STACKS="$( aws cloudformation describe-stacks \
    --stack-name $LMIAB_CLOUDFORMATION_STACKNAME \
    2>>$LMIAB_LOG_FILE
  )" || {
    lmiab_log "Stack not found, aborted."
    return 1
  }
  
  lmiab_log "Running cmd: $_CMD_TO_RUN"
  eval $_CMD_TO_RUN 2>&1
  local _WAIT_COUNTER=1
  
  while :
  do
    lmiab_log_waiting "Destroying CloudFormation stack '$LMIAB_CLOUDFORMATION_STACKNAME'$( lmiab_char_repeat '.' $_WAIT_COUNTER )"
    aws cloudformation describe-stacks \
      --stack-name="$LMIAB_CLOUDFORMATION_STACKNAME" 2>>$LMIAB_LOG_FILE >>$LMIAB_LOG_FILE || break
    sleep 2
    
    [ $_WAIT_COUNTER -ge 3 ] && _WAIT_COUNTER=0
    _WAIT_COUNTER=$(( $_WAIT_COUNTER + 1 ))
  done
  
  echo
  lmiab_log "Installation '$LMIAB_INSTALLATION_ID' has been destroyed.

Resources below are kept for your future backup/restore purporse, if you want to
delete them you have to do it manually:
- Amazon Lightsail static IP 
- Amazon S3 buckets for mail and nextcloud backup
- Amazon SSM Parameter Store for storing secret_key.txt
- Amazon SES Email Identity
"

  [ "$LMIAB_DESTROY_ALL_RESOURCES" = "yes" ] && {
    lmiab_log "Destroying all resources..."
    lmiab_destroy_all_resources "$_CF_DESCRIBE_STACKS"
  }

  return 0
}

# Create a function to empty s3 bucket and delete the bucket

lmiab_destroy_all_resources()
{
  local _CF_DESCRIBE_STACKS="$1"

  local _RESOURCE_LIST="$( echo "$_CF_DESCRIBE_STACKS" | \
    jq -r '.Stacks[].Outputs[] | ( .OutputKey + "\t" + .OutputValue )' )"

  [ "$LMIAB_DELETE_S3_BUCKET" = "yes" ] && {
    local _S3_MAIL_BUCKET="$( echo "$_RESOURCE_LIST" | grep 'S3MailBackupBucket\s' | awk '{print $2}' )"
    lmiab_log "Deleting mail backup bucket '$_S3_MAIL_BUCKET'..."
    (aws s3 rm s3://$_S3_MAIL_BUCKET --recursive && aws s3 rb s3://$_S3_MAIL_BUCKET) >> $LMIAB_LOG_FILE
    
    local _S3_NEXTCLOUD_BUCKET="$( echo "$_RESOURCE_LIST" | grep 'S3NextCloudBackupBucket\s' | awk '{print $2}' )"
    lmiab_log "Deleting mail backup bucket '$_S3_NEXTCLOUD_BUCKET'..."
    (aws s3 rm s3://$_S3_NEXTCLOUD_BUCKET --recursive && aws s3 rb s3://$_S3_NEXTCLOUD_BUCKET) >> $LMIAB_LOG_FILE
  }
  
  local _SSM_BACKUP_SECRET_KEY="$( echo "$_RESOURCE_LIST" | grep 'BackupSecretKeySsm\s' | awk '{print $2}' )"
  lmiab_log "Deleting secret_key.txt Parameter Store '$_SSM_BACKUP_SECRET_KEY'..."
  aws ssm delete-parameter --name $_SSM_BACKUP_SECRET_KEY >> $LMIAB_LOG_FILE
  
  local _LIGHTSAIL_STATIC_IP="$( echo "$_RESOURCE_LIST" | grep 'LightsailIP\s' | awk '{print $2}' )"
  lmiab_log "Deleting Lightsail static IP '$_LIGHTSAIL_STATIC_IP'..."
  aws lightsail release-static-ip --static-ip-name $_LIGHTSAIL_STATIC_IP >> $LMIAB_LOG_FILE
  
  local _SES_IDENTITY="$( echo "$_RESOURCE_LIST" | grep 'SesIdentity\s' | awk '{print $2}' )"
  lmiab_log "Deleting SES Identity '$_SES_IDENTITY'..."
  aws ses delete-identity --identity $_SES_IDENTITY >> $LMIAB_LOG_FILE
  
  return 0
}

lmiab_init()
{
  [ ! -d "$LMIAB_CACHE_DIR" ] && mkdir -p $LMIAB_CACHE_DIR
  
  [ -z "$LMIAB_INSTALLATION_ID" ] && {
    echo "Missing installation id. See --help for more info." >&2
    return 1
  }

  local _MISSING_TOOL="$( lmiab_missing_tool )"
  [ ! -z "$_MISSING_TOOL" ] && {
    echo "Missing tool: ${_MISSING_TOOL}. Make sure it is installed and available in your PATH." >&2
    return 1
  }
  
  for _env in LMIAB_MAIL_BACKUP_BUCKET LMIAB_NEXTCLOUD_BACKUP_BUCKET LMIAB_BACKUP_SECRET_KEY
  do
    eval "local _value=\${$_env}"
    [ -z "$_value" ] && [ "$LMIAB_IS_RESTORE" = "yes" ] && {
      echo "Missing env '$_env' value." >&2
      return 1
    }
    
    [ ! -z "$_value" ] && [ "$LMIAB_IS_RESTORE" = "no" ] && {
      echo "Env '$_env' can only be used with --restore flag." >&2
      return 1
    }
  done

  [ "$LMIAB_ACTION" = "install" ] && {
    [ -z "$LMIAB_ADMIN_EMAIL" ] && {
      echo "Missing administrator email. See --help for more info." >&2
      return 1
    }
    
    [ -z "$LMIAB_BOX_HOSTNAME" ] && {
      echo "Missing box hostname. See --help for more info." >&2
      return 1
    }

    [ ! -r "$LMIAB_SSH_PRIVATE_KEY_FILE" ] && {
      printf "Missing SSH private key file: %s.\n" "$LMIAB_SSH_PRIVATE_KEY_FILE" >&2
      printf "Make sure it is exists and readble. You can set the location via LMIAB_SSH_PRIVATE_KEY_FILE environment variable." >&2
      return 1
    }
    
    LMIAB_BUNDLE_ID="$( lmiab_is_package_valid $LMIAB_PLAN )" || {
      printf "Instance type '%s' is not valid. See --help for more info.\n" "$LMIAB_PLAN" >&2
      return 1
    }
  }

  # See all available regions u{sing CLI: `aws lightsail get-regions`
  # Remove the last character from AZ to get region
  # See https://unix.stackexchange.com/questions/144298/delete-the-last-character-of-a-string-using-string-manipulation-in-shell-script
  LMIAB_REGION="${LMIAB_AZ%?}"
  LMIAB_REGION_DISPLAY_NAME="$( lmiab_get_region_display_name "$LMIAB_REGION" )"
  
  export AWS_REGION=$LMIAB_REGION
  
  LMIAB_CLOUDFORMATION_STACKNAME=$LMIAB_CLOUDFORMATION_STACKNAME_PREFIX-$LMIAB_INSTALLATION_ID
  
  local _LOG_SUFFIX="$( date +"%Y%m%d%H%M%S" )"
  LMIAB_LOG_FILE="${LMIAB_OUTPUT_DIR}/${LMIAB_REGION}-${LMIAB_CLOUDFORMATION_STACKNAME}-${_LOG_SUFFIX}.log"
  
  LMIAB_RANDOM_ID="$( lmiab_gen_random_chars 6 )"
  
  LMIAB_EMAIL_DOMAIN="$( lmiab_get_domain_from_email "$LMIAB_ADMIN_EMAIL" )"
  
  [ -z "$LMIAB_SMTP_RELAY_ENDPOINT" ] && LMIAB_SMTP_RELAY_ENDPOINT="email-smtp.${LMIAB_REGION}.amazonaws.com"
  [ -z "$LMIAB_MAIL_BACKUP_BUCKET" ] && LMIAB_MAIL_BACKUP_BUCKET="$LMIAB_CLOUDFORMATION_STACKNAME-$LMIAB_RANDOM_ID-mail-backup"
  [ -z "$LMIAB_NEXTCLOUD_BACKUP_BUCKET" ] && LMIAB_NEXTCLOUD_BACKUP_BUCKET="$LMIAB_CLOUDFORMATION_STACKNAME-$LMIAB_RANDOM_ID-nextcloud-backup"

  return 0
}

# Default action
LMIAB_ACTION="install"

# Parse the arguments
while [ $# -gt 0 ]; do
  case $1 in
    --az)
      LMIAB_AZ="$2"
      shift 
    ;;
    --destroy)
      LMIAB_ACTION="destroy"
    ;;
    # !! WARNING !! #
    # Undocumented feature #
    --destroy-all-resources)
      LMIAB_ACTION="destroy"
      LMIAB_DESTROY_ALL_RESOURCES="yes"
    ;;
    --disable-smtp-relay)
      LMIAB_DISABLE_SMTP_RELAY="yes"
      shift
    ;;
    --dry-run)
      LMIAB_DRY_RUN="yes"
      shift 
    ;;
    --email)
      LMIAB_ADMIN_EMAIL="$2"
      shift
    ;;
    --help)
      lmiab_help
      exit 0
    ;;
    --hostname)
      LMIAB_BOX_HOSTNAME="$2"
      shift
    ;;
    --installation-id)
      LMIAB_INSTALLATION_ID="$2"
      shift 
    ;;
    --instance-type)
      LMIAB_PLAN="$2"
      shift 
    ;;
    --password)
      LMIAB_ADMIN_PASSWORD="$2"
      shift
    ;;
    --restore)
      LMIAB_IS_RESTORE="yes"
    ;;
    --restore-help)
      lmiab_restore_help
      exit 0
    ;;
    --version)
      echo "lightsail-miab-installer version $LMIAB_VERSION"
      exit 0
    ;;
    *) 
      echo "Unrecognised option passed: $1" 2>&2; 
      exit 1
    ;;
  esac
  shift
done

case "$LMIAB_ACTION" in
  install)
    lmiab_init && \
    lmiab_run_cloudformation && \
    lmiab_run_post_installation_commands
  ;;
  
  destroy)
    lmiab_init && \
    lmiab_destroy_installation
  ;;
  
  *)
    echo "Unrecognised action." >&2
    exit 1
  ;;
esac
