## About lightsail-miab-installer

lightsail-miab-installer is a user-friendly command-line tool designed to streamline the setup of [Mail-in-a-Box](https://mailinabox.email/) (a comprehensive mail server package) on Amazon Lightsail. This installer is configured to integrate with Amazon S3 for backups and Amazon SES for email sending (relay), it offers a quick and efficient way to host your own email solution.

To begin installation, run the following command.

```sh
sh lightsail-miab-installer.sh \
  --installation-id demo \
  --az ap-southeast-1a  \
  --email admin@example.com \
  --hostname box.example.com
```

Your mail server should up and running in few minutes, and you can access it using a web interface. By default it will be installed on $5 USD/mo Amazon Lightsail instance.

All the data in your Amazon S3 bucket will be preserved, allowing you to restore it on another machine if needed. Additionally, you have the option to delete the stack using the CloudFormation web console or AWS CLI.

#### Navigate:

- [Requirements](#requirements)
- [Installation](#installation)
- [Usage and Examples](#usage-and-examples)
  - [Specify hostname](#specify-hostname)
  - [Specify email and password for Administrator](#specify-email-and-password-for-administrator)
  - [Specify instance type](#specify-instance-type)
  - [Specify availability zone](#specify-availability-zone)
  - [Restore from backup](#restore-from-backup)
  - [Destroy installation](#destroy-installation)
  - [Dry run mode](#dry-run-mode)
- [Post installation](#post-installation)
- [FAQ](#faq)
  - [I cannot send an email, what's wrong?](#i-cannot-send-an-email-whats-wrong)
  - [I am not receiving any emails, what's wrong?](#i-am-not-receiving-any-emails-whats-wrong)
  - [The installation is stuck, what should I do?](#the-installation-is-stuck-what-should-i-do)
  - [Is it safe to delete installation via CloudFormation?](#is-it-safe-to-delete-installation-via-cloudFormation)
  - [How do I skip SSH passphrase?](#how-do-i-skip-ssh-passphrase)
- [Changelog](#changelog)
- [Todo](#todo)
- [Credits](#credits)
- [Contributing](#Changelog)
- [License](#license)
  
## Requirements

Prerequisites for running this script:

- An active AWS account with sufficient permissions.
- [AWS CLI v2](https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html).
- SSH client
- Basic shell utilities such as `awk aws base64 cat cut date openssl sed ssh tee tr wc`
- [jq](https://stedolan.github.io/jq/)

lightsail-miab-installer has been tested using following shells:

- bash v4.2 (Linux)
- zsh v5.8.1 (macOS, Linux)

## Installation

Download the archive or clone the repository.

```sh
curl -o 'lightsail-miab-installer.zip' -s -L https://github.com/rioastamal/lightsail-miab-installer/archive/refs/heads/main.zip
unzip lightsail-miab-installer.zip
cd lightsail-miab-installer-main/
```

## Usage and Examples

Running lightsail-miab-installer with --help flag will gives you list of options and examples.

```sh
sh lightsail-miab-installer.sh --help
```

```
Usage: lightsail-miab-installer.sh [OPTIONS]

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
homepage at http://github.com/rioastamal/lightsail-miab-installer.
```

Command below will install Mail-in-a-Box on $5/mo Amazon Lightsail instance (1 RAM), Availability Zone `ap-southeast-1c` - Asia Pasific (Singapore), `box.example.com` as hostname, `admin@example.com` as Administrator's email and `lightsaildemo123` as Administrator's password.

```sh
sh lightsail-miab-installer.sh \
  --installation-id demo \
  --az ap-southeast-1c \
  --hostname box.example.com \
  --email 'admin@example.com' \
  --password 'lightsaildemo123'
```

Here, I am specifying `demo` as installation id, and the corresponding CloudFormation stack name would be `miab-demo`.

### Specify hostname

Although you can access the server via its IP address, it is necessary to specify a hostname. This allows Mail-in-a-Box to generate SSL certificates for you. Having SSL certificates for your box prevents any warnings when accessing your Admin panel from a web browser or when making API calls.

To specify hostname you can use `--hostname` option.

```sh
sh lightsail-miab-installer.sh \
  --installation-id demo \
  --az ap-southeast-1c \
  --hostname box.example.org \
  --email 'admin@example.org' \
  --password 'lightsaildemo123'
```

Mail-in-a-box recommends using `box` subdomain when configuring the hostname. For example, if your domain is `example.org` you can specify `box.example.org` as the hostname.

### Specify email and password for Administrator

To be able to use Mail-in-a-Box you need to specify Administrator's email and password for accessing Admin panel and to calls API. You can specify email using `--email` and password using `--password` option.

```sh
sh lightsail-miab-installer.sh \
  --installation-id demo \
  --az ap-southeast-1c \
  --hostname box.example.com \
  --email 'john@example.net' \
  --password 'MyEmailServer123'
```

Domain of the email doesn't have to be the same as the hostname. 

### Specify instance type

Default Lightsail plan used is $5 USD/mo with 1GB of RAM and 40GB of SSD disk. If you want to change this, you can specify using `--instance-type` option.

```sh
sh lightsail-miab-installer.sh \
  --installation-id demo \
  --az ap-southeast-1c \
  --hostname box.example.com \
  --email 'admin@example.com' \
  --password 'lightsaildemo123' \
  --instance-type 20_usd
```

Command above will use $20/mo plan, which offers 4GB of RAM, 2 Core CPU and 80GB SSD disk. You can find details about all available plans on the Amazon Lightsail [pricing page](https://aws.amazon.com/lightsail/pricing/).

### Specify availability zone

Default availability zone is `us-east-1a`. To change the availability zone you can use `--az` option, e.g `eu-west-1a` Europe (Ireland).

```sh
sh lightsail-miab-installer.sh \
  --installation-id demo \
  --az eu-west-1a \
  --hostname box.example.com \
  --email 'admin@example.com' \
  --password 'lightsaildemo123' \
  --instance-type 20_usd
```

### Restore from backup

To restore from backup, you need to specify several configurations from previous installation: 

1. Amazon S3 buckets that are used to store the mail backup and Nextcloud data
2. Mail-in-a-Box backup secret key can be found on your old box machine at `/home/user-data/backup/secret_key.txt` or in the AWS SSM Parameter Store at  `/MailInABox/miab-[INSTALLATION_ID]/BackupSecretKey`.

```sh
export LMIAB_BACKUP_SECRET_KEY='_YOUR_BACKUP_SECRET_KEY_'
export LMIAB_MAIL_BACKUP_BUCKET='_YOUR_OLD_MAIL_BACKUP_BUCKET_'
export LMIAB_NEXTCLOUD_BACKUP_BUCKET='_YOUR_OLD_NEXTCLOUD_BACKUP_BUCKET_'
```

Add `--restore` option when creating new box.

```
sh lightsail-miab-installer.sh \
  --installation-id new-demo \
  --az ap-southeast-1c \
  --hostname new-box.example.com \
  --email 'admin@new-demo.example.com' \
  --password 'lightsaildemo123' \
  --restore
```

Assuming that you will use your old IP address for your new box, you need to add a DNS A record of `new-box.example.com` to point to your old IP. Afterward, on the Amazon Lightsail instance, you should detach the static IP from the old box and assign it to the new one.

### Destroy installation

You have two options to destroy your Mail-in-a-Box installation which was installed by lightsail-miab-installer. You can use `--destroy` option as shown in the example below.

```sh
sh lightsail-miab-installer.sh \
  --installation-id demo \
  --az ap-southeast-1c \
  --destroy
```

There will be a confirmation, you need to type "yes" to destroy.

```
This action will destroy CloudFormation stack 'demo' (ap-southeast-1).
Type 'yes' to continue:
```

### Dry run mode

To execute the script in dry run mode, use the `--dry-run` option. This will print the CloudFormation template and then exit. Running the script in this mode can be beneficial for inspecting the resources that will be created.

```sh
sh lightsail-miab-installer.sh \
  --installation-id demo \
  --az eu-west-1a \
  --hostname box.example.com \
  --email 'admin@example.com' \
  --password 'lightsaildemo123' \
  --instance-type 20_usd \
  --dry-run
```

## Post installation

After the installation, there are a few things you should check:

- Ensure that the nameserver of your domain is correctly pointing to the box. The process of changing the nameserver depends on your DNS provider. Refer to your DNS provider's documentation for instructions. 
- Provision SSL certificates by logging into the Admin panel and navigating to **System &gt; TLS (SSL) Certificates**. Then, click the Provision button.
- Verify that your domain is successfully verified on Amazon SES before sending any emails. You can find more details in the ["Verified identities"](https://docs.aws.amazon.com/ses/latest/dg/verify-addresses-and-domains.htm) section of Amazon SES. Note that the verification process may take several minutes. If it takes too long, you can try removing the identity and creating a new one.
- For production use, if your Amazon SES account is still in sandbox mode, it is necessary to [request the removal of sandbox](https://docs.aws.amazon.com/ses/latest/dg/request-production-access.html) restrictions for your account.
- If you are using an external DNS service for your domain, verify that the related DNS records, such as MX, SPF, DKIM, and DMARC settings, are properly configured. These settings are crucial for email delivery and security. Ensure they are accurately set according to the guidelines provided by your DNS service or in the Mail-in-a-Box documentation.

## FAQ

### I cannot send an email, what's wrong?

Check the rejection messages for specific reasons and review the mail server logs at `/var/log/mail.log` or `/var/log/syslog` for further insights.

### I am not receiving any emails, what's wrong?

There several reason for this.

1. Make sure your MX record is pointing to the box. You can use online DNS lookup tool or from command line.
    
    ```sh
    dig +short example.com MX
    ```

    It should output the address of servers which responsible for handling the email delivery.

    ```
    10 box.example.com.
    ```
2. Check mail server log at `/var/log/mail.log` or `/var/log/syslog` for more details.
3. Make sure firewall for incoming port 25 is open both on OS and on Amazon Lightsail instance.

### The installation is stuck, what should I do?

See the log file at `.out/[REGION]-[CLOUDFORMATION_STACK_NAME]-[TIME].log`. If you did not find the issue then open CloudFormation console. Most of the time this is caused by CloudFormation failed to create a resource such as failed to create Amazon Lightsail Instance due permission issue or you do not have enough quota.

### Is it safe to delete installation via CloudFormation?

Yes it is totally safe. It will destroy all resources created by lightsail-miab-installer.

### How do I skip SSH passphrase?

lightsail-miab-installer uses SSH to connect to node in Kubernetes to perform tasks. If your SSH key having a passphrase it may quite annoying to enter the passphrase multiple times during installation process.

One of the solution is by using [ssh-agent](https://docs.github.com/en/authentication/connecting-to-github-with-ssh/generating-a-new-ssh-key-and-adding-it-to-the-ssh-agent) and ssh-add. Before running the installation, issue command below.

```sh
eval $( ssh-agent )
ssh-add /path/to/your/ssh-private.key
```

## Changelog

### v1.2 (2024-01-09)

- Bugfix: Resolved [unexpected behavior](https://github.com/rioastamal/lightsail-miab-installer/issues/3) with the `--dry-run` option.
- Bugfix: Script [no longer works](https://github.com/rioastamal/lightsail-miab-installer/issues/4) due to Ubuntu updates. Thanks to [@paulj-net](https://github.com/paulj-net) for providing the fixes.

### v1.1 (2023-08-23)

- Added support for new shell: zsh
- Added support for macOS

### v1.0 (2023-07-18)

- Automatic restore from S3 backup

### v1.0-RC1 (2023-06-20)

- Initial release candidate

## Todo

- [ ] Automatically generate TLS certificates for main domain
- [x] Automatically restore from S3 backup
- [ ] Test on different shells (dash, ~zsh~)

## Credits

This project is heavily inspired from:

- [Fully Automated Deployment of an Open Source Mail Server on AWS](https://aws.amazon.com/blogs/opensource/fully-automated-deployment-of-an-open-source-mail-server-on-aws/) by Michael Meidlinger and David Schwendemann.
- [aws-samples/aws-opensource-mailserver](https://github.com/aws-samples/aws-opensource-mailserver)

## Contributing

Fork this repo and send me a PR.

## License

This project is licensed under MIT License.