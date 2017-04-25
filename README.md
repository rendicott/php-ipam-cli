# pySser
"IP better with pySser"

Latest version: 1.0
Author: Rendicott@gmail.com

Script to interact with the [phpIpam](http://phpipam.net/) [API](http://phpipam.net/api-documentation/). 

## Features
- Import data from CSV and import into phpIpam
- Use as an Ansible inventory script.
-- Can pass filter parameters to pull specific subsets of the phpIpam database and return as Ansible inventory
- Delete subnets from phpIpam
- Claim and Release IP's with script parameters

## Updates
- 20160721_Added mac address field support on import address.

## PreReqs
Needs: Python 2.7, ConfigParser and Requests

> **NOTE**: (Tested against phpIpam v1.2)

## Usage

Call help with the --help parameter

```

python pysser.py --help

Usage: pysser.py [--debug] [--printtostdout] [--logfile] [--version] [--help] [--samplefileoption]
Interacts with the phpIpam API as defined in the config file INI. Calling with no options
 will simply load data from the system.

Options:
  --version             show program's version number and exit
  -h, --help            show this help message and exit
  -c FILE, --configfile=FILE
                        REQUIRED: config ini file. See sample. (default =
                        'runningconfig.ini'
  --filtersubnet=FILTERSUBNET
                        When loading addresses limit load to a single subnet
                        e.g., '10.119.6.0'. This flag overrides the
                        'filter_subnet' setting within the config file.
                        (Default: None)
  --searchhostname=SEARCHHOSTNAME
                        Searches inventory for given hostname  e.g.,
                        'MYMACHINE'. NOTE: filters still apply first
                        (Default: None)
  --subnetfile=FILE     CSV File from which to import new subnets into the
                        default section. (Default: None)
  --addressfile=FILE    CSV File from which to import new addresses into the
                        default section. (Default: None)
  --deletesubnets       Boolean flag. If this option is present then all
                        subnets in the default_section will be DELETED
                        (default=False)
  --list                Boolean flag. If this option is present then the
                        Ansible formatted inventory will be be printed to
                        stdout (default=False)
  --nohostnamevalidation
                        Boolean flag. If this option is present then no
                        hostname rule checking will be  performed
                        (default=False)
  --claimip=CLAIMIP     Claim IP and assign hostname. Syntax is ip:hostname.
                        E.g., '10.119.6.145:MYMACHINE01.   (Default = None)
  --modifyip=MODIFYIP   Modify IP and change hostname. Syntax is ip:hostname.
                        E.g., '10.119.6.145:MYMACHINE01.   (Default = None)
  --capsv=CAPSV         Custom attribute pipe separated string. Used primarily
                        with --claimip and --modifyip. Will attempt to set the
                        keyvalue data given to match the custom attributes
                        defined in the INI file. Example:
                        'cdl_isprod:0|cdl_autodelete:0|cdl_dhcp:1'
                        (Default=None
  --releaseip=RELEASEIP
                        Release IP delete all associated information including
                        hostname and additional attributes. Syntax is 'ip'.
                        E.g., '10.119.6.145' (Default=None)
  --firstavailable=FIRSTAVAILABLE
                        Searches for and claims the first available IP in a
                        given subnet and sets the hostname and any additional
                        custom attributes with the --capsv string. If no
                        filter_subnet is specified via --filtersubnet or
                        'filter_subnet' in config file then this function will
                        return an error. E.g. '--firstavailable MYHOSTNAME
                        --capsv cdl_isprod:0|cdl_autodelete:0|cdl_dhcp:1' OR
                        '--firstavailable MYHOSTNAME --filtersubnet
                        10.119.125.0' (Default=None)

  Debug Options:
    -d DEBUG, --debug=DEBUG
                        Available levels are CRITICAL (3), ERROR (2), WARNING
                        (1), INFO (0), DEBUG (-1)
    -p, --printtostdout
                        Print all log messages to stdout
    -l FILE, --logfile=FILE
                        Desired filename of log file output. Default is
                        "pysser.py.log"


```

Specify a config file with the `--configfile` parameter. See 'Config File' section for more detailed information on config files.

Specify a single subnet to retrieve from the phpIpam instance with the `--filtersubnet` parameter. Currently this parameter only supports a single /24 subnet in the '192.168.1.0' syntax. This parameter overrides the `filter_subnet` configuration setting within the config file ini.
Example:

```

python pysser.py --configfile myconfig.ini --filtersubnet 10.119.6.0

```

To search for a single hostname to see if it exists in the phpIpam database use the `--searchhostname` parameter. This only supports a single hostname and must be a case insensitive exact match. All filters specified in config file still apply.
Example:

```

python pysser.py --configfile myconfig.ini 

```


When the `--subnetfile` parameter is present the script assumes you wish to import those subnets into the phpIpam database. If the subnets already exist in the database then the script will just continue on to the next subnet in the file. 

When the `--addressfile` parameter is present the script assumes you wish to import those IP addresses into the phpIpam database. If the address already exists in the database then the script will just continue on to the next IP.

> **NOTE:** The script will only interact with the phpIpam 'Section' specified in the `default_section` entry specified in the config file. See phpIpam documentation for more information on 'Sections'

The `--deletesubnets` parameter will delete all subnets in the default_section. It will ask for confirmation before doing this. 

The `--list` parameter is specifically designed for Ansible support and will cause the script to read the default config file ('runningconfig.ini' in the same directory as the script) for options and return a JSON inventory from the query. This way you can use pySser as the Ansible inventory script as described in the Ansible documentation. 

> **NOTE:** No other parameters will be processed if the `--list` option is passed because when Ansible calls a script as inventory it doesn't support other parameters except `--list`.

The `--claimip` parameter lets you claim a specific ip. Syntax is "ip:hostname". 

Example:

`python pysser.py --claimip 10.119.125.10:VMCOOLMACHINE`

The `--releaseip` parameter lets you release a specific ip. Syntax is "ip"

The '--nohostnamevalidation' turns off the 15 character "no underscores" rules for checking hostnames. This is experimental bus should allow you to enter larger hostnames if needed.

The '--modifyip' parameter allows you to modify an existing entry in the database. Syntax is IP:HOSTNAME as outlined in the --help. '--modifyip' also supports '--capsv' strings so you can modify custom attributes.



Example:

`python pysser.py --releaseip 10.119.125.10`

### DEBUG OPTIONS
Specify debug level with `--debug={-1,0,1,2,3}` for `{DEBUG,INFO,WARNING,ERROR,CRITICAL}` respectively.

Specify whether you want debug printed to stdout when the script runs by passing the `--printtostdout` flag.

Specify whether you want to log to a different location with the `--logfile` parameter. By default everything logs to a file *pysser.py.log* in the same directory as the script and is overwritten on each execution. 

## Config File

Included is a *sampleConfig.ini* which has examples and some comments. 

`sampleConfig.ini`

```

[global]
# https is required. All API calls expect it.
base_url: https://phpipam.mycompany.com/phpipam
# the app_id that you have set up in your phpIpam API applications
#  see: http://phpipam.net/api-documentation/
app_id: sampleapplication
username: user
password: P4ssw0rd
# the default section in which to interact with the API
default_section: test
# if you want only a specific subnet you can specify here
filter_subnet: 10.119.6.0

[ansible]
# subnets to ignore on inventory export separated by comma
#   for example, 10.119.0.0 to ignore iLO addresses
#   and 10.119.131.0 to ignore private IPs
export_ignore_subnets: 10.119.0.0,10.119.131.0,10.119.130.0,192.168.175.0

# list of hostnames separated by comma to ignore on export
#   for example, some hostnames in inventory are listed
#   as "RESERVED" or "GATEWAY" so we don't care about those
export_ignore_hostnames: RESERVED

##### EXPERIMENTAL CUSTOM ATTRIBUTES ############
# define custom attributes within phpIpam and what default values should be for loading
# currently this only applies to addresses. All sections with [custom_attribute_*] in the
# section name will be processed. All sections must be unique as long as they follow the
# [custom_attribute_*] format.
# ****boolean types must be a numeric 0 or 1
[custom_attribute_01]
attribute_name: cdl_isprod
attribute_type: bool
attribute_default_value: 1

[custom_attribute_02]
attribute_name: cdl_grabbed_by
attribute_type: text
attribute_default_value: None

# define custom filters for when the script is run with the --list parameter (ansible)
# this will allow you to only return entries with the desired value by default
[custom_filter_01]
attribute_name: cdl_ansible_ignore
attribute_desired_value: 0

```

* `base_url`: This is the URL of your phpIpam instance. The API calls assume that there will be and HTTP AUTH so therefore the API app_id and app_security need to be set to SSL or NONE. This has only been tested with HTTPS but according to the phpIpam documentation the app_id's app_security should be able to be set to NONE and you could use HTTP instead of HTTPS.
* `app_id`: This is the application ID that you set up in the 'API Management' section of phpIpam Admin page. This is tested working against an app with the following phpIpam API app settings:

|   setting      |       value           |
|----------------|-----------------------|
|App Id          | sampleapplication     |
|App Code        | Not Used              |
|App permissions | Read / Write / Admin  |
|App Security    | SSL                   |

> **NOTE:** See http://phpipam.net/api-documentation/ for more detailed information.

* `username` and `password` : These are pretty self explanatory. Currently pySser has no support for the *crypt* functionality with the phpIpam API applications.
* `default_section`: If you're familiar with phpIpam you know that there is a concept of 'Sections'. These are large organizational which you can use to break up your IPv4 environment. Subnets can be duplicated across sections. pySser needs to know which section to work with. At this time pySser does not support working with multiple sections in a single session. 
* `filter_subnet` : Set this if you want to filter results down to a single subnet. This only supports /24 subnets for now. This setting is overridden by the `--filtersubnet` cmd line parameter.

`[ansible]` Section
This section was added for ansible specific stuff but it will affect the return results for all queries. 

* `export_ignore_subnets` : This is comma separated list of subnets to ignore when returning results. This is to handle the situations where a single hostname has an IP in multiple subnets. Somtimes those addresses are unreachable by Ansible anyway (e.g., iLo addresses and private network NICs) so we really don't care to return those.
* `export_ignore_hostnames` : This is a comma separated list of hostnames to ignore when returning results. This was added to ignore certain 'hostnames' stored in the database such as 'RESERVED' or 'GATEWAY' that aren't really hostnames we care about for Ansible results.

`[custom_attribute_*]` Section

This section is for defining the custom attributes you have set in phpIpam. For example: If you wanted to filter on an attribute called 'cdl_ansible_ignore' you could define it here then set up a filter in the `[custom_filter_*]` section. This attribute will be read during the 'python pysser.py --list' workflow and any entry with that flag will be ignored.
However, we needed a way to make pySser aware of the custom attributes without having to hard code the entries. Therefore, the list of custom attributes you define in the INI file will be looped through and referenced in most
of the pySser code. NOTE: This currently only supports custom attributes in the Address object within phpIpam. Custom attributes in phpIpam's Sections, Subnets, Vlans, etc are ignored.

NOTE: The 'attribute_type' field is currently not used and totally ignored.

See concrete examples in 'sampleConfig.ini'

`[custom_filter_*]` Section

This section affects the '--list' parameters output. Filters defined here currently work on an "positive inclusion" principle where only attributes with the desired value wil be returned. I may add a variation to support "negative exclusion" later.

For example if you had a custom attribute in phpIpam called 'cstm_experimental' and you wanted to ignore all entries that matched that you would have to make the following files have these modifications:

'runningconfig.ini'

```

[custom_attribute_09]
attribute_name: cstm_experimental
attribute_type: boolean
attribute_default_value: 1

[custom_filter_04]
attribute_name: cstm_experimental
attribute_desired_value: 0

```

That would be good enough for working with existing inventory but if you wanted to import and bulk load your custom attributes you would need to make your csv look like this:

'iventory.csv'

```

Ip,Name,Metadata,Description,mac,cstm_experimental
10.119.125.0,,SUBNET ADDRESS,,1
10.119.125.1,,USED,,1
10.119.125.2,,AVAILABLE,,1
10.119.125.3,,USED,awesome box,00:45:EF:1A:6C:AD,0


```


## Import CSV Formatting

The format of the CSV files for import are described as follows:

`--subnetfile` format:

```

subnet
10.119.23.0/24
10.119.4.0/24
10.119.20.0/24
10.119.200.0/24
10.119.123.0/24

```

`--addressfile` format:

For now the only addresses that will be loaded from the address file CSV are thos with the string 'USED' in the 'Metadata' field (third column) since phpIpam already handles creating all of the unused addresses for a given subnet. 

If no hostname is given in the 'Name' column then pySser will auto generate a hostname in the form 'UNKNOWN-n' with an incrementing counter that starts on script load. Example: The first three IPs with unknown hostnames will be listed as 'UNKNOWN-1', 'UNKNOWN-2', and 'UNKNOWN-3'

If there are custom attributes specified in the config INI file then the importer will try to process columns with the header of the custom 'attribute_name'. For now all values will be processed as strings. phpIpam seems to treat everything as strings so this works for now.



```

Ip,Name,Metadata,Description,ReservedBy,ReservedOn,IsProduction,IsTaken,cdl_isprod,cdl_autodelete,cdl_dhcp,mac
10.119.125.0,,SUBNET ADDRESS,,,,,,1,0,0,00:45:EF:1A:6C:AD
10.119.125.1,,USED, ,,,,,1,0,0,00:45:EF:1A:6C:AD
10.119.125.2,,AVAILABLE,,,,,,1,0,0,
10.119.125.198,FBUATLISTENER.CL.LOCAL,USED,,,,,,1,0,0,00:45:EF:1A:6C:AD
10.119.125.199,VMFBUATPORTAL03.CL.LOCAL,USED,,,,,,1,0,0,00:45:EF:1A:6C:AD
10.119.125.200,JSHPSAN01.CL.LOCAL,USED,,,,,,1,0,0,00:45:EF:1A:6C:AD
10.119.125.201,JSHPSAN01.CL.LOCAL,USED,,,,,,1,0,0,00:45:EF:1A:6C:AD
10.119.125.202,Z011.CDL.COM,USED,,,,,,1,0,0,00:45:EF:1A:6C:AD
10.119.125.203,Z012.CDL.COM,USED,,,,,,1,0,0,00:45:EF:1A:6C:AD
10.119.125.204,Z013.CDL.COM,USED,,,,,,1,0,0,00:45:EF:1A:6C:AD
10.119.125.205,Z014.CDL.COM,USED,,,,,,1,0,0,00:45:EF:1A:6C:AD
10.119.125.206,Z015.CDL.COM,USED,,,,,,1,0,0,00:45:EF:1A:6C:AD
10.119.125.207,Z016.CDL.COM,USED,,,,,,1,0,0,00:45:EF:1A:6C:AD
10.119.125.208,Z017.CDL.COM,USED,,,,,,1,0,0,00:45:EF:1A:6C:AD
10.119.125.209,Z018.CDL.COM,USED,,,,,,1,0,0,00:45:EF:1A:6C:AD
10.119.125.210,JSESXHOST09.CL.LOCAL,USED,,,,,,1,0,0,00:45:EF:1A:6C:AD
10.119.125.211,Z019.CDL.COM,USED,,,,,,1,0,0,00:45:EF:1A:6C:AD
10.119.125.212,JSMITH-LT.CL.LOCAL,USED,,,,,,1,0,0,00:45:EF:1A:6C:AD
10.119.125.213,JSDEVQAEDWSQL01.CL.LOCAL,USED,,,,,,1,0,0,00:45:EF:1A:6C:AD
10.119.125.214,Z021.CDL.COM,USED,,,,,,1,0,0,00:45:EF:1A:6C:AD
10.119.125.215,Z022.CDL.COM,USED,,,,,,1,0,0,00:45:EF:1A:6C:AD
10.119.125.216,DONAG0.CL.LOCAL,USED,DevOps Nagios build/test used by Bamboo,,,,,1,0,0,00:45:EF:1A:6C:AD
10.119.125.217,DONAG1.CL.LOCAL,USED,DevOps Nagios VM,,,,,1,0,0,00:45:EF:1A:6C:AD
10.119.125.218,DOPUP1.CL.LOCAL,USED,DevOps Puppet Experiment,,,,,1,0,0,00:45:EF:1A:6C:AD
10.119.125.219,CLSTASH01.CL.LOCAL,USED,New Stash server as of 20150908,,,,,1,0,0,00:45:EF:1A:6C:AD
10.119.125.220,DOGRAPH1,USED,DevOps Graphite data collection app/db server,,,,,1,0,0,00:45:EF:1A:6C:AD
....

```

## Future Enhancements
* Export/Import to/from phpIpam via
