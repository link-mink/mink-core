[<div align="center"><img src="http://139.162.200.34/mink.png"></div>](https://github.com/dfranusic/mink)

##### *MINK framework core components*
----
[![Build Status](https://github.com/link-mink/mink-core/actions/workflows/c-cpp.yml/badge.svg)](https://github.com/link-mink/mink-core/actions/workflows/c-cpp.yml)
[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=link-mink_mink-core&metric=alert_status)](https://sonarcloud.io/dashboard?id=link-mink_mink-core)
[![CII Best Practices](https://bestpractices.coreinfrastructure.org/projects/5232/badge)](https://bestpractices.coreinfrastructure.org/projects/5232)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

- Core components
  - [**libgdt**](#gdt-protocol-library) - GDT protocol library      
  - [**configd**](#configuration-daemon) - Configuration daemon                                                                               
  - [**cli_service**](#cli-client-shell) - CLI client shell                                                                                   
  - [**routingd**](#gdt-routing-daemon) - GDT Routing daemon                                                                                
  - [**configdc**](#config-daemon-client) - Config daemon client                                                                               
  - [**gdttrapc**](#gdt-trap-client) - GDT trap client                                                                                   

- [License](#license)

### GDT protocol library
---
GDT is a stateful stream based application layer protocol used for data communication between various MINK nodes. 
It is [defined](http://github.com/dfranusic/mink/blob/master/src/gdt/gdt.asn) using 
[ASN.1](http://en.wikipedia.org/wiki/Abstract_Syntax_Notation_One) syntax notation and carried by wire 
in binary [Basic Encoding Rules (BER)](https://en.wikipedia.org/wiki/X.690) format. At the moment, GDT 
uses  **[SCTP](https://en.wikipedia.org/wiki/Stream_Control_Transmission_Protocol)** for reliable data transfer, 
although it can be easily ported to TCP. Correct order of packets and statefulness is maintained by both 
SCTP and GDT to ensure maximum quality of packet delivery.

The overall design of the protocol was influenced by [TCAP](https://en.wikipedia.org/wiki/Stream_Control_Transmission_Protocol) 
but with various enhancements and differences. GDT supports **label** based application layer routing; 
every **end-point** is defined by a two part string label. The first part, named **id**, is a unique 
MINK node identifier string, similar to IP address of a machine. The second part is a **type** string, 
used mainly for grouping of various nodes for redundancy and load balancing purposes. MINK framework 
comes with a specialized node called **Routing daemon (routingd)** which is used mainly for GDT 
label-based routing and [Weighted round robin (WRR)](https://en.wikipedia.org/wiki/Weighted_round_robin) 
load balancing.

All GDT messages consist of two basic parts; a **Header** and a **Body**. 
Header is mandatory and is handled by the **libgdt** library and mostly not 
used by the end-user. The body of the message is where the actual data resides; 
there are many different types of message bodies and most of them are specialized 
and used internally by MINK framework. User generated data is transferred in 
a **ServiceMessage** body; every service message stream contains a user defined
**service-id** value used for data classification.

```asn1
-- ============
-- GDT Message
-- ============
-- header       - packet header
-- body         - packet body
GDTMessage ::= SEQUENCE {
        header          Header,
        body            Body OPTIONAL,
        ...
}

-- ===========
-- GDT Header
-- ===========
-- version       - GDT version
-- source        - source information
-- destination   - destination information
-- uuid          - universally unique identifier (UUID)
-- sequence-num  - sequence number
-- sequence-flag - packet sequence information (stateful/stateless/etc.)
-- enc-info      - encryption information
-- hop-info      - hop counter
-- status        - error code
Header ::= SEQUENCE {
        version       [0] INTEGER,
        source        [1] EndPointDescriptor,
        destination   [2] EndPointDescriptor,
        uuid          [3] OCTET STRING,
        sequence-num  [4] INTEGER,
        sequence-flag [5] SequenceFlag,
        enc-info      [6] EncryptionInfo OPTIONAL,
        hop-info      [7] HopInfo OPTIONAL,
        status        [8] ErrorCode OPTIONAL,
        ...
}

-- =========
-- GDT Body
-- =========
-- encrypted-data        - Encrypted GDT body, used only when content is encrypted (header.encryption)
-- packet-fwd            - General packet forwarding, used for routing and failovers
-- filter                - Filtering service, mostly used but not limited to SMS
-- data-retention        - Data retention service, used for DB storage
-- general               - Reserved for custom daemons and/or future use
-- conf                  - Configuration daemon service
-- stats                 - Statistical data exchange
-- auth                  - Authentication messages, used for daemon authentication
-- reg                   - Registration messages, used for daemon discovery and various 
--                         registration procedures
-- ntfy                  - Various notification/alarm/etc. messages
-- data                  - payload data exchange
-- routing               - routing related messages
-- service-msg           - service related messages
-- state-msg             - statefulness related messages
Body ::= CHOICE {
        encrypted-data  [1] OCTET STRING,
        packet-fwd      [2] PacketFwdMessage,
        filter          [3] FilterMessage,
        data-retention  [4] DataRetentionMessage,
        conf            [6] ConfigMessage,
        stats           [7] StatsMessage,
        auth            [8] AuthMessage,
        reg             [9] RegistrationMessage,
        ntfy            [10] NotifyMessage,
        data            [11] DataMessage,
        routing         [12] RoutingMessage,
        service-msg     [13] ServiceMessage,
        state-msg       [14] StateMessage,
        ...
}

```

### Configuration parser library
---
MINK Configuration parser library is a core component used primarily by **Configuration daemon (configd)**. 
When designing a system on top of MINK framework, configuration definition is always a good starting point. There
are two types of configuration files used by configd; **definition** and **contents**. 

Definition file is used to describe the structure of data stored in the contents file. Proper definition ensures data
integrity and avoids unnecessary implementations of custom data validators in user specific daemons. Both types
of configuration files share a similar structure and are parsed using the same grammar. Default extension for MINK
configuration files is ``.mink``; a standard naming convention used in this project is to add a `_def` suffix to
base name of definition file (e.g. ``mink_def.pmcfg`` for definition and ``mink.pmcfg`` for contents).

The following example shows a simple configuration showing **3 main types** of configuration items:

* **primitive**
  - single field container whose type is defined in the **TYPES** section of configuration definition file
* **block** 
  - a storage container similar to a file system directory, defined with **CONST** keyword and used mostly for grouping
* **dynamic block**
  - special storage container identified by a **"*"** (star) symbol; serves a purpose of being a **template** node for 
    dynamic creation of block nodes

###### Configuration definition "mink_def.pmcfg"
```c
// data types   
TYPES {         
  // each type is defined by perl-type regex
  "INT"     PTRN\d+PTRN  "Number type" 
  "STRING"  PTRN.*PTRN   "Alphanumeric type"
}                               
                                        
// config structure                     
CONFIG {                                        
  // global parameter                           
  test_global  "INT"  "Global INT parameter"            
                                                                
  // static sub node                                           
  local CONST  "Local group" {                
    test_local  "INT"  "Local INT parameter"    
  }                             

  // dynamic nodes
  dynamic CONST "Dynamic container node" {
    dynamic_child * "STRING" "Dynamic child node" {
      test "INT" "Test INT parameter"
    }
  }
}
```

###### Configuration contents "mink.pmcfg"
```c
test_global "10"
local {
  test_local "666"
}
dynamic {
  node_1 {
    test "10"
  }
  node_2 {
    test "20"
  }
}
```
### Configuration daemon
---
Configuration daemon is a MINK daemon used for configuration management and is a central most important service
of this framework. These are the main features of configd:

* configuration file management
* replication of configuration data 
* **ACID** like properties for configuration transactions (**COMMIT/DISCARD/ROLLBACK**)
* real-time distribution of configuration data to all affected daemons 
  - each MINK daemon attaches itself to its own subset of configuration nodes; smart configuration definition will play a
    vital role in minimizing bandwith usage for configuration data 
  - when configuration data is changed in some way (using MINK Command Line Interface), all connected daemons 
    that are affected with that particular modification, are notified
  - configuration data can grow quite a bit  and is therefore advised for each daemon to attach itself to its own subset of 
    configuration defintion (e.g. STP daemon should not get any configuration data related to GDT routing)

###### configd command line arguments
```bash
config_daemon - MINK Configuration daemon

Options:
 -?	help
 -i	unique daemon id
 -p	GDT inbound port
 -d	configuration definition file
 -c	configuration contents file
 -r	routing daemon address (ipv4:port)
 -n	other config daemon id
 -t	user timeout in seconds
 -D	debug mode
 -R	enable routing

GDT Options:
=============
 --gdt-streams		GDT Session stream pool		(default = 1000)
 --gdt-stimeout	GDT     Stream timeout in seconds       (default = 5
```

###### configd example
```bash
$ ./configd -i cfg1 -p 10000 -d /tmp/test_def.pmcfg -c /tmp/test.pmcfg -R
```
This will start **configd** with the following parameters set:

- MINK unique daemon id = **cfg1**
- SCTP listening port = **10000**
- configuration definition file = **/tmp/test_def.pmcfg**
- configuration contents file = **/tmp/test.pmcfg** 
- **-R** flag is used when configd should accept connections directly and not via **routingd** 

### CLI client shell
---
MINK Command Line Service (CLI) is a specialized shell used for interaction with configd; it features a powerful
TAB activated auto-complete and was inspired by [CISCO](http://www.cisco.com) and [Vyatta](http://vyos.io/) command line interfaces.

###### cli_service command line arguments
```bash
cli_service - MINK CLI service

Options:
 -i	unique service id
 -f	cli definition file
 -c	config daemon address (ipv4:port)
```

###### cli_service example
```bash
$ ./cli_service -i cli1 -f /tmp/cli_default.pmcfg -c 127.0.0.1:10000
```

This will start **cli_service** with the following parameters set:

- MINK unique daemon id = **cli1**
- CLI definition file = **/tmp/cli_default.pmcfg**
- configd IP address and listening port = **127.0.0.1:10000**

CLI definition file is used for defining commands and modules available to the user.  At the moment, **cli_service** uses only one 
available plugin; **pm\_plg\_cli\_cfg.so** module is used for **cli <---> configd** communication. 

### GDT Routing daemon
---
Routing daemon is a general purpose GDT router; it is used for **label** based GDT routing and load balancing. The most common type
of setup assumes the following:

- two routing daemons (or one if redundancy is not an issue)
- one config daemon
- any number of user daemons

In this setup, **routingd** connects directly to **configd** while other daemons involved in this setup connect only to **routingd**. 
Routing daemon facilitates all **daemon-to-daemon** communication, takes care of **load balancing** (if used), and creates an extra 
layer of security for **configd**. Direct connection to **configd** is established only by **routing**, all other daemons communicate 
with **configd** via **routingd**.

###### routingd command line arguments
```bash
routingd - MINK Routing daemon

Options:
 -?	help
 -i	unique daemon id
 -c	config daemon address (ipv4:port)
 -p	GDT inbound port
 -D	start in debug mode

GDT Options:
=============
 --gdt-streams		GDT Session stream pool		(default = 1000)
 --gdt-stimeout	        GDT Stream timeout in seconds	(default = 5)
```

###### routingd example
```bash
$ ./routingd -i rtr1 -c 127.0.0.1:10000 -p 15000
```

This will start **routingd** with the following parameters set:

- MINK unique daemon id = **rtr1**
- configd IP address and listening port = **127.0.0.1:10000**
- SCTP listening port = **15000**

### Config daemon client
---
Configuration daemon client is an alternative interface to **configd**. Unlike **cli_service** which is interactive, **configdc** 
is a script based client used by 3rd party applications like WEB GUIs and shell scripts. Script format used by **configdc** is a 
simple text file containing a list of commands to be sent to **configd**. Commands are processed sequentially and results are 
outputted to standard output. The resulting output is generated for each command found in a script file; commands are outputted 
with a **: (colon)**  prefix  and their results follow in the next line, unmodified. If an error occurs, **configd** will do an 
automatic **discard** of the whole transaction, and the resulting output will start with **"ERROR:"**, followed by the 
actual error message generated by **configd**.


###### configdc command line arguments
```bash
cfgdc - MINK Config daemon client

Options:
========
 -?	help
 -i	unique daemon id
 -f	config daemon command script file
 -r	routing daemon address (ipv4:port)
 -D	start in debug mode

GDT Options:
=============
 --gdt-streams		GDT Session stream pool		(default = 1000)
 --gdt-stimeout	        GDT Stream timeout in seconds	(default = 5)
```

###### configdc example (success)
```bash
$ cat /tmp/test.txt
configuration
show dyn node_1 test

$ ./configdc -i cfgc1 -r 127.0.0.1:10000 -f /tmp/test.txt
: configuration
test_global "10"
local {
	test_local "666"
}
dynamic {
	node_1 {
		test "10"
	}
	node_2 {
		test "20"
	}
}

: show dyn node_1 test
test = 10
```

This will start **configdc** with the following parameters set:

- MINK unique daemon id = **cfgc1**
- configd (or routingd) IP address and listening port = **127.0.0.1:10000**
- script file with the list of commands to send to configd = **/tmp/test.txt**


###### configdc example (error)
```bash
$ cat /tmp/test_err.txt
configuration
show dyn node_1 testbla

$ ./configdc -i cfgc1 -r 127.0.0.1:10000 -f /tmp/test_err.txt
: configuration
test_global "10"
local {
	test_local "666"
}
dynamic {
	node_1 {
		test "10"
	}
	node_2 {
		test "20"
	}
}

: show dyn node_1 testbla
ERROR: Unknown item or command "testbla"!
```

This will start **configdc** with the following parameters set:

- MINK unique daemon id = **cfgc1**
- configd (or routingd) IP address and listening port = **127.0.0.1:10000**
- script file with the list of commands to send to configd = **/tmp/test_err.txt**

### GDT trap client
---
GDT Trap client is a tool used for fetching MINK performance counters. Daemons can expose various
counters which are usually required for performance tracking and trouble shooting. MINK framework uses
its own system for counters; it is an GDT protocol extension quite similar but not as powerful as
[SNMP](https://en.wikipedia.org/wiki/Simple_Network_Management_Protocol). Most production environments
use their own 3rd party monitoring tools; creating wrapper scripts to convert **gdttrapc** output to 
SNMP compatible data should not be a big issue.

###### gdttrapc command line arguments

```bash
gdttrapc - MINK GDT trap client

Options:
 -c	target daemon address (ipv4:port)
 -t	target daemon type
 -i	target daemon id
 -s	target trap id (0 for ALL)
 -a	unique client id

GDT Options:
=============
 --gdt-streams		GDT Session stream pool		        (default = 10)
 --gdt-stimeout	        GDT Stream timeout in seconds		(default = 5)
 --gdt-smsg-pool	GDT Service message pool		(default = 10)
 --gdt-sparam-pool	GDT Service message parameter pool	(default = 1000)
```


###### gdttrapc example (specific counter)

```bash

$ ./gdttrapc -c 127.0.0.1:15000 -t routingd -i rtr1 -s GDT_IN_config_daemon_cfg1_BYTES -a trapc1
                         Trap Id                    Trap Value
-------------------------------------------------------------
GDT_IN_config_daemon_cfg1_BYTES                           140

```

This will start **gdttrapc** with the following parameters set:

- routingd IP address and listening port = **127.0.0.1:10000**
- **type label** of target daemon to fetch counters from = **routingd**
- **id label** of target daemon to fetch counters from = **rtr1**
- counter id (multiple **-s** supported) to fetch = **GDT_IN_config_daemon_cfg1_BYTES**
- trap client's unique daemon id = **trapc1**


###### gdttrapc example (all counters)

```bash
$ ./gdttrapc -c 127.0.0.1:15000 -t routingd -i rtr1 -s 0 -a trapc1
                                      Trap Id                    Trap Value
----------------------------------------------------------------------------
                 GDT_IN_%routingd_%rtr1_BYTES                            441
             GDT_IN_%routingd_%rtr1_DISCARDED                            0
             GDT_IN_%routingd_%rtr1_MALFORMED                            0
               GDT_IN_%routingd_%rtr1_PACKETS                            5
              GDT_IN_%routingd_%rtr1_POOL_ERR                            0
            GDT_IN_%routingd_%rtr1_SOCKET_ERR                            0
               GDT_IN_%routingd_%rtr1_STREAMS                            1
          GDT_IN_%routingd_%rtr1_STREAM_BYTES                            192
            GDT_IN_%routingd_%rtr1_STREAM_ERR                            0
       GDT_IN_%routingd_%rtr1_STREAM_LOOPBACK                            0
        GDT_IN_%routingd_%rtr1_STREAM_TIMEOUT                            0
           GDT_IN_gdttrapc_trapc117815_BYTES                             0
       GDT_IN_gdttrapc_trapc117815_DISCARDED                             0
       GDT_IN_gdttrapc_trapc117815_MALFORMED                             0
         GDT_IN_gdttrapc_trapc117815_PACKETS                             0
        GDT_IN_gdttrapc_trapc117815_POOL_ERR                             0
      GDT_IN_gdttrapc_trapc117815_SOCKET_ERR                             0
         GDT_IN_gdttrapc_trapc117815_STREAMS                             0
    GDT_IN_gdttrapc_trapc117815_STREAM_BYTES                             0
      GDT_IN_gdttrapc_trapc117815_STREAM_ERR                             0
 GDT_IN_gdttrapc_trapc117815_STREAM_LOOPBACK                             0
  GDT_IN_gdttrapc_trapc117815_STREAM_TIMEOUT                             0
                GDT_OUT_%routingd_%rtr1_BYTES                            815
            GDT_OUT_%routingd_%rtr1_DISCARDED                            0
            GDT_OUT_%routingd_%rtr1_MALFORMED                            0
              GDT_OUT_%routingd_%rtr1_PACKETS                            7
             GDT_OUT_%routingd_%rtr1_POOL_ERR                            0
           GDT_OUT_%routingd_%rtr1_SOCKET_ERR                            0
              GDT_OUT_%routingd_%rtr1_STREAMS                            0
         GDT_OUT_%routingd_%rtr1_STREAM_BYTES                            0
           GDT_OUT_%routingd_%rtr1_STREAM_ERR                            0
      GDT_OUT_%routingd_%rtr1_STREAM_LOOPBACK                            0
       GDT_OUT_%routingd_%rtr1_STREAM_TIMEOUT                            0
          GDT_OUT_gdttrapc_trapc117815_BYTES                             0
      GDT_OUT_gdttrapc_trapc117815_DISCARDED                             0
      GDT_OUT_gdttrapc_trapc117815_MALFORMED                             0
        GDT_OUT_gdttrapc_trapc117815_PACKETS                             0
       GDT_OUT_gdttrapc_trapc117815_POOL_ERR                             0
     GDT_OUT_gdttrapc_trapc117815_SOCKET_ERR                             0
        GDT_OUT_gdttrapc_trapc117815_STREAMS                             0
   GDT_OUT_gdttrapc_trapc117815_STREAM_BYTES                             0
     GDT_OUT_gdttrapc_trapc117815_STREAM_ERR                             0
GDT_OUT_gdttrapc_trapc117815_STREAM_LOOPBACK                             0
 GDT_OUT_gdttrapc_trapc117815_STREAM_TIMEOUT                             0

```

This will start **gdttrapc** with the following parameters set:

- routingd IP address and listening port = **127.0.0.1:10000**
- **type label** of target daemon to fetch counters from = **routingd**
- **id label** of target daemon to fetch counters from = **rtr1**
- counter id (multiple **-s** supported) to fetch = **0**
- trap client's unique daemon id = **trapc1**

### License
----
This software is licensed under the MIT license
