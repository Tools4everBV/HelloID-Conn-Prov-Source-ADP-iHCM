# HelloID-Conn-Prov-Source-ADP-iHCM

| :warning: Warning |
|:---------------------------|
| Note that this connector is "a work in progress" and therefore not ready to use in your production environment. |

| :information_source: Information |
|:---------------------------|
| This repository contains the connector and configuration code only. The implementer is responsible to acquire the connection details such as username, password, certificate, etc. You might even need to sign a contract or agreement with the supplier before implementing this connector. Please contact the client's application manager to coordinate the connector requirements. |
<br />
<p align="center">
  <img src="https://www.tools4ever.nl/connector-logos/adp-logo.png">
</p>
<br />

The _'HelloID-Conn-Prov-Source-ADP-iHCM'_ connector needs to be executed 'on-premises'. Make sure you have 'Windows PowerShell 5.1' installed on the server where the 'HelloID agent and provisioning agent' are running, and that the 'Execute on-premises' switch is toggled.

Note that the _'HelloID-Conn-Prov-Source-ADP-iHCM'_ implementation is based on ADP iHCM environments for the Dutch market. If you want to implement the connector for the US market, changes will have to be made within the source code.

## Table of contents

- [HelloID-Conn-Prov-Source-ADP-iHCM](#helloid-conn-prov-source-adp-ihcm)
  - [Table of contents](#table-of-contents)
  - [Introduction](#introduction)
  - [Prerequisites](#prerequisites)
  - [Getting started](#getting-started)
    - [X.509 certificate / public key](#x509-certificate--public-key)
    - [X.509 certificate / Private key](#x509-certificate--private-key)
    - [AccessToken](#accesstoken)
- [HelloID Docs](#helloid-docs)


## Introduction

ADP iHCM is a cloud based HR management platform and provides a set of REST API's that allow you to programmatically interact with it's data. The HelloID source connector uses the API's in the table below.

---

## Prerequisites

- Windows PowerShell 5.1 installed on the server where the 'HelloID agent and provisioning agent' are running.

- The public key *.pfx certificate belonging to the X.509 certificate that's used to activate the required API's.

- The password for the public key *.pfx certificate.

- The 'Execute on-premises' switch on the 'System' tab is toggled.

## Getting started

### X.509 certificate / public key

To get access to the ADP iHCM API's, a x.509 certificate is needed. This certificate has to be created by the customer.

The public key belonging to the certificate, must be send ADP. ADP will then generate a ClientID and ClientSecret and will activate the required API's.

There are a few options for creating certificates. One of them being the 'OpenSSL' utility. Available on Linux/Windows. https://www.openssl.org/

### X.509 certificate / Private key

The private key (*.pfx) belonging to the X.590 certificate must be used in order obtain an accesstoken.

### AccessToken

In order to retrieve data from the ADP iHCM API's, an AccessToken has to be obtained. The AccessToken is used for all consecutive calls to ADP iHCM. To obtain an AccessToken, we will need the ___ClientID___, ___ClientSecret___, ___The path to your pfx certificate___ and the ___password for the pfx certificate___.

Tokens only have access to a certain API scope. Default the scope is set to: 'worker-demographics organization-departments'. Data outside this scope from other API's cannot be retrieved

# HelloID Docs
The official HelloID documentation can be found at: https://docs.helloid.com/
