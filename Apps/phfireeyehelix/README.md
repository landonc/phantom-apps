# FireEye Helix Connector

## Description
FireEye Helix is a SIEM + SOAR platform.  Currently the connector enables the ingestion of Helix alerts into Phantom for Phatom based case management and security orchestation and automation.

## Supported Actions

`on_poll` - ingest alerts as events with the alert detail information parsed to CEF fields and mapping phantom "cef contains" identifiers where possible

## Modify CEF Mapping
To add/change/remove a CEF mapping you can modify the FIREEYEHELIX_CEF_MAPPING constant located in fireeyehelix_consts.py.  Below is an example of how to remap a field in the alert to a new name and/or add the cef_contains keys for the field.

Full Modifcation

    "accountname": {"cef_name": "user", "cef_contains": ["user name"]}

Rename only, no Phantom contains

    "accountname": {"cef_name": "user"}

Add Phantom "contains" and don't rename

    "accountname": {"cef_contains": ["user name"]}

## To-Do

- [ ] Pull Alert Details from Helix alert ID
- [ ] Control HX Endpoint containment state