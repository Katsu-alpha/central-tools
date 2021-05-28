#!/usr/bin/python3

import sys
import argparse
import json
import pandas as pd
from time import sleep
import mylogger as log
import centralsession

Devices = {}        # key=MAC (00:11:22:aa:bb:cc format)

#
#   Exception definition
#
class InvalidServerResponse(Exception):
    pass

########################
#   utility functions
########################
def root_cause(e):
    rc = e
    while rc.__context__ is not None:
        rc = rc.__context__
    return rc

def get_mkeys(dic, *args):
    arg = [*args]
    return(dic[k] for k in arg)


def get_labels_str(arr):
    names = [l['name'] for l in arr]
    return ",".join(names)


################################################################
#   GET Inventory
################################################################
def get_endpoints(ses, url_fmt, datakey, api=False):
    limit = 50
    offset = 0
    endpoints = []

    if not url_fmt.startswith('/'):
        raise ValueError(f"invalid url: {url_fmt}")

    while True:
        if api:
            resp = ses.apiGet(url_fmt.format(limit=limit, offset=offset))
        else:
            resp = ses.nmsGet(url_fmt.format(limit=limit, offset=offset))
        j = json.loads(resp.content)

        try:
            data = j
            for k in datakey:
                data = data[k]
        except KeyError:
            raise InvalidServerResponse(f"Can't find datakey: {datakey}")

        assert(isinstance(data, list))
        endpoints.extend(data)

        try:
            count = j['count']
        except KeyError:
            try:
                count = j['data']['total']
            except KeyError:
                try:
                    count = j['data']['total_count']
                except KeyError:
                    try:
                        count = j['data']['results']['total']
                    except KeyError:
                        raise InvalidServerResponse("Total number of data is not specified.")

        if len(endpoints) >= count:
            break
        offset += limit
        sleep(0.5)          # sleep 500 msec to avoid 501 Server Error

    if len(endpoints) != count:
        print(f"Got {len(endpoints)} endpoints != count value({count})")

    return endpoints

#
#   Group
#   https://{central_ui}/groups/v2/limit/{limit}/offset/{offset}
#
def get_groups(ses):
    '''
    Centalグループの一覧を取得
        {
      "config_version": "8x",
      "configid": 1,
      "device_count": 0,
      "group_name": "default",
      "groupid": 0,
      "is_template": false,
      "mixed_template_type": {
        "CX": false,
        "IAP": false,
        "MC": false,
        "SWITCH": false
      },
      "properties": {
        "AOS_VERSION": "AOS_8X",
        "MOSW": false
      }
    },
    '''
    global Groups
    try:
        groups = get_endpoints(ses, "/groups/v2/limit/{limit}/offset/{offset}", ["groups"])
    except (InvalidServerResponse, json.decoder.JSONDecodeError) as e:
        log.err(f"Server error: {e}")
        return False

    table = []
    for g in groups:
        id, name, cfgid = get_mkeys(g, 'groupid', 'group_name', 'configid')
        table.append([id, name, cfgid, g['device_count'], "Yes" if g['is_template'] else "No"])

    Groups = pd.DataFrame(table, columns=['ID', 'Name', 'ConfigID', 'Devices', 'Template'])
    Groups.index = Groups.index + 1
    return True

#
#   AP
#   https://{central_ui}/monitor/v2/ap?limit={limit}&offset={offset}
#
def get_aps(ses):
    global APs, Devices
    try:
        aps = get_endpoints(ses, "/monitor/v2/ap?limit={limit}&offset={offset}", ["data", "results", "aps"])
    except (InvalidServerResponse, json.decoder.JSONDecodeError) as e:
        log.err(f"Server error: {e}")
        return False

    table = []
    for ap in aps:
        ip, mac, sn, name, model, grp, vc = \
            get_mkeys(ap, 'ipaddr', 'macaddr', 'serial_number', 'name', 'model', 'grp_name', 'vc_name')
        if grp == 'Unprovisioned' or grp == 'unprovisioned':
            continue                # skip if the AP belongs to 'unprovisioned' group
        if 'site' not in ap or ap['site'] is None:
            site = ''
        else:
            site = ap['site']['name']
        labels = get_labels_str(ap['labels'])
        table.append([name, model, sn, ip, mac, grp, vc, site, labels])
        Devices[mac] = {'type': 'AP', 'name': name, 'model': model, 'sn': sn}

    APs = pd.DataFrame(table, columns=['Name', 'Model', 'SN', 'IP', 'MAC', 'Group', 'VC', 'Site', 'Labels'])
    APs.index = APs.index + 1
    return True

#
#   VC
#   https://{central_ui}/groups/v2/all/swarms/limit/{limit}/offset/{offset}
#   https://{central_apigw}/monitoring/v1/swarms
#
def get_vcs(ses):
    global VCs
    try:
        vcs = get_endpoints(ses, "/groups/v2/all/swarms/limit/{limit}/offset/{offset}", ["devices"])
    except (InvalidServerResponse, json.decoder.JSONDecodeError) as e:
        log.err(f"Server error: {e}")
        return False

    table = []
    for vc in vcs:
        name, sn, mac, id, grp, confid = get_mkeys(vc, 'name', 'serial_number', 'mac_address', 'id', 'group', 'config_id')
        if grp == 'Unprovisioned' or grp == 'unprovisioned':
            continue
        table.append([name, mac, sn, id, grp, confid])

    VCs = pd.DataFrame(table, columns=['Name', 'MAC', 'SN', 'SwarmID', 'Group', 'ConfigID'])
    VCs.index = VCs.index + 1

    # try:
    #     vcs = get_endpoints(ses, "/monitoring/v1/swarms?limit={limit}&offset={offset}", ["swarms"], api=True)
    # except (InvalidServerResponse, json.decoder.JSONDecodeError) as e:
    #     log.err(f"Server error: {e}")
    #     return False
    #
    # table = []
    # for vc in vcs:
    #     name, ip, pubip, swarmid, grp = get_mkeys(vc, 'name', 'ip_address', 'public_ip_address', 'swarm_id', 'group_name')
    #     if grp == 'Unprovisioned' or grp == 'unprovisioned':
    #         continue
    #     table.append([name, ip, pubip, swarmid, grp])
    #
    # pd2 = pd.DataFrame(table, columns=['Name', 'IP', 'GIP', 'SwarmID', 'Group'])
    # pd2.index = pd2.index + 1
    # pd2.sort_values('SwarmID', inplace=True)
    # log.info(str(pd2))

    return True

#
#   Gateway
#   https://{central_ui}/monitor/v2/gateway/list?limit={limit}&offset={offset}
#
def get_gws(ses):
    global GWs, Devices
    try:
        gws = get_endpoints(ses, "/monitor/v2/gateway/list?limit={limit}&offset={offset}", ["data", "result"])
    except (InvalidServerResponse, json.decoder.JSONDecodeError) as e:
        log.err(f"Server error: {e}")
        return False

    table = []
    for gw in gws:
        ip, mac, sn, name, model, grp = get_mkeys(gw, 'ip', 'macaddr', 'serial_number', 'name', 'model_type', 'grp_name')
        if grp == 'Unprovisioned' or grp == 'unprovisioned':
            continue                # skip if the gateway belongs to 'unprovisioned' group
        if 'site' not in gw or gw['site'] is None:
            site = ''
        else:
            site = gw['site']['name']
        labels = get_labels_str(gw['labels'])
        table.append([name, model, sn, ip, mac, grp, site, labels])
        Devices[mac] = {'type': 'GW', 'name': name, 'model': model, 'sn': sn}

    GWs = pd.DataFrame(table, columns=['Name', 'Model', 'SN', 'IP', 'MAC', 'Group', 'Site', 'Label'])
    GWs.index = GWs.index + 1
    return True


#
#   Switches
#   https://{Central_ui}/groups/v2/all/switches/limit/{limit}/offset/{offset}
#   https://{Central_ui}/monitor/v2/switches?limit={limit}&offset={offset}
#
def get_switches(ses):
    global Switches, Devices
    try:
        switches = get_endpoints(ses, "/groups/v2/all/switches/limit/{limit}/offset/{offset}", ["devices"])
    except (InvalidServerResponse, json.decoder.JSONDecodeError) as e:
        log.err(f"Server error: {e}")
        return False

    table = []
    for sw in switches:
        name, mac, sn, grp, confid, stackid =\
            get_mkeys(sw, 'name', 'mac_address', 'serial_number', 'group', 'config_id', 'stack_id')
        if grp == 'Unprovisioned' or grp == 'unprovisioned':
            continue                # skip if the switch belongs to 'unprovisioned' group
        table.append([name, mac, sn, grp, confid, stackid])

    pd1 = pd.DataFrame(table, columns=['Name', 'MAC', 'SN', 'Group', 'ConfID', 'StackID'])

    try:
        switches = get_endpoints(ses, "/monitor/v2/switches?limit={limit}&offset={offset}", ["data", "results", "switches"])
    except (InvalidServerResponse, json.decoder.JSONDecodeError) as e:
        log.err(f"Server error: {e}")
        return False

    table = []
    for sw in switches:
        if 'site' not in sw or sw['site'] is None:
            site = ''
        else:
            site = sw['site']['name']
        labels = get_labels_str(sw['labels'])
        grp = sw['group']['name'] if 'name' in sw['group'] else ""
        ip, mac, sn, name, model, type =\
            get_mkeys(sw, 'ip_address', 'macaddr', 'serial', 'hostname', 'model', 'type')
        table.append([name, model, type, sn, ip, mac, grp, site, labels])
        Devices[mac] = {'type': 'SW', 'name': name, 'model': model, 'sn': sn}

    pd2 = pd.DataFrame(table, columns=['Name', 'Model', 'Type', 'SN', 'IP', 'MAC', 'Group', 'Site', 'Label'])

    Switches = pd.merge(pd1, pd2, how="left", on=["Name", "Group"], suffixes=['', '_2'])
    Switches.index = Switches.index + 1
    Switches.drop(columns=['SN_2', 'MAC_2'], inplace=True)
    return True


def get_alldevices(ses):
    get_groups(ses)
    get_aps(ses)
    get_vcs(ses)
    get_gws(ses)
    get_switches(ses)
    return


################################################################
#   main
################################################################
if __name__ == '__main__':

    parser = argparse.ArgumentParser(
        description="Get device inventory from Central")
    parser.add_argument('--debug', help='Enable debug log', action='store_true')
    parser.add_argument('--info', help='Enable informational log', action='store_true')
    args = parser.parse_args()

    if args.debug:
        log.setloglevel(log.LOG_DEBUG)
    elif args.info:
        log.setloglevel(log.LOG_INFO)
    else:
        log.setloglevel(log.LOG_WARN)

    central = centralsession.create_session()

####### list group
    print("Getting Group list... ", end="")
    if get_groups(central):
        print("done.")
    else:
        print("failed.")
        sys.exit(-1)
    print("--- Group List ---")
    print(Groups)
    print("")

####### list APs
    print("Getting AP list... ", end="")
    if get_aps(central):
        print("done.")
    else:
        print("failed.")
        sys.exit(-1)
    print("--- AP List ---")
    print(APs)
    print("")

####### list VCs
    print("Getting VC list... ", end="")
    if get_vcs(central):
        print("done.")
    else:
        print("failed.")
        sys.exit(-1)
    print("--- VC List ---")
    print(VCs)
    print("")

####### list GWs
    print("Getting GW list... ", end="")
    if get_gws(central):
        print("done.")
    else:
        print("failed.")
        sys.exit(-1)
    print("--- GW List ---")
    print(GWs)
    print("")

####### list Switches
    print("Getting Switch list... ", end="")
    if get_switches(central):
        print("done.")
    else:
        print("failed.")
        sys.exit(-1)
    print("--- Switch List ---")
    print(Switches)
    print("")

    sys.exit(0)
