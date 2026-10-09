#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Vulnerability DB updater

Gets all feeds from NVD and aggregates all into a single DB.

NVD update timestamps are taken into consideration for selecting DB updates

"""

import requests
import re
import io
import zipfile
import gzip
import json
import os
from datetime import datetime

regenerate_single_file_dbs = False

nvd_base_url = "https://nvd.nist.gov"
nvd_data_feeds = f"{nvd_base_url}/vuln/data-feeds"

my_dbs = "databases"
csv_full_db = f"{my_dbs}/all.aggregated.csv.gz"
json_full_db = f"{my_dbs}/all.aggregated.json.gz"

print(f"Checking local dabatases at {my_dbs}")
if os.path.exists(my_dbs):
    dbs = os.listdir(my_dbs)
else:
    os.makedirs(my_dbs)
    dbs = []
    regenerate_single_file_dbs = True

# get feeds' url
print(f"Getting NVD list of feeds from {nvd_data_feeds}")
all_feeds = requests.get(nvd_data_feeds)
my_feeds = re.findall(r'/feeds/json/cve/1.1/nvdcve-1.1-.[0-9]+.json.zip', all_feeds.text)

cache_db = {}
for feed in my_feeds:
    get_url = f'{nvd_base_url}{feed}'

    print(f"Fetching NVD feed {feed}")
    r = requests.get(get_url)
    r.raise_for_status()
    z = zipfile.ZipFile(io.BytesIO(r.content))

    for filename in z.namelist():
        nvd_db = json.loads(z.read(filename))
        if filename+".gz" in dbs:
            try:
                with gzip.open(f"{my_dbs}/{filename}") as f:
                    json_content = json.loads(f.read().decode('utf-8'))
                    cache_db[filename] = json_content
            except:
                cache_db[filename] = {
                    'CVE_data_timestamp': '0'
                    }

            try:
                if nvd_db['CVE_data_timestamp'] <= cache_db[filename]['CVE_data_timestamp']:
                    # NVD has NOT been updated, nothing to do here
                    continue
                else:
                    # cache the updated NVD DB
                    cache_db[filename] = nvd_db
            except KeyError:
                print("ERR: NVD feed does not have a CVE_data_timestamp. Ignoring...")
                continue
        else:
            cache_db[filename] = nvd_db

        # if we got here, it's because we found an updated NVD feed that needs to be saved into our local repo
        # and thus the whole CSV DB needs updating
        print(f"NVD DB {filename} has been updated - triggering rebuild of the single file simplified databases")
        regenerate_single_file_dbs = True
        # with open(f"{my_dbs}/{filename}", 'w') as f:
        #     f.write(json.dumps({"CVE_data_timestamp": nvd_db['CVE_data_timestamp']}))
        # z.extractall(my_dbs)
        with gzip.open(f"{my_dbs}/{filename}.gz", "wt") as jsondbgz:
            jsondbgz.write(json.dumps(nvd_db))


if regenerate_single_file_dbs:
    # Because there are updates to at least 1 NVD DB, we need to regenerate the CSV single file DB
    csv_content = ''
    json_content = {
        "CVE_data_type" : "CVE",
        "CVE_data_timestamp": datetime.strftime(datetime.utcnow(), "%Y-%m-%dT%H:%MZ"),
        "CVE_Items": []
    }
    for k, db in cache_db.items():
        # Go through all the NVD DBs (both new and unchanged ones) and map CVE_Items into single CSV file
        try:
            for cve_item in db['CVE_Items']:
                cve_id = cve_item['cve']['CVE_data_meta']['ID']
                cve_description = ' | '.join([dd['value'].replace(";", ".")
                                              for dd in cve_item['cve']['description']['description_data']])

                cve_impact = cve_item.get('impact', {})
                base_metric = cve_impact.get('baseMetricV3', cve_impact.get('baseMetricV2', {}))
                cvss = base_metric.get('cvssV3', base_metric.get('cvssV2', {}))

                cvss_score = cvss.get('baseScore', '')
                cvss_severity = cvss.get('baseSeverity', cvss.get('severity', ''))

                cve_published = cve_item.get('publishedDate', '')
                cve_modified = cve_item.get('lastModifiedDate', '')

                # node operators are being ignored for now, so false positive can still occur
                nodes = cve_item.get('configurations', {}).get('nodes', [])

                all_cpes = []
                for node in nodes:
                    cpe_match = node.get('cpe_match', [])
                    for child in node.get('children', []):
                        cpe_match += child.get('cpe_match', [])

                    all_cpes += list(map(lambda c:
                                         f"{c.get('versionStartExcluding', '')}:{c.get('versionStartIncluding', '')}:"
                                         f"{c.get('versionEndIncluding', '')}:{c.get('versionEndExcluding', '')}|"
                                         f"{c.get('cpe23Uri', '')}" if c.get('vulnerable') else '', cpe_match))

                cve_url = ''
                if cve_id.startswith('CVE-'):
                    # then we can assum the default MITRE CVE base url
                    cve_url = f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve_id}"
                else:
                    reference_data = cve_item['cve'].get('references', {}).get('reference_data')
                    if reference_data and isinstance(reference_data, list):
                        # take a random (first) reference to issue
                        cve_url = reference_data[0].get('url', '')

                csv_content += f"{cve_id};{cve_description};{cvss_score};{cvss_severity};" \
                    f"{cve_url};{cve_published};{cve_modified};{' '.join(all_cpes)}\n"

                json_content['CVE_Items'].append({
                    'cve': {
                        'CVE_data_meta': {
                            'ID': cve_id
                        },
                        'description': {
                            'description_data': [{
                                "value": cve_description
                            }]
                        },
                        'references': {
                            'reference_data': [{
                                'url': cve_url
                            }]
                        }
                    },
                    'impact': {
                        'baseMetricV2': {
                            'cvssV2': {
                                'baseScore': cvss_score
                            },
                            'severity': cvss_severity
                        },
                        'baseMetricV3': {
                            'cvssV3': {
                                'baseScore': cvss_score,
                                'baseSeverity': cvss_severity
                            }
                        }
                    },
                    'publishedDate': cve_published,
                    'lastModifiedDate': cve_modified
                })
        except KeyError as e:
            print(f"ERR: could not read CVE specific attributes from {k}: {e}")
            continue

    with gzip.open(csv_full_db, "wt") as csvgz:
        print(f"Compressing {csv_full_db}...")
        csvgz.write(csv_content)

    with gzip.open(json_full_db, "wt") as jsongz:
        print(f"Compressing {json_full_db}...")
        jsongz.write(json.dumps(json_content))
