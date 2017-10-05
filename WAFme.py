#!//usr/bin/env python
# -------------------------------------------------------------------------------
# Name:        ModSecruity audit log extractor
# Purpose:     Build ModSecurity rules to whitelist CRS
#
# Author:      mleos
#
# Created:     5/10/2017
#
# Copyright:   (c) spartantri cybersecurity
# Licence:     Apache2
# -------------------------------------------------------------------------------

import json, re

def find_values(id, json_repr):
    results = []

    def _decode_dict(a_dict):
        try: results.append(a_dict[id])
        except KeyError: pass
        return a_dict

    json.loads(json_repr, object_hook=_decode_dict)  # Return value ignored.
    return results


def extractor(jsonlog):
    parsed=[]
    for log in WAFme.find_values('messages', jsonlog):
        var=re.search('\[data "Matched Data:.*found within (\S+): ', log[0])
        id=re.search('\[id "[^"]+"]', log[0])
        uri=re.search('^\w+ /\S+\?? HTTP/', WAFme.find_values('request_line', jsonlog))
        txid=WAFme.find_values('transaction_id', jsonlog)
        parsed.append([id, var, uri, txid])
        print id, var, uri, txid
    return

def main():
    soup = RuleEditor.get_ref_manual()
    variables = RuleEditor.get_ref_section('Variables', soup)
    t=tail.Tail('audit.log')
    t.register_callback(extractor)
    t.follow()
    
    
