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
import RuleEditor, tail

def find_values(id, json_repr):
    results = []

    def _decode_dict(a_dict):
        try: results.append(a_dict[id])
        except KeyError: pass
        return a_dict

    json.loads(json_repr, object_hook=_decode_dict)  # Return value ignored.
    return results


def extractor(jsonlog):
    line=''
    for log in find_values('messages', jsonlog):
        id=re.search('\[id "([^"]+)"]', log[0])
        if id:
            line=''.join([line, str(id.group(1))])
        else:
            line=''.join([line, 'noid'])
        var=re.search('\[data "Matched Data:.*found within (\S+): ', log[0])
        if var:
            line=' '.join([line, var.group(1)])
        else:
            line=' '.join([line, log[0]])
        try:
            uri=re.search('^\w+ (\/\S+)\?? HTTP\/', find_values('request_line', jsonlog))
            if uri:
                line=' '.join([line, log[0]])
            else:
                line=' '.join([line, find_values('request_line', jsonlog)])
        except:
            uri=find_values('request_line', jsonlog)
            if uri:
                line=' '.join([line, uri[0])
        txid=find_values('transaction_id', jsonlog)
        line=' '.join([line, txid])
        print line
        id=var=uri=line=None
    return


def main():
    soup = RuleEditor.get_ref_manual()
    variables = RuleEditor.get_ref_section('Variables', soup)
    t=tail.Tail('audit.log')
    t.register_callback(extractor)
    t.follow()
    
    
if __name__ == '__main__':
    main()
