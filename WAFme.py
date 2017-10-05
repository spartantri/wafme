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
        uri=re.search('^\w+\s(\/[^\?\s]+)\??.*\sHTTP\/(?:(?:1|2)\.?(?:1|0)?)$', find_values('request_line', jsonlog))
        for event in log:
            if uri:
                line=' '.join([line, log[0]])
            else:
                line=' '.join([line, find_values('request_line', log)])
            id=re.search('\[id "([^"]+)"\]', log[0])
            if id:
                line=''.join([line, str(id.group(1))])
            else:
                line=''.join([line, 'noid'])
            var=re.search('\[data "Matched Data:.*found within (\S+): ', log[0])
            if var:
                line=' '.join([line, var.group(1)])
            else:
                line=' '.join([line, log[0]])
            txid=find_values('transaction_id', log[0])
            line=' '.join([line, txid[0]])
            print line
            id=var=line=None
        uri=None
    return


def main():
    soup = RuleEditor.get_ref_manual()
    variables = RuleEditor.get_ref_section('Variables', soup)
    t=tail.Tail('audit.log')
    t.register_callback(extractor)
    t.follow()
    
    
if __name__ == '__main__':
    main()
