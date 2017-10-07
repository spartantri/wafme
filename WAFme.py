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

import json, re, signal
import RuleEditor, tail
from collections import namedtuple

result={}
actions=variables=operators=transforms=list()
rule_parents={'921180':['TX:paramcounter_','921170','ARGS_NAMES']}
new_rule_id=37173

def find_values(id, json_repr):
    results = []
    def _decode_dict(a_dict):
        try: results.append(a_dict[id])
        except KeyError: pass
        return a_dict
    json.loads(json_repr, object_hook=_decode_dict)  # Return value ignored.
    return results


def extractor(jsonlog):
    global result
    line=''
    uri=re.search('^\w+\s(\/[^\?\s]+)\??.*\sHTTP\/(?:(?:1|2)\.?(?:1|0)?)$', find_values('request_line', jsonlog)[0])
    txid=find_values('transaction_id', jsonlog)[0]
    for log in find_values('messages', jsonlog):
        for event in log:
            id_check=var_check=False
            if uri:
                line=' '.join([line, uri.group(1)])
            else:
                line=' '.join([line, find_values('request_line', jsonlog)[0]])
            id=re.search('\[id "([^"]+)"\]', log[0])
            if id:
                line=' '.join([line, str(id.group(1))])
                id_check=True
            else:
                line=' '.join([line, 'noid'])
            var=re.search('\[data "(?:M|m)atch.*found\swithin\s(\S+?):?\s', log[0])
            if not var:
                var=re.search('(?:M|m)atch.*?\s(?:at|against)\s(\S+?)\.?\s', log[0])
            if var:
                line=' '.join([line, var.group(1)])
                var_check=True
            else:
                line=' '.join([line, log[0]])
            if id_check==True and var_check==True:
                add_item(id.group(1), uri.group(1), var.group(1))
            else:
                line=' '.join([line, txid])
                print 'Error'
                print line
            del var
            del id
            line=''
    return


def sigint_handler(signum, frame):
    print_rule()
    exit(0)

 
signal.signal(signal.SIGINT, sigint_handler)


def add_item(id, uri, var):
    global result
    item=''.join([id,',',uri])
    if var not in result.setdefault(item, {}):
        result.setdefault(item, {})[var]=1
    else:
        result.setdefault(item, {})[var]+=1
    print '.',
    return


def print_rule():
    global result, variables, rule_parents
    variables_rx='|'.join(var.name for var in variables)
    variables_rx=''.join(['^(',variables_rx,')'])
    print result
    for e in result.keys():
        id, uri = e.split(',', 1)
        for i in result[e].keys():
            prob=re.search(variables_rx, result[e].keys()[0])
            if prob:
                print "The rule %s matched %s from %s %s times at uri %s" % (id, prob.group(1), result[e].keys()[0], result[e][i], uri)
            else:
                print "The rule %s matched %s %s times at uri %s" % (id, result[e].keys()[0], result[e][i], uri)
        rule_skeleton(id, result[e].keys(), result[e], uri)
    return


def rule_skeleton(id, target, match, uri):
    global new_rule_id
    sk_ctlruleremovetargetbyid='SecRule %s "@endsWith %s$" \\\n' % (target[0], uri)
    sk_ctlruleremovetargetbyid_actions='\\\n    '.join(['"id:', str(new_rule_id), 'phase:2', 't:none', 'nolog', 'pass']) 
    target_list=''
    for ctl in target:
        sk_ctlruleremovetargetbyid_1='ctl:ruleRemoveTargetById=%s;%s' % (id, ctl)
        target_list=',\\\n'.join([target_list, sk_ctlruleremovetargetbyid_1])
    target_list=''.join([target_list, '"'])
    rule=''.join([sk_ctlruleremovetargetbyid, sk_ctlruleremovetargetbyid_actions, target_list])
    print rule
    return


def main():
    global variables
    soup = RuleEditor.get_ref_manual()
    variables = RuleEditor.get_ref_section('Variables', soup)
    t=tail.Tail('audit.log')
    t.register_callback(extractor)
    t.follow()


if __name__ == '__main__':
    main()
