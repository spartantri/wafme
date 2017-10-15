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

import json, re, signal, os
import RuleEditor, tail
from collections import namedtuple

result={}
actions=variables=operators=transforms=list()
rule_parents={'921180':['TX:paramcounter_','921170','ARGS_NAMES']}
new_rule_id=37173
audit_log='audit.log'
rules_output='REQUEST-903.9003-CUSTOMAPP-EXCLUSION-RULES.conf'
restart_command='./apache_restart.sh'
skipper=[]
min_instances=2


def largest_id():
    global new_rule_id, rules_output
    val = max_num = new_rule_id
    with open(rules_output, 'r') as data:
        for line in data.readlines(): # read the lines as a generator to be nice to my memory
            try:
                id=re.search('id:(\d+)',line)
                if id:
                    val = int(id.group(1))
                del id
            except ValueError: # just incase the text file is not formatted like your example
                val = 0
            if val > max_num: # logic
                max_num = val
    if new_rule_id <= max_num:
        new_rule_id = max_num+1
    return


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
                var=re.search('(?:(?:M|m)atch|(?:F|f)ound).*?\s(?:at|against|in)\s(\S+?)\.?\s', log[0])
            if var:
                line=' '.join([line, var.group(1)])
                var_check=True
            else:
                line=' '.join([line, log[0]])
            if id_check==True and var_check==True:
                add_item(id.group(1), uri.group(1), var.group(1))
                print '.',
            else:
                line=' '.join([line, txid])
                print 'ERROR:',
                print line
            del var
            del id
            line=''
    return


def sigint_handler(signum, frame):
    print_rules()
    retvalue = os.system(restart_command)
    print retvalue
    exit(0)

 
signal.signal(signal.SIGINT, sigint_handler)


def add_item(id, uri, var):
    global result
    item=''.join([id,',',uri])
    if var not in result.setdefault(item, {}):
        result.setdefault(item, {})[var]=1
    else:
        result.setdefault(item, {})[var]+=1
    return


def print_rules():
    global result, variables, rule_parents, min_instances, skipper
    variables_rx='|'.join(var.name for var in variables)
    variables_rx=''.join(['^(',variables_rx,')'])
    print result
    elements=shrinker()
    for a in elements.keys():
        if elements[a] > min_instances:
            skipper.append(a)
    for e in result.keys():
        id, uri = e.split(',', 1)
        for i in result[e].keys():
            prob=re.search(variables_rx, result[e].keys()[0])
            if prob:
                print "#The rule %s matched %s from %s %s times at uri %s" % (id, prob.group(1), result[e].keys()[0], result[e][i], uri)
            else:
                print "#The rule %s matched %s %s times at uri %s" % (id, result[e].keys()[0], result[e][i], uri)
        rule_skeleton(id, result[e].keys(), result[e], uri)
        rule_globals()
    return


def rule_skeleton(id, target, match, uri):
    global new_rule_id, rule_parents, skipper
    counter=0
    if id in rule_parents:
        comment='#Sibling rule %s triggered on %s at %s\n' % (id, target[0], uri)
        rx=''.join(['^',rule_parents[id][0],'(.*)'])
        id=rule_parents[id][1]
        original_target=re.search(rx, target[0])
        comment=''.join([comment,'#Parent rule %s whitelisting %s at %s\n']) % (id, original_target.group(1), uri)
        target[0]=original_target.group(1)
    else:
        comment=''
    comment=''.join([comment,'#%s whitelisted from %s\n' % (target[0], uri)])
    sk_ctlruleremovetargetbyid='SecRule %s "@endsWith %s$" \\\n' % ('REQUEST_FILENAME', uri)
    sk_ctlruleremovetargetbyid_actions=',\\\n    '.join(['"id:%s' % str(new_rule_id), 'phase:2', 't:none', 'nolog', 'pass'])
    sk_ctlruleremovetargetbyid_actions=''.join(['    ', sk_ctlruleremovetargetbyid_actions])
    #sk_ctlruleremovetargetbyid_actions=''.join([sk_ctlruleremovetargetbyid_actions, ',\\\n    '])
    target_list=''
    for ctl in target:
        if ctl not in skipper:
            sk_ctlruleremovetargetbyid_1='ctl:ruleRemoveTargetById=%s;%s' % (id, ctl)
            target_list=',\\\n    '.join([target_list, sk_ctlruleremovetargetbyid_1])
            counter+=1
    target_list=''.join([target_list, '"\n'])
    rule=''.join([comment, sk_ctlruleremovetargetbyid, '', sk_ctlruleremovetargetbyid_actions, target_list])
    if counter>0:
        print rule
        with open(rules_output, 'a') as file:
            file.write(rule)
        new_rule_id+=1
    return


def rule_globals():
    global result, rule_parents, skipper
    global_whitelist={}
    rules=""
    for e in result.keys():
        id, uri = e.split(',', 1)
        for i in result[e].keys():
            if i in skipper:
                if id not in global_whitelist.setdefault(i, []):
                    global_whitelist.setdefault(i, [])[i].append(id)
    for r in global_whitelist.keys():
        for item in global_whitelist[r]:
            rule= "SecRuleUpdateTargetById %s !%s\n" % (r, item)
            rules=''.join([rules, rule])
    with open(rules_output, 'a') as file:
            file.write(rules)
    return


def shrinker():
    global result, variables, rule_parents
    elements={}
    for e in result.keys():
        id, uri = e.split(',', 1)
        for i in result[e].keys():
            if i not in elements.setdefault(i, {}):
                elements.setdefault(i, {})[i]=1
            else:
                elements.setdefault(i, {})[i]+=1
    return elements


def main():
    global variables, new_rule_id
    soup = RuleEditor.get_ref_manual()
    variables = RuleEditor.get_ref_section('Variables', soup)
    largest_id()
    print 'Starting rule id will be : %d' % new_rule_id
    t=tail.Tail(audit_log)
    t.register_callback(extractor)
    print 'Press CTRL+C to finish tailing %s and output the rules to %s' % (audit_log, rules_output)
    t.follow()


if __name__ == '__main__':
    main()
