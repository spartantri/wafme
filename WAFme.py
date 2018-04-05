#!//usr/bin/env python
# -------------------------------------------------------------------------------
# Name:        ModSecurity audit log extractor
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

#CWD
cwd=os.getcwd()
#Starting rule id to use if no rule is found
new_rule_id=37173
#Keep initial rule for computing stats
initial_rule_id=new_rule_id

#Rule id increases
increase_rule_id=10

#Audit log file to tail
audit_log=''.join([cwd,'/audit.log'])

#Rule set output file
rules_output=''.join([cwd,'/REQUEST-903.9003-CUSTOMAPP-EXCLUSION-RULES.conf'])

#Webbserver restart command or script to execute to load the rules produced
restart_command=''.join([cwd,'/apache_restart.sh'])

#result dictionary keep track of identified rule ids and matching elements, keys are "id,uri"
#result contents are lists of matched variables and the hit count
result=sample_requests={}

#actions list stores the actions extracted from the modsecurity reference manual
#variables list stores the variables extracted from the modsecurity reference manual
#operators list stores the operators extracted from the modsecurity reference manual
#transforms list stores the transforms extracted from the modsecurity reference manual
#min_instances variable is the minimum number of times a match must be added into a global white list
#skipper variables list is used to add items that exceeded the min_instances threshold
#skipper holds variables found in multiple different URI
actions=variables=operators=transforms=skipper=tags=list()

#Number of different URI where a variable must be present to white list it globally
min_instances=10

#rule_parents dictionary is used to whitelist rules that are derivated from another one
#rule_parents keys are the derivated rule id and the content list have the regex of the derivated rule match,
#the parent rule id and the variable used in the parent rule
rule_parents={'921180':['TX:paramcounter_','921170','ARGS_NAMES']}

#rule_sensitive list contains the rules the will issue additional warning as they are critical to security
#rule_sensitive contains rules that use detectxss and detectsqli
rule_sensitive=['941100','941101','942100']

#rule_ignore list are rules to be ignored and no action will be taken
rule_ignore=['981405','952100']

#replacement_element dictionary contains replacements for items that contain variable names eg. tailing MD5
replacement_element={"REQUEST_COOKIES:wordpress_sec_[a-zA-Z0-9]{10-40}":"REQUEST_COOKIES:/wordpress_sec_*/",
                    "REQUEST_COOKIES:wordpress_logged_in_[a-zA-Z0-9]{10-40}":"REQUEST_COOKIES:/wordpress_logged_in_*/"}


def largest_id():
    #Find the max rule id number in the ruleset file
    global new_rule_id, increase_rule_id, rules_output
    val = max_num = new_rule_id
    #Go through the ruleset file and get the ids and return the max value + 1 to use as next rule id
    try:
        with open(rules_output, 'r') as data:
            for line in data.readlines(): # read the lines as a generator to be nice to my memory
                try:
                    id=re.search('id:\'?(\d+)\'?',line)
                    if id:
                        val = int(id.group(1))
                    del id
                except ValueError:
                    val = 0
                if val > max_num:
                    max_num = val
    except:
        max_num = 0
    if new_rule_id <= max_num:
        new_rule_id = max_num+increase_rule_id
    return


def find_values(id, json_repr):
    #Extract from json content the requested section and return it
    results = []
    def _decode_dict(a_dict):
        try: results.append(a_dict[id])
        except KeyError: pass
        return a_dict
    json.loads(json_repr, object_hook=_decode_dict)  # Return value ignored.
    return results


def extractor(jsonlog):
    #Process tail and extract rule messages
    global result
    #Use line to build log line
    line=''
    #Extract URI from request_line field using regex to ignore method any parameters after ? and protocol
    uri=re.search('^\w+\s(\/[^\?\s]+)\??.*\sHTTP\/(?:(?:1|2)\.?(?:1|0)?)$', find_values('request_line', jsonlog)[0])
    #If URI was successfully captured use it, otherwise get the entire request_line and use it
    if uri:
        line=' '.join([line, uri.group(1)])
    else:
        line=' '.join([line, find_values('request_line', jsonlog)[0]])
    #Get the transaction unique_id
    txid=find_values('transaction_id', jsonlog)[0]
    #Iterate through the rule messages looking for known patterns to extract matching rule and offending argument 
    for log in find_values('messages', jsonlog):
        for event in log:
            #Initializing variables for every loop
            id_check=var_check=False
            #Get the rule id of current rule message, if matched use it on the log line otherwise use "noid" instead
            id=re.search('\[id "([^"]+)"\]', log[0])
            if id:
                line=' '.join([line, str(id.group(1))])
                id_check=True
            else:
                line=' '.join([line, 'noid'])
            #Get the matched variable
            var=re.search('\[data "(?:M|m)atch.*found\swithin\s(\S+?):?\s', log[0])
            #If there is no match for the regex then use complementary regex and try to get a match and use it in the log line
            if not var:
                var=re.search('(?:(?:M|m)atch|(?:F|f)ound).*?\s(?:at|against|in)\s(\S+?)\.?\s', log[0])
            if var:
                line=' '.join([line, var.group(1)])
                var_check=True
            else:
                line=' '.join([line, log[0]])
            #If both id and var got matched then add the item to rule to output and add sample payload to replay
            #Print a dot to get some motion on screen
            #If no matches the simply throw the log line to screen as ERROR
            if id_check==True and var_check==True:
                add_item(id.group(1), uri.group(1), var.group(1))
                add_sample(id.group(1), uri.group(1), var.group(1), jsonlog)
                print '.',
            else:
                line=' '.join([line, txid])
                print 'ERROR:',
                print line
            #Destroy var and id variables and reset log line
            del var
            del id
            line=''
    return


def sigint_handler(signum, frame):
    global result, sample_requests, initial_rule_id, new_rule_id
    #Whenever a CTRL+C is pressed process the rules to output
    global new_rule_id, initial_rule_id
    #Process rules and output to rule set
    print_rules()
    #If there are no changes then exit, otherwise start over
    if new_rule_id==initial_rule_id:
        print 'No new rules generated...exiting'
        exit(0)
    else:
        initial_rule_id=new_rule_id
        resp = confirm('Do you want to restart the Web server service and continue analyzing the log', True)
        if resp:
            #Restart the webserver process to load the new configuration
            retvalue = os.system(restart_command)
            #Print output from restart command
            print retvalue
            #Start over
            result=sample_requests={}
            initial_rule_id=new_rule_id
            main()
        else:
            resp = confirm('Do you want to restart the Web server service before exiting', True)
            if resp:
                # Restart the webserver process to load the new configuration
                retvalue = os.system(restart_command)
                # Print output from restart command
                print
                retvalue
            else:
                exit(0)

 
signal.signal(signal.SIGINT, sigint_handler)


def add_item(id, uri, var):
    #Add matching rule to dictionary to be processed
    global result
    #Build the cictionary item key as "ruleid,uri"
    item=''.join([id,',',uri])
    #If the incoming item exists add 1 to the counter of that element, otherwise initialize it
    #var is the matching element eg ARGS:element
    if var not in result.setdefault(item, {}):
        result.setdefault(item, {})[var]=1
    else:
        result.setdefault(item, {})[var]+=1
    return


def add_sample(id, uri, var, content):
  #Build from the auditlog message a sample request to replay it
  #Get the request section of the audit log
  request=find_values('request', content)[0]
  #Printing the request section for debug purposes
  #print request
  #Extract the interesting parts from the request to build the sample
  headers=request["headers"]
  request_line=request["request_line"]
  uri_check=re.search('^(\w+)\s(\/[^\?\s]+)\??(.*)\sHTTP\/(?:(?:1|2)\.?(?:1|0)?)$', request_line)
  if not uri_check:
      print request_line
  if uri != uri_check.group(2):
      print uri_check.group(1),uri_check.group(2),uri_check.group(3)
  else:
      method=uri_check.group(1)
      request_filename=uri_check.group(2)
      args=uri_check.group(3)
  body=request.setdefault("body", [])
  #Get the transaction section of the audit log to get the target to replay the request
  transaction=find_values('transaction', content)[0]
  #Printing the transaction section for debug purposes
  #print transaction
  '''
  {u'local_port': 443, u'remote_port': 37536, u'remote_address': u'78.227.109.215', u'time': u'18/Oct/2017:01:09:34 +0000', u'local_address': u'172.31.26.26', u'transaction_id': u'Weapzn8AAQEAAEikCSkAAAAI'}
  '''
  transaction_id=transaction["transaction_id"]
  print transaction_id
  remote_address=transaction["remote_address"]
  remote_port=transaction["remote_port"]
  local_address=transaction["local_address"]
  #local_port=transaction["local_port"]
  sample='import requests\n'
  for header_key in headers.keys():
      host_header=re.search("(?i)(host)", header_key)
      if host_header:
          host_header_name=host_header.group(1)
  if uri_check:
      if method == "GET" or method == "HEAD":
          sample=''.join([sample,'requests.get("https://',headers[host_header_name],request_filename,'"'])
          if len (args)>0:
              sample=''.join([sample,'?',args,'"'])
          else:
              sample=''.join([sample,'"'])
          sample=''.join([sample,',headers=',str(headers),')'])
      elif method == "POST":
          sample=''.join([sample,'requests.post("https://',headers[host_header_name],request_filename,'", data="',body[0],'"'])
      if len(sample) > 20:
          print sample
  return


def print_rules():
    #Trigger rule generation and global whitelisting
    global result, variables, min_instances, skipper
    #Build variable identification regex to match all identified variables from reference manual
    variables_rx='|'.join(var.name for var in variables)
    variables_rx=''.join(['^(',variables_rx,')'])
    #Print the summary of rule ids, uris and variables identified
    print result
    #Get reduced list of elements
    elements=shrinker()
    #Check which elements appear in more different URI than the min_instances threshold
    for a in elements.keys():
        if elements[a] > min_instances:
            skipper.append(a)
    #Iterate through the result dictionary and search for variables to print messages to screen
    for e in result.keys():
        id, uri = e.split(',', 1)
        for i in result[e].keys():
            prob=re.search(variables_rx, result[e].keys()[0])
            if prob:
                print "#The rule %s matched %s from %s %s times at uri %s" % (id, prob.group(1), result[e].keys()[0], result[e][i], uri)
            else:
                print "#The rule %s matched %s %s times at uri %s" % (id, result[e].keys()[0], result[e][i], uri)
        #print id, result[e].keys(), result[e], uri
        #Generate individual rules to whitelist variables per rule id identified per URI (SecRule with ctl)
        rule_skeleton(id, result[e].keys(), result[e], uri)
        #Generate whitelist of identified variables to be whitelisted (SecRuleUpdateTargetById)
        rule_globals()
    return


def rule_skeleton(id, target, match, uri):
    #Generate the rule to whitelist elements from a rule id on a given URI
    global new_rule_id, increase_rule_id, rule_parents, skipper, tags
    counter=0
    #Check if rule have a related rule and do the whitelisting on it instead
    if id in rule_parents:
        #Rule was found in rule_parents and have to be substituted
        comment='#Sibling rule %s triggered on %s at %s\n' % (id, target[0], uri)
        rx=''.join(['^',rule_parents[id][0],'(.*)'])
        #Use the rule id of the related rule in rule_parents
        id=rule_parents[id][1]
        original_target=re.search(rx, target[0])
        comment=''.join([comment,'#Parent rule %s whitelisting %s at %s\n']) % (id, original_target.group(1), uri)
        target[0]=original_target.group(1)
    else:
        #If there is no match then initialize comment variable
        comment=''
    #Add comment to specify variable and URI
    comment=''.join([comment,'#%s whitelisted from %s\n' % (target[0], uri)])
    #Build rule using REQUEST_FILENAME ending with the URI
    sk_ctlruleremovetargetbyid='SecRule %s "@endsWith %s$" \\\n' % ('REQUEST_FILENAME', uri)
    #Set rule id, phase:2, no transform, nolog, pass
    sk_ctlruleremovetargetbyid_actions=',\\\n    '.join(['"id:%s' % str(new_rule_id), 'phase:2', 't:none', 'nolog', 'pass'])
    #Adding tags
    for tag in tags:
        sk_ctlruleremovetargetbyid_actions=',\\\n    '.join([sk_ctlruleremovetargetbyid_actions, tag])
    #Add 4 heading blank spaces
    sk_ctlruleremovetargetbyid_actions=''.join(['    ', sk_ctlruleremovetargetbyid_actions])
    #sk_ctlruleremovetargetbyid_actions=''.join([sk_ctlruleremovetargetbyid_actions, ',\\\n    '])
    #Initialize target whitelist
    target_list=''
    #Iterate through the list of items for a given URI and rule id
    for ctl in target:
        if ctl not in skipper:
            #Add a ctl to remove target by id If the variable is not in the list of global_whitelist to skip
            sk_ctlruleremovetargetbyid_1='ctl:ruleRemoveTargetById=%s;%s' % (id, ctl)
            target_list=',\\\n    '.join([target_list, sk_ctlruleremovetargetbyid_1])
            #Add 1 to counter of elemets added to the rule
            counter+=1
    #Add tailing \n
    target_list=''.join([target_list, '"\n'])
    #Build the entire rule with heading comment, main rule body, the list of ctl and tailing \n
    rule=''.join([comment, sk_ctlruleremovetargetbyid, '', sk_ctlruleremovetargetbyid_actions, target_list])
    #If rule have no ctl (made it to the global whitelist), print the rule and save it to the rule set file
    if counter>0:
        print rule
        with open(rules_output, 'a+') as file:
            file.write(rule)
        #Increase the rule id for next rule
        new_rule_id+=increase_rule_id
    return


def get_parent(id, target):
    #Check if a rule have a related rule id and return the replacement id and variable to use
    global rule_parents, replacement_element
    child=[]
    #Check if the received target is type list, if not then convert it to list
    if type(target) is list:
        child=target
    else:
        child=[target]
    #Check if rule have related rule
    if id in rule_parents:
        #rule_parents[id][0] holds the regex to match in the current rule
        rx=''.join(['^',rule_parents[id][0],'(.*)'])
        #rule_parents[id][1] contains the rule id of the related rule
        id=rule_parents[id][1]
        original_target=re.search(rx, child[0])
        child[0]=original_target.group(1)
    #Check if there is a variable that have to be replaced and do the switch
    for k in replacement_element.keys():
        match=re.search(k, child[0])
        if match:
            child[0]=replacement_element[k]
    return id, child


def rule_globals():
    #Build SecRuleUpdateTargetById to whitelist variables in all URI
    global result, rule_parents, skipper, rule_sensitive
    #Initialize the whitelist dictionary
    global_whitelist={}
    #Add comments
    rules="#Site wide whitelisted elements\n"
    #Iterate thourgh the result dictionary
    for e in result.keys():
        id, uri = e.split(',', 1)
        #Iterate through the variables for every 
        for i in result[e].keys():
            #If a variable is listed in the skipper list add it to the global_whitelist dictionary
            if i in skipper:
                if id not in global_whitelist.setdefault(i, []):
                    global_whitelist[i]=[id]
                else:
                    global_whitelist[i].append(id)
    #Iterate through the global_whitelist just built
    for r in global_whitelist.keys():
        for item in global_whitelist[r]:
            #Get the related rule if any
            new_item, new_target = get_parent(item, [r])
            if item==new_item:
                rule="SecRuleUpdateTargetById %s !%s" % (item, r)
                #If rule is listed as sensitive throw additional warning
                if item in rule_sensitive:
                    print "#Warning whitelisting sensitive rule! - %s" % item
            else:
                rule="SecRuleUpdateTargetById %s !%s" % (new_item, new_target[0])
                #If replaced rule is listed as sensitive throw additional warning
                if new_item in rule_sensitive:
                    print "#Warning whitelisting sensitive rule! - %s" % item
            #Open the rule set file and check if the item to be whitelisted is already presend
            with open(rules_output, 'r+') as file:
                ruleset=file.read()
                #If the item is not already listed add it, otherwise ignore it
                if rule not in ruleset:
                    rule=''.join([rule, "\n"])
                    rules=''.join([rules, rule])
    #If the rules have something else other than the inital comment, save it
    if rules != "#Site wide whitelisted elements\n":
        with open(rules_output, 'a+') as file:
            file.write(rules)
        print rules
    return


def shrinker():
    #Shrink ruleset by removing duplicates 
    global result
    elements={}
    for e in result.keys():
        id, uri = e.split(',', 1)
        for i in result[e].keys():
            if i not in elements.setdefault(i, {}):
                elements.setdefault(i, {})[i]=1
            else:
                elements.setdefault(i, {})[i]+=1
    return elements

  
def ruleset_control():
    #General ruleset control comments and settings
    global new_rule_id, increase_rule_id, tags
    import time
    #Start time
    start_time=str(time.time()).replace(".","")
    #Rule set prolog
    ruleset_vars=''.join(['SecAction ', '"id:%s' % str(new_rule_id), 'phase:2', "setvar:'tx.wafme_debuglevel=0'", 'noauditlog', 'nolog', 'pass'])
    ruleset_header='SecMarker %s_START' % start_time
    ruleset_trailer='SecMarker %s_FINISH' % start_time
    tags.append("tag:'wafme_%s'" % start_time)
    return

def validate_files(files):
    for access_type in files:
        for item in files[access_type]:
            print 'Testing file access %s' % item
            if os.access(item, os.F_OK):
                if os.access(item, access_type):
                    print 'File %s exists and permissions are ok' % item
                else:
                    print 'File %s permissions are wrong' % item
                    print oct(os.stat(item).st_mode & 0777)
            else:
                print "File %s does not exist" % item
    os.system(''.join(['touch', ' ', rules_output]))
    return


def confirm(prompt=None, resp=False):
    """ActiveState receipe, prompts for yes or no response from the user. Returns True for yes and
    False for no.

    'resp' should be set to the default value assumed by the caller when
    user simply types ENTER.

    >>> confirm(prompt='Create Directory?', resp=True)
    Create Directory? [y]|n:
    True
    >>> confirm(prompt='Create Directory?', resp=False)
    Create Directory? [n]|y:
    False
    >>> confirm(prompt='Create Directory?', resp=False)
    Create Directory? [n]|y: y
    True"""

    if prompt is None:
        prompt = 'Confirm'

    if resp:
        prompt = '%s [%s]|%s: ' % (prompt, 'y', 'n')
    else:
        prompt = '%s [%s]|%s: ' % (prompt, 'n', 'y')

    while True:
        ans = raw_input(prompt)
        if not ans:
            return resp
        if ans not in ['y', 'Y', 'n', 'N']:
            print
            'please enter y or n.'
            continue
        if ans == 'y' or ans == 'Y':
            return True
        if ans == 'n' or ans == 'N':
            return False


def main():
    global variables, new_rule_id, increase_rule_id, audit_log, rules_output
    #new_rule_id,increase_rule_id, audit_log, rules_output, restart_command, min_instances, rule_sensitive, rule_ignore
    files={os.R_OK:[audit_log], os.W_OK:[rules_output], os.X_OK:[restart_command]}
    validate_files(files)
    #Read the modsecurity reference manual
    soup = RuleEditor.get_ref_manual()
    #Read all the variables into variables dictionary
    variables = RuleEditor.get_ref_section('Variables', soup)
    #Get starting id to use for rules
    largest_id()
    ruleset_control()
    print 'Starting rule id will be : %d' % new_rule_id
    print 'Increases to rule id will be : %d' % increase_rule_id
    #Declare audit log file and function to process all events
    t=tail.Tail(audit_log)
    t.register_callback(extractor)
    print 'Press CTRL+C to finish tailing %s and output the rules to %s' % (audit_log, rules_output)
    #Tail and follow the log
    t.follow()


if __name__ == '__main__':
    main()
