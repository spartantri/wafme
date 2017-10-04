#!//usr/bin/env python
# -------------------------------------------------------------------------------
# Name:        ModSecruity rule editor GUI
# Purpose:     GUI to build ModSecurity rules
#
# Author:      mleos
#
# Created:     2/10/2017
#
# Copyright:   (c) spartantri cybersecurity
# Licence:     Apache2
# -------------------------------------------------------------------------------


import sys, codecs, argparse, os, requests, wx
from bs4 import BeautifulSoup as Soup
localReferenceManual = '/home/wtf/wafme/Reference-Manual.html'
remoteReferenceManual = 'https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual'
actions = variables = operators = transforms = list()
from collections import namedtuple

#parser = argparse.ArgumentParser(description='ModSecurity Rule Builder GUI')
#parser.add_argument('remote', help='Download remote Reference Manual', action='store_true')
#args = vars(parser.parse_args())
args = 'local'
#print args



class RuleEditor(wx.Frame):

    def __init__(self, *args, **kwargs):
        super(RuleEditor, self).__init__(*args, **kwargs)

        self.InitUI()
        self.Centre()
        self.Show(True)


    def InitUI(self):
        menubar = wx.MenuBar()
        fileMenu = wx.Menu()
        fitem = fileMenu.Append(wx.ID_EXIT, 'Quit', 'Quit application')
        menubar.Append(fileMenu, '&File')

        self.SetMenuBar(menubar)
        self.Bind(wx.EVT_MENU, self.OnQuit, fitem)
        self.SetSize((1580, 880))
        self.SetTitle('Rule Edifor for ModSecurity WAF')

        rch = {'c1': 20, 'c2': 60, 'c3': 110, \
               'r1': 5, 'r2': 20, \
               'h1': 20}
        positions = {'id_label': [(rch['c1'], rch['r1'])], \
                     'id_text': [(rch['c1'], rch['r2']), (80, rch['h1'])], \
                     'phase_label': [(rch['c3'], rch['r1'])], \
                     'phase_text': [(rch['c3'], rch['r2']), (120, rch['h1'])]}


        panel = wx.Panel(self, -1)

        hbox = wx.BoxSizer(wx.HORIZONTAL)
        #wx.FlexGridSizer(int rows=1, int cols=0, int vgap=0, int hgap=0)
        fgs = wx.FlexGridSizer(20, 12, 9, 25)

        id_label = wx.StaticText(panel, label="Rule id", pos=positions[self[0]])
        id_text = wx.TextCtrl(panel, pos=positions[self[0]])

        phase_label = wx.StaticText(panel, label="Phase", pos=positions[self[0]])
        phase_combo = wx.ComboBox(panel, pos=positions[self[0]])

        selector_label = wx.StaticText(panel, label="Selector")
        selector_combo = wx.ComboBox(panel)

        operator_label = wx.StaticText(panel, label="Operator")
        operator_combo = wx.ComboBox(panel)

        pattern_label = wx.StaticText(panel, label="Rule id")
        pattern_text = wx.TextCtrl(panel)

        location_label = wx.StaticText(panel, label="Location")
        location_combo = wx.ComboBox(panel)

        #fgs.AddMany([(id_label), (id_text, 1),
        #             (phase_label), (phase_combo),
        #             (selector_label), (selector_combo, wx.EXPAND),
        #             (operator_label), (operator_combo, wx.EXPAND),
        #             (pattern_label), (pattern_text, wx.EXPAND),
        #             (location_label), (location_combo, wx.EXPAND)])
        #fgs.AddGrowableRow(2,1)
        #fgs.AddGrowableCol(1,1)

        #hbox.Add(fgs, proportion=1, flag=wx.ALL|wx.EXPAND, border=15)
        #panel.SetSizer(hbox)



    def OnQuit(self, e):
        self.Close()

def get_ref_manual():
    global localReferenceManual, remoteReferenceManual, args
    if args == 'remote':
        try:
            http = os.environ['HTTP_PROXY']
            https = os.environ['HTTPS_PROXY']
            proxy_dict = { 'http': http, 'https': https }
        except:
            next
        try:
            if proxy_dict:
                r = requests.get(remoteReferenceManual, proxies=proxy_dict)
            else:
                r = requests.get(remoteReferenceManual)
            if r.status_code == 200:
                print r
                soup = Soup(r, "html.parser")
                return soup
        except:
            print '%s not accessible try to use %s local file' % (remoteReferenceManual, localReferenceManual)
            next
    else:
        handler = open(localReferenceManual).read()
        soup = Soup(handler, "html.parser")
        print localReferenceManual
        return soup


def get_ref_section(section, soup):
    item = namedtuple(section, ['ref', 'name','comment'])
    section = section.replace('_', ' ')
    extracted_section = list()
    print 'Getting %s' % section
    for li in soup.findAll('li'):
        if li.a:
            if li.a.string == section:
                for ul in li.findAll('li'):
                    if ul.a:
                        extracted_section.append(item(ref=ul.a['href'], name=ul.a.string, comment='?'))
    return extracted_section


def get_ref_subsection(section, soup):
    return extracted_section


def put_lists_data():
    global directive_types
    directive_types = {'Disruptive': ['pass', 'deny', 'block', 'drop', 'allow', 'redirect', 'pause', 'proxy', 'msg'], \
                    'Persistence': ['setuid', 'setsrc', 'setsid', 'initcol'], \
                    'Meta-data': ['severity', 'maturity', 'accuracy', 'version', 'rev'], \
                    'Flow': ['skip', 'skipAfter'], \
                    'Data': ['status', 'xmlns'], \
                    'Non-disruptive':['log', 'nolog', 'auditlog', 'noauditlog', 'capture', 'setvar', 'deprecatevar', \
                                      'expirevar', 'setenv', 'multiMatch', 'exec', 'prepend', 'append', 't', 'ctl', \
                                      'logdata', 'sanitiseArg', 'sanitiseMatched', 'sanitiseMatchedBytes', \
                                      'sanitiseRequestHeader', 'sanitiseResponseHeader', 'tag'] \
                    }
    return


def main():
    soup = get_ref_manual()
    global actions, variables, operators, transforms, directive_types
    operators = get_ref_section('Operators', soup)
    actions = get_ref_section('Actions', soup)
    variables = get_ref_section('Variables', soup)
    transforms = get_ref_section('Transformation_functions', soup)
    put_lists_data()

    #app = wx.App()
    #RuleEditor(None)
    #app.MainLoop()


if __name__ == '__main__':
