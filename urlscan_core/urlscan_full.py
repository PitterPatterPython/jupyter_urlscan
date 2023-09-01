#!/usr/bin/python

# Base imports for all integrations, only remove these at your own risk!
import json
import sys
import os
import time
import pandas as pd
from collections import OrderedDict
import re
from integration_core import Integration
import datetime
from IPython.core.magic import (Magics, magics_class, line_magic, cell_magic, line_cell_magic)
from IPython.core.display import HTML
from io import StringIO
from requests import Request, Session

from urlscan_core._version import __desc__
from jupyter_integrations_utility.batchquery import df_expand_col
# Your Specific integration imports go here, make sure they are in requirements!
import jupyter_integrations_utility as jiu
#import IPython.display
from IPython.display import display_html, display, Javascript, FileLink, FileLinks, Image
import ipywidgets as widgets

##custom to urlscan integration
import random

@magics_class
class Urlscan(Integration):
    # Static Variables
    # The name of the integration
    name_str = "urlscan"
    instances = {}
    custom_evars = ["urlscan_conn_default", "urlscan_verify_ssl", "urlscan_rate_limit","urlscan_submission_visiblity"]
    # These are the variables in the opts dict that allowed to be set by the user. These are specific to this custom integration and are joined
    # with the base_allowed_set_opts from the integration base

    # These are the variables in the opts dict that allowed to be set by the user. These are specific to this custom integration and are joined
    # with the base_allowed_set_opts from the integration base
    custom_allowed_set_opts = ["urlscan_conn_default", "urlsacn_verify_ssl","url_rate_limit", "urlscan_submission_visiblity"]

    help_text = ""
    help_dict = {}
    myopts = {}
    myopts['urlscan_conn_default'] = ["default", "Default instance to connect with"]
    myopts['urlscan_verify_ssl'] = [True, "Verify integrity of SSL"]
    myopts['urlscan_rate_limit'] = [True, "Limit rates based on URLScan user configuration"]
    myopts['urlscan_submission_visiblity'] = ["public", "Default visiblity for submissions to URLScan."]
    myopts['urlscan_submission_country'] = ["US","The country from which the scan should be performed"]
    myopts['urlscan_submission_referer'] = [None, "Override the HTTP referer for this scan"]
    myopts['urlscan_submission_useragent'] = [None, "Override useragent for this scan"]

    countries = ["de","us","jp","fr","gb","nl","ca","it","es","se","fi","dk","no","is","au","nz","pl","sg","ge","pt","at","ch"]

    """
    Key:Value pairs here for APIs represent the type? 
    """

    apis = {
            "scan": "/scan/",
            "get_result": "/result/",
            "get_screenshot": "/screenshot/",
            "get_dom": "/dom/",
            "search": "/search/?q=",
            }

    base_url = "https://urlscan.io/api/v1"


    # Class Init function - Obtain a reference to the get_ipython()
    def __init__(self, shell, debug=False, *args, **kwargs):
        super(Urlscan, self).__init__(shell, debug=debug)
        self.debug = debug
        #Add local variables to opts dict
        for k in self.myopts.keys():
            self.opts[k] = self.myopts[k]

        self.load_env(self.custom_evars)
        self.parse_instances()
#######################################



    def retCustomDesc(self):
        return __desc__


    def customHelp(self, curout):
        n = self.name_str
        mn = self.magic_name
        m = "%" + mn
        mq = "%" + m
        table_header = "| Magic | Description |\n"
        table_header += "| -------- | ----- |\n"
        out = curout

        qexamples = []
        qexamples.append(["myinstance", "scan\nhttps://this.supershady.url/", "Run a urlscan query for iris-enrich"])
        qexamples.append(["","result\na353d4c9-2fa1-4b9b-8919-08ac1db9772a","Provide a UUID to retrieve results from URLScan for the submission associated to it."])
        qexamples.append(["","dom\na353d4c9-2fa1-4b9b-8919-08ac1db9772a","Provide a UUID to retrieve results from URLScan for the submission associated to it."])
        out += self.retQueryHelp(qexamples)

        return out

    def customAuth(self, instance):
        result = -1
        inst = None
        if instance not in self.instances.keys():
            result = -3
            print("Instance %s not found in instances - Connection Failed" % instance)
        else:
            inst = self.instances[instance]
        if inst is not None:
            if inst['options'].get('useproxy', 0) == 1:
                myproxies = self.get_proxy_str(instance)
            else:
                myproxies = None

            inst['session']=Session()
            inst['session'].proxies=myproxies

            mypass = ""
            if inst['enc_pass'] is not None:
                mypass = self.ret_dec_pass(inst['enc_pass'])
                inst['session'].headers.update({'API-Key':mypass,'Content-Type':'application/json'})
            ssl_verify = self.opts['urlscan_verify_ssl'][0]
            if isinstance(ssl_verify, str) and ssl_verify.strip().lower() in ['true', 'false']:
                if ssl_verify.strip().lower() == 'true':
                    ssl_verify = True
                else:
                    ssl_verify = False
            elif isinstance(ssl_verify, int) and ssl_verify in [0, 1]:
                if ssl_verify == 1:
                    ssl_verify = True
                else:
                    ssl_verify = False

            inst['session'].verify=ssl_verify
            result = 0
        return result

    def parse_query(self, query):
        q_items = query.split("\n")
        end_point = q_items[0].strip()
        if len(q_items) > 1:
            end_point_vars = q_items[1].strip()
        elif len(q_items) > 2:
            end_point_vars = list(map(lambda variable : variable.strip(),q_items))
        else:
            end_point_vars = None
        return end_point, end_point_vars


    def validateQuery(self, query, instance):
        bRun = True
        bReRun = False

        if self.instances[instance]['last_query'] == query:
            # If the validation allows rerun, that we are here:
            bReRun = True
        # Example Validation
        # Warn only - Don't change bRun
        # Basically, we print a warning but don't change the bRun variable and the bReRun doesn't matter

        inst = self.instances[instance]
        ep, ep_vars = self.parse_query(query)

        if ep not in self.apis.keys():
            print(f"Endpoint: {ep} not in available APIs: {self.apis.keys()}")
            bRun = False
            if bReRun:
                print("Submitting due to rerun")
                bRun = True
        return bRun


    def customQuery(self, query, instance, reconnect=True):
        ep, ep_data = self.parse_query(query)
        ep_api = self.apis.get(ep, None)
        if self.debug:
            print(f"Query: {query}")
            print(f"Endpoint: {ep}")
            print(f"Endpoint Data: {ep_data}")
            print(f"Endpoint API Transform: {ep_api}")
            print("Session headers")
            print(self.instances[instance]['session'].headers)
        mydf = None
        status = ""
        str_err = ""
        if ep == "help":
            self.call_help(ep_data, instance)
            return mydf, "Success - No Results"

        try:
            if self.debug:
                print("! endpoint and cell data parsed !")
                print(f"API {ep_api}")
                print(f"DATA {ep_data}")
            if ep_api == "/search/?q=":
                myres=self.instances[instance]['session'].get(f'{self.base_url}{ep_api}{ep_data}')
            elif ep_api == "/scan/":
                data={"url":ep_data.strip(),"visibility":self.opts['urlscan_submission_visiblity'][0]}
                if self.debug:
                    print("Scanning the following submit data")
                    print(data)
                if self.opts['urlscan_submission_country'][0]:
                    data.update({"country":self.opts['urlscan_submission_country'][0]})
                else:
                    data.update({"country":random.choice(self.countries)})
                if self.opts['urlscan_submission_useragent'][0]:
                    data.update({"customagent":self.opts['urlscan_submission_useragent'][0]})
                if self.opts['urlscan_submission_referer'][0]:
                    data.update({"referer":self.opts['urlscan_submission_referer'][0]})
                req = Request('POST', f'{self.base_url}{ep_api}', headers=self.instances[instance]['session'].headers,data=data)
                staged = req.prepare()
                print(staged)
                print(staged.headers)
                print(staged.body)
                myres = self.instances[instance]['session'].send(staged,verify=self.opts['urlscan_verify_ssl'][0])
                #myres = self.instances[instance]['session'].post(f'{self.base_url}{ep_api}',data=json.dumps(ep_data))
            elif ep_api == "/result/":
                myres = self.instances[instance]['session'].get(f'{self.base_url}{ep_api}{ep_data}')
            elif ep_api == "/dom/":
                myres = self.instances[instance]['session'].get(f'https://urlscan.io{ep_api}{ep_data}')
            elif ep_api == "/screenshots/":
                myres = self.instances[instance]['session'].get(f'https://urlscan.io{ep_api}{ep_data}')
            else:
                mydf = None
                str_err = "Success - No Results"
            if myres is not None:
                mydf = pd.DataFrame(myres)
        except Exception as e:
            mydf = None
            str_err = str(e)

        if str_err.find("Success") >= 0:
            pass
        else:
            status = "Failure - query_error: " + str_err

        return mydf, status


    def parse_help_text(self):

        help_lines = self.help_text.split("\n")
        bmethods = False
        methods_dict = {}
        method = ""
        method_name = ""
        method_text = []
        inmethod = False
        for l in help_lines:
            if l.find(" |  -------------------------") == 0:
                if inmethod:
                    methods_dict[method_name] = {"title": method, "help": method_text}
                    method = ""
                    method_name = ""
                    method_text = []
                    inmethod = False
                bmethods = False
            if bmethods:
                if l.strip() == "|":
                    continue
                f_l = l.replace(" |  ", "")
                if f_l[0] != ' ':
                    inmethod = True
                    if inmethod:
                        if method_name.strip() != "":
                            if method_name == "__init__":
                                method_name = "API"
                            methods_dict[method_name] = {"title": method, "help": method_text}
                            method = ""
                            method_name = ""
                            method_text = []
                    method = f_l
                    method_name = method.split("(")[0]
                else:
                    if inmethod:
                        method_text.append(f_l)
            if l.find("|  Methods defined here:") >= 0:
                bmethods = True
        self.help_dict = methods_dict

    # This is the magic name.
    @line_cell_magic
    def urlscan(self, line, cell=None):
        if cell is None:
            line = line.replace("\r", "")
            line_handled = self.handleLine(line)
            if self.debug:
                print("line: %s" % line)
                print("cell: %s" % cell)
            if not line_handled: # We based on this we can do custom things for integrations. 
                if line.lower() == "testintwin":
                    print("You've found the custom testint winning line magic!")
                else:
                    print("I am sorry, I don't know what you want to do with your line magic, try just %" + self.name_str + " for help options")
        else: # This is run is the cell is not none, thus it's a cell to process  - For us, that means a query
            self.handleCell(cell, line)

##############################
