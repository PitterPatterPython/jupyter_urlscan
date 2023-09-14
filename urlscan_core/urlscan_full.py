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
from requests import Request, Session, Response

from urlscan_core._version import __desc__
from jupyter_integrations_utility.batchquery import df_expand_col
# Your Specific integration imports go here, make sure they are in requirements!
import jupyter_integrations_utility as jiu
#import IPython.display
from IPython.display import display_html, display, Javascript, FileLink, FileLinks, Image
import ipywidgets as widgets

##custom to urlscan integration
import random
from time import strftime, localtime, sleep
import jmespath
from io import BytesIO
import base64
from IPython.core.debugger import set_trace

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
    myopts['urlscan_batchsubmit_wait_time'] = [2, "Seconds between batch HTTP requests"]
    myopts['urlscan_batchsubmit_max_file_load'] = [100, "The number of submissions"]
    myopts['urlscan_redirect_wait'] = [5, "Seconds to wait on HTTP30X redirect"]
    myopts['urlscan_resultready_wait_time']=[12, "Seconds between submission and result polling"]
    myopts['urlscan_resultready_wait_attempts']=[3, "How many times to poll results before giving up."]
    myopts['urlscan_ssdisplay_height'] = [1200, "how many pixels wide for displaying an image"]
    myopts['urlscan_ssdisplay_width'] = [850, "how many pixels wide for screenshots for displaying an image"]
    myopts['urlscan_submission_visiblity'] = ["public", "Default visiblity for submissions to URLScan."]
    myopts['urlscan_submission_country'] = ["US","The country from which the scan should be performed"]
    myopts['urlscan_submission_referer'] = [None, "Override the HTTP referer for this scan"]
    myopts['urlscan_submission_useragent'] = [None, "Override useragent for this scan"]

    countries = ["de","us","jp","fr","gb","nl","ca","it","es","se","fi","dk","no","is","au","nz","pl","sg","ge","pt","at","ch"]

    """
    Key:Value pairs here for APIs represent the type? 
    """

    base_url = "https://urlscan.io/api/v1"
    other_base_url = "https://urlscan.io"

    apis={
        "scan": {
            'url':base_url,
            'path':"/scan/",
            'method':'POST',
            "switches":['-q','-b','-p']
        },
        "result":{
            'url':base_url,
            'path':"/result/<~~uuid~~>/",
            'method':'GET',
            'switches':['-b','-q'],
            'parsers':[
                ("page","page"),
                ("uuid","task.uuid"),
                ("report_url","task.reportURL"),
                ("verdicts","verdicts.overall"),
                ("cookies","data.cookies[*].[domain,name,value]"),
                ("embedded_links","data.links"),
                ("rdns","meta.processors.rdns.data[]"),
                ("certificates","lists.certificates[].[subjectName,issuer,validTo]"),
                ("tls_stats","stats.tlsStats"),
                ("protocol_stats","stats.protocolStats"),
                ("global_strings","data.globals[?type=='string'].[prop]"),
                ("global_functions","data.globals[?type=='function'].[prop]"),
                ("global_objects","data.globals[?type=='object'].[prop]"),
                ("global_booleans","data.globals[?type=='boolean'].[prop]"),
                ("domain_stats","stats.domainStats"),
                ("submitter","submitter")
            ]
        },
        "screenshot":{
            'url':other_base_url,
            'path':'/screenshots/<~~uuid~~>.png',
            'method':'GET',
            'switches':['-b'],
        },
        "dom":{
            'url':other_base_url,
            'path':"/dom/<~~uuid~~>/",
            'method':'GET',
            'switches':['-b'],
        },
        "search":{
            'url':base_url,
            'path':"/search/?q=<~~uuid~~>",
            'method':'GET',
            'switches':['-q'],
        },
        "dom_similar":{
            'url':base_url,
            'path':'/pro/result/<~~uuid~~>/similar/',
            'method':'GET',
            'switches':['-b','-q'],
            'parsers':[
                ('page','results[].page'),
                ('brand','results[].brand'),
                ('verdicts','results[].verdicts'),
                ('verdicts','results[].dom'),
                ('score','results[]._score'),
                ('text','results[].text'),
                ('result','results[].result'),
                ('result','results[].screenshot'),
                ('id','results[]._id')
            ]
        },
        "redirect_use_only":{
            'url':'',
            'path':'',
            'method':'GET',
            'switches':[],
            'parsers':[]
        },
    }



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
        qexamples.append(["myinstance", "scan -p\nhttps://this.supershady.url/", "Run a urlscan query for iris-enrich, optional -p flag enables POLLING, or waiting, for the results are ready, or a wait limit is reached, whichever occurs first."])
        qexamples.append(["","result -q\na353d4c9-2fa1-4b9b-8919-08ac1db9772a","Provide a UUID to retrieve results from URLScan for the submission associated to it. -q indicates the 'quiet' option, returning results to a dataframe without rendering that dataframe to the invoking user."])
        qexamples.append(["","dom -b\na353d4c9-2fa1-4b9b-8919-08ac1db9772a\na421e9d8-3eb2-4b9b-8919-18ad1dc9722b","Provide a UUID to retrieve results from URLScan for the submission associated to it. -b enables 'batching', sending more than a single submission in a query."])        
        out += self.retQueryHelp(qexamples)

        return out

    #This function stops the integration for prompting you for username
    def req_username(self, instance):
        bAuth=False
        return bAuth

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
                inst['session'].headers.update({'API-Key':mypass})
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
        command = q_items[0].strip().split(" ")
        command = list(filter(None,command))
        end_point_switches = []
        end_point = command[0].lower()
        if len(command) > 1:
            end_point_switches = command[1:] 
        if len(q_items[1:]) >= 1:
            end_point_vars = list(set(list(filter(None,list(map(lambda variable : variable.strip(),q_items[1:]))))))
        else:
            end_point_vars = None
        return end_point, end_point_vars, end_point_switches

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
        ep, ep_vars, eps = self.parse_query(query)

        if ep not in self.apis.keys():
            print(f"Endpoint: {ep} not in available APIs: {self.apis.keys()}")
            bRun = False
            if bReRun:
                print("Submitting due to rerun")
                bRun = True

        if not set(eps).issubset(self.apis[ep]['switches']):
            bRun = False
            print(f"Endpoint: {ep} does not support switch {eps}")
            print(f"Supported switches: {self.apis[ep]['switches']}")

        return bRun


    def display_screenshot(self, response, width, height):
        b64_img_data = base64.b64encode(response.content).decode()
        try:
            output = f"""
                <img
                    height="{str(height)}"
                    width="{str(width)}"
                    src="data:image/png;base64,{b64_img_data}"
                />
            """
            display(HTML(output))
        except Exception as e:
            print(f"An error with IPython.display occured: {str(e)}")
        return 


    def buildRequest(self,ep,ep_data):
        post_data = None
        method = self.apis[ep.lower()]['method']
        api_url = self.apis[ep.lower()]['url']+self.apis[ep.lower()]['path']

        if method=='POST':
            post_data={"url":ep_data.strip(),"visibility":self.opts['urlscan_submission_visiblity'][0]}
            if self.opts['urlscan_submission_country'][0]:
                post_data.update({"country":self.opts['urlscan_submission_country'][0]})
            else:
                post_data.update({"country":random.choice(self.countries)})
            if self.opts['urlscan_submission_useragent'][0]:
                post_data.update({"customagent":self.opts['urlscan_submission_useragent'][0]})
            if self.opts['urlscan_submission_referer'][0]:
                post_data.update({"referer":self.opts['urlscan_submission_referer'][0]})

        elif method=='GET':
            api_url=f"{self.apis[ep.lower()]['url']}{self.apis[ep.lower()]['path']}"
            api_url=api_url.replace('<~~uuid~~>', ep_data.strip())

        return method,api_url,post_data



    def execute_request(self, instance, ep, ep_data, polling=False, batching=False):
        """
        Parameters
        ----------
        ep : str
            represents a user given command, maps to an endpoint
        ep_data : str|list
            data passed to 'cell' after line, ep
        polling : bool, optional
            If True, polls URLScan results after submission for X attempts by Y
            interval, as defined by myopts['urlscan_resultready_wait_attempts']
            and myopts['urlscan_resultready_wait_time'] respectively
        batching : bool, optional
            If True, tells execute_request NOT to instantiate instance globals
            _dict and _raw for prev_%yourmagic%_%yourinstance%_, presumes you
            will handle the variables downstream as an aggregate

        Output
        ------
        myres : requests.models.Response
            A reponse object containing data from URLScan API endpoint
        """

        method, api_url, post_data = self.buildRequest(ep, ep_data)
        if self.debug:
            print('!'*20)
            print('Executing request:')
            print(api_url)
            print(method)
            print(post_data)
            print('!'*20)

        while True:
            myres = self.instances[instance]['session'].request(method,api_url,json=post_data,verify=self.opts['urlscan_verify_ssl'][0])
            if myres.status_code==301 or myres.status_code==302 or myres.status_code==308:
                api_url=myres.headers.get('Location')
                method='GET'
                post_data=None
                sleep(self.opts['urlscan_redirect_wait'][0])
            else:
                break
        if polling:
            endpoint = ""
            if ep == 'scan': #we are polling for a different endpoint 
                endpoint = 'result'
                input_data = myres.json().get('uuid')
            else:
                endpoint = ep
                input_data = ep_data
            for i in range(0,self.opts['urlscan_resultready_wait_attempts'][0]):
                sleep(self.opts['urlscan_resultready_wait_time'][0])
                polled_response = self.execute_request(instance, endpoint,input_data) 
                if polled_response.ok:
                    break
            myres = polled_response

        if not batching:
            if ep!='dom' and ep!='screenshot':#would break responses jsonlib
                self.ipy.user_ns[f'prev_{self.name_str}_{instance}_dict']={ep_data[0]:myres.json()}
            self.ipy.user_ns[f'prev_{self.name_str}_{instance}_raw']=myres.content

        return myres 


    def execute_batch_request(self, instance, ep, data, polling=False):
        """
        Params
        ------
        instance - str - represents the instance in self.instances[{instance}]
        ep - str - represents the endpoint/command passed by the user
        data - list - a list of data provided in the %magics cell by the user
        polling - bool - (default False) if True, tells execute_request to poll
        the API for results after submissions
        Returns
        -------
        """

        results = []

        self.ipy.user_ns[f'prev_{self.name_str}_{instance}_dict']={}
        self.ipy.user_ns[f'prev_{self.name_str}_{instance}_raw']={}
        
        for post_data in data:
            if self.debug:
                print(f"Batch processing, running: {post_data}")

            myres = self.execute_request(instance, ep,post_data,batching=True)

            try:
                if ep=='dom' or ep=='screenshot':
                    self.ipy.user_ns[f'prev_{self.name_str}_{instance}_dict'].update({post_data:None})
                else:
                    self.ipy.user_ns[f'prev_{self.name_str}_{instance}_dict'].update({post_data:myres.json()})
            except Exception as e:
                print(f"Error occured while parsing Response to 'dict' {str(e)}")
                self.ipy.user_ns[f'prev_{self.name_str}_{instance}_dict'].update({post_data:None})
                pass
            self.ipy.user_ns[f'prev_{self.name_str}_{instance}_raw'].update({post_data:myres.content})
            results.append(myres)
            sleep(self.opts['urlscan_batchsubmit_wait_time'][0])
        return results

    def parse_response(self, response,ep):
        """
        Description
        -----------
        This is a place holder function for future parsing use cases

        Parameters
        ----------
        response - type requests.model.Response - A response object
        ep - type string - Represents the endpoint passed to parse

        Output
        ------
        filtered_dict - type dictionary - A dictionary representing a filtered
        json string interpreted from the response object provided
        """

        if 'X-Rate-Limit-Limit' in response.headers.keys() and float(int(response.headers.get('X-Rate-Limit-Remaining'))/int(response.headers.get('X-Rate-Limit-Limit')))<0.11:
            print("!"*22) 
            print("! RATE LIMIT WARNING !")
            print("!"*22) 
            print(f"Rate Limiting:{response.headers.get('X-Rate-Limit-Remaining')}")
            print(f"You have {response.headers.get('X-Rate-Limit-Limit')} requests to your limit.")
            print(f"Rate Limit resets on {str(response.headers.get('X-Rate-Limit-Reset'))}")
            print(f"Rate Limit resets in {str(response.headers.get('X-Rate-Limit-Reset-After'))} seconds")
            print("If this request was a 'private' submission, you can switch to use 'unlisted' to work around this quota.")
        try:
            parsed = {}
            if isinstance(response, Response):
                if response.status_code==200:
                    if self.apis[ep].get('parsers'):
                        for parser in self.apis[ep].get('parsers'):
                            if ep=='result':
                                parsed.update({parser[0]:[jmespath.search(parser[1],response.json())]})
                            elif ep=='dom_similar':
                                parsed.update({parser[0]:jmespath.search(parser[1],response.json())})
                    else:
                        parsed = response.json()

                return parsed 
        except Exception as e:
            print(f"Error while parsing JSON from request: {str(e)}")
        return

    def customQuery(self, query, instance, reconnect=True):
        ep, ep_data, eps = self.parse_query(query)
        ep_api = self.apis.get(ep, None)

        if self.debug:
            print(f"Endpoint: {ep}")
            print(f"Endpoint Data: {ep_data}")
            print(f"Endpoint Switches: {eps}")

        mydf = None
        status = ""
        str_err = ""
        quiet=False
        batch=False
        polling=False

        if ep == "help":
            self.call_help(ep_data, instance)
            return mydf, "Success - No Results"

        if "-q" in eps:
            quiet=True

        if "-b" in eps or len(ep_data)>1:
            batch=True

        if "-p" in eps:
            polling=True

        try:
            if batch:
                myres = self.execute_batch_request(instance, ep, ep_data, polling=polling)
            else:
                myres = self.execute_request(instance, ep, ep_data[0],polling=polling)
            if ep=='dom':
                quiet = True
                print(f"""
                DOM content put into variables: 
                prev_{self.name_str}_{instance}_raw
                prev_{self.name_str}_{instance}_dict
                """)
                str_err = "Success - No Results"
            elif ep=='screenshot':
                print(f"""
                Screenshot content put into variables: 
                prev_{self.name_str}_{instance}_raw
                prev_{self.name_str}_{instance}_dict
                """)
                if not quiet: #display
                    width=self.opts['urlscan_ssdisplay_width'][0]
                    height=self.opts['urlscan_ssdisplay_height'][0]
                    if isinstance(myres, list):
                        for resp in myres:
                            self.display_screenshot(resp,width, height)
                    else:
                        self.display_screenshot(myres,width, height)
                str_err = "Success - No Results"
            else: # ep was scan, result, search
                if isinstance(myres,list):
                    batch_results = [self.parse_response(r,ep) for r in myres]
                    mydf = pd.DataFrame(batch_results,index=list(range(0,len(batch_results))))
                else:
                    if ep=='scan': index=[0]
                    else: index=None
                    mydf = pd.DataFrame(self.parse_response(myres,ep),index=index)
                str_err = "Success"
                if quiet:
                    str_err = str_err + " - No Results"
                else:
                    str_err = str_err + " - Results"

        except Exception as e:
            mydf = None
            str_err = str(e)
            print(str_err)

        if str_err.find("Success") >= 0:
            status = status+str_err
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
