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
from requests import Session, JSONDecodeError
from requests.models import Response

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
    myopts['urlscan_verify_ssl'] = [False, "Verify integrity of SSL"]
    myopts['urlscan_rate_limit'] = [True, "Limit rates based on URLScan user configuration"]
    myopts['urlscan_batchsubmit_wait_time'] = [2, "Seconds between batch HTTP requests"]
    myopts['urlscan_batchsubmit_max_file_load'] = [100, "The number of submissions"]
    myopts['urlscan_batchsubmit_error_concat'] = [100, "The length of error messages printed during batchsubmission processing"]
    myopts['urlscan_redirect_wait'] = [5, "Seconds to wait on HTTP30X redirect"]
    myopts['urlscan_resultready_wait_time']=[6, "Seconds between submission and result polling"]
    myopts['urlscan_resultready_wait_attempts']=[6, "How many times to poll results before giving up."]
    myopts['urlscan_ssdisplay_height'] = [1200, "how many pixels wide for displaying an image"]
    myopts['urlscan_ssdisplay_width'] = [850, "how many pixels wide for screenshots for displaying an image"]
    myopts['urlscan_submission_visiblity'] = ["private", "Default visiblity for submissions to URLScan."]
    myopts['urlscan_submission_country'] = ["US","The country from which the scan should be performed"]
    myopts['urlscan_submission_referer'] = [None, "Override the HTTP referer for this scan"]
    myopts['urlscan_submission_useragent'] = [None, "Override useragent for this scan"]
    myopts['urlscan_nodecode_error'] = [300, "The number of characters to allow before truncating error message strings related to non-decode errors"]
    myopts['urlscan_special_stop_code'] = [[400,429],"Error codes from the web server that a developer may want to respect to take special action."]
    myopts['urlscan_redirect_codes']=[[301,302,308],"Redirect codes that may require special handling by the integration developer"]

    countries = ["de","us","jp","fr","gb","nl","ca","it","es","se","fi","dk","no","is","au","nz","pl","sg","ge","pt","at","ch"]

    """
    Key:Value pairs here for APIs represent the type? 
    """

    apis={
        "scan": {
            'path':"/api/v1/scan/",
            'method':'POST',
            "switches":['-b','-p','--random-ip','--custom-ref','--custom-ua'],
            'decodes':True,
            'parsers':[],
            'stop_codes':[200,400],
            'post_body':{'url':'<~~replace~~>','visibility':'private','country':'US'},
            'map_field':'url',
            'polling_ep':'result',
            'polling_data':'uuid'
        },
        "result":{
            'path':"/api/v1/result/<~~uuid~~>/",
            'decode':True,
            'replace_me':'<~~uuid~~>',
            'method':'GET',
            'switches':['-b'],
            'decodes':True,
            'stop_codes':[200],
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
            'path':'/screenshots/<~~uuid~~>.png',
            'replace_me':'<~~uuid~~>',
            'method':'GET',
            'switches':['-b','-q'],
            'stop_codes':[200],
            'display':True
        },
        "dom":{
            'path':"/dom/<~~uuid~~>/",
            'replace_me':'<~~uuid~~>',
            'method':'GET',
            'stop_codes':[200],
            'switches':['-b']
        },
        "search":{
            'path':"/api/v1/search/?q=<~~uuid~~>",
            'replace_me':'<~~uuid~~>',
            'method':'GET',
            'switches':[''],
            'decodes':True,
            'stop_codes':[200],
            'parsers':[]
        },
        "dom_similar":{  
            'path':'/api/v1/pro/result/<~~uuid~~>/similar/',
            'replace_me':'<~~uuid~~>',
            'method':'GET',
            'switches':['-b'],
            'decodes':True,
            'stop_codes':[200],
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
        "visual_similar":{
            'path':'/api/v1/search/?q=visual%3Aminscore-1650%7C<~~uuid~~>',
            'replace_me':'<~~uuid~~>',
            'method':'GET',
            'switches':[],
            'decodes':True,
            'stop_codes':[200],
            'parsers':[
                ('uuid','results[].task.uuid'),
                ('domain','results[].task.domain'),
                ('url','results[].task.url'),
            ]
        },
        "redirect_use_only":{
            'path':'',
            'method':'GET',
            'switches':[],
            'decodes':True,
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
        qexamples.append(["","result \na353d4c9-2fa1-4b9b-8919-08ac1db9772a","Provide a UUID to retrieve results from URLScan for the submission associated to it."])
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
                myproxies = self.retProxy(instance)
            else:
                myproxies = None
            
            inst['base_url']=inst['scheme']+"://"+inst['host']
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

            inst['session'].verify=self.opts['urlscan_verify_ssl'][0]
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
            end_point_data = list(set(list(filter(None,list(map(lambda variable : variable.strip(),q_items[1:]))))))
        else:
            end_point_data = None
        return end_point, end_point_data, end_point_switches

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


    def display_screenshot(self, content, width, height,quiet=False):
        """
        Parameters
        ----------
        content : bytes - bytes representing an image string
        width : int - represents how many pixels wide an image will be rendereds
        height : int - represents how many pixels high an image will be rendered
        quiet : bool - if true, will not display 

        Output
        ------
        b64_img_string : str - base64 encoded string created from 'content' param
        """
        try:
            b64_img_data = base64.b64encode(content).decode()
            output = f"""
                <img
                    height="{str(height)}"
                    width="{str(width)}"
                    src="data:image/png;base64,{b64_img_data}"
                />
            """
            if not quiet:
                display(HTML(output))
        except Exception as e:
            print(f"An error with IPython.display occured: {str(e)}")
        return b64_img_data


    def buildRequest(self,instance,ep,ep_data,map_field=None):
        post_data = None
        method = self.apis[ep.lower()]['method']
        api_url = self.instances[instance]['base_url']+self.apis[ep.lower()]['path']

        if method=='POST':
            post_data=self.apis[ep].get('post_body',None)
            post_data.update({map_field:ep_data})

        elif method=='GET':
            api_url=f"{self.instances[instance]['base_url']}{self.apis[ep.lower()]['path']}"
            api_url=api_url.replace(self.apis[ep.lower()].get('replace_me'), ep_data.strip())

        return method,api_url,post_data

    def response_decodes(self, response : Response):
        try:        
            response.json()
        except JSONDecodeError as json_e:
            return False
        return True
    
    def check_rate_limit(self, headers : dict):
        if 'X-Rate-Limit-Limit' in headers.keys() and float(int(headers.get('X-Rate-Limit-Remaining'))/int(headers.get('X-Rate-Limit-Limit')))<0.11:
            print("!"*22) 
            print("! RATE LIMIT WARNING !")
            print("!"*22) 
            print(f"Rate Limiting:{headers.get('X-Rate-Limit-Remaining')}")
            print(f"You have {headers.get('X-Rate-Limit-Limit')} requests to your limit.")
            print(f"Rate Limit resets on {str(headers.get('X-Rate-Limit-Reset'))}")
            print(f"Rate Limit resets in {str(headers.get('X-Rate-Limit-Reset-After'))} seconds")
            print("If this request was a 'private' submission, you can switch to use 'unlisted' to work around this quota.")
        return 

    def execute_request(self, instance : str, ep : str, data : str, polling : bool = False):
        """
        Description
        -----------

        This function makes requests using the Python requests library, and can optionally poll for responses
        
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
        bDecode : bool - bool flag indicating if the 'text' object passed be decoded into a dictionary object using the JSON library
        status : bool - bool flag indicating if response object 'ok' field is True or False
        status_code : int value represents response status code from interacting web server
        text : str - the response content (in decoded text) sent from interacting web server
        content : bytes - raw bytes as provided by the interacting web server
        """

        method, api_url, post_data = self.buildRequest(instance, ep, data,map_field=self.apis[ep].get('map_field',None))
        final_response=None
        try:
            response = self.instances[instance]['session'].request(method,api_url,json=post_data)
            final_response = response
        except Exception as e:
            print(f"An error occured while performing {method} on {api_url} with {post_data}\n{str(e)}")
            return False, False, None, None, None
        
        if polling and response.ok:
            limit = self.opts['urlscan_resultready_wait_attempts'][0]
            wait = self.opts['urlscan_resultready_wait_time'][0]     
            print(f"""
                Waiting {wait} seconds 
                after each submission to ask {str(self.name_str)} if the results are ready for a 
                maximum of {limit} attempts...
            """)
            data = response.json().get(self.apis[ep].get('polling_data',data)) #change the data if necessary to get the result
            ep = self.apis[ep].get('polling_ep',ep) #change the endpoint if necessary to get the result
            method, api_url, post_data = self.buildRequest(instance, ep, data,self.apis[ep].get('map_field',None))
            last_response = None
            for i in range(0,limit):
                response = self.instances[instance]['session'].request(method,api_url,json=post_data)
                if self.debug:
                    print("debugging polling!")
                    print(response.ok)
                    print(response.url)
                    print(method)
                    print(post_data)
                last_response = response
                if response.status_code in self.opts['urlscan_special_stop_code'][0]:
                    break
                if response.status_code in self.opts['urlscan_redirect_codes'][0]:
                    method='GET'
                    api_url=response.headers.get('Location')
                    post_data=None
                    wait = self.opts['urlscan_redirect_wait'][0]
                    #check for statuscode stop condition
                if response.ok or response.status_code in self.apis[ep].get('stop_codes'): break
                sleep(wait)
            final_response=last_response
        return self.response_decodes(final_response), final_response.ok, final_response.status_code, final_response.text, final_response.content 


    def execute_batch_request(self, instance, ep, data, polling=False):
        """
        Parameters
        ----------
        instance - str - represents the instance in self.instances[{instance}]
        ep - str - represents the endpoint/command passed by the user
        data - list - a list of data provided in the %magics cell by the user
        polling - bool - (default False) if True, tells execute_request to poll
        the API for results after submissions
        
        Output
        ------
        results : list - a list of dictionary objects representing requests.Response objects.
        """

        results = []

        self.ipy.user_ns[f'prev_{self.name_str}_{instance}_dict']={}
        self.ipy.user_ns[f'prev_{self.name_str}_{instance}_raw']=[]
        
        for post_data in data:
            sleep(self.opts['urlscan_batchsubmit_wait_time'][0])
            if self.debug:
                print(f"Batch processing, running: {post_data}")

            canDecode, status, status_code, response_text,content = self.execute_request(instance,ep,post_data,polling=polling)
            if not status: #filter out anything that isn't a valid 200 response with parsable data from the API
                #at least prompt the user
                print(f'Failure to retrieve sample: {post_data} - Status Code: {str(status_code)}')
                print(f"{response_text[:self.opts['urlscan_batchsubmit_error_concat'][0]]}...")
                print('Skipping...')
                continue
            else:
                #These responses should be parsed, and added routed back to the user in an appropriate means
                try:
                    sample = self.defang_url(post_data)
                    if canDecode:
                        sample_data = json.loads(response_text)
                        self.ipy.user_ns[f'prev_{self.name_str}_{instance}_dict'].update({sample:sample_data})
                        sample_data.update({'sample':sample})
                        results.append(sample_data)
                    else:
                        self.ipy.user_ns[f'prev_{self.name_str}_{instance}_dict'].update({sample:response_text})
                        results.append({'sample':sample,'_raw':content})
                except Exception as e:
                    print(f"Error occured while parsing Response to 'dict' {str(e)}")
                    self.ipy.user_ns[f'prev_{self.name_str}_{instance}_dict'].update({self.defang_url(post_data):None})
                    pass
                self.ipy.user_ns[f'prev_{self.name_str}_{instance}_raw'].append({self.defang_url(post_data):content})
            
        return results

    def defang_url(self,input):
        return re.sub(r'((?:^|[\'\"])(?:s(?=f))?)[fh](t?tp)',r'\1x\2',input) 

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
            print("Quiet mode enabled")
            quiet=True

        if "-b" in eps or len(ep_data)>1:
            print("Batch processing enabled")
            batch=True

        if "-p" in eps:
            print("Polling enabled")
            polling=True

        try:
            # make the request(s) to API, get results
            if batch:
                results = self.execute_batch_request(instance, ep, ep_data, polling=polling)
            else:
                canDecode, ok, status_code, response_text,content = self.execute_request(instance, ep, ep_data[0],polling=polling)
                if canDecode: 
                    self.ipy.user_ns[f'prev_{self.name_str}_{instance}_dict']=json.loads(response_text)
                    if ep=='scan':
                        index=[0]
                    elif ep=='scan' and polling:
                        index=None
                        ep='result'
                    else: index=None
                else: #can't decode this content without throwing a JSON error, data not appropriate for a pd.DataFrame
                    self.ipy.user_ns[f'prev_{self.name_str}_{instance}_dict']=None
                self.ipy.user_ns[f'prev_{self.name_str}_{instance}_raw']=content

            # based on the endpoint, process the results
            if ep.lower() in ['screenshot','dom']: #screenshots and dom don't go in a data frame
                print(f"""
                {ep} command invoked, output put into variables:
                prev_{self.name_str}_{instance}_raw
                prev_{self.name_str}_{instance}_dict
                """)
                if self.apis[ep].get('display',False):
                    if batch:
                        self.ipy.user_ns[f'prev_{self.name_str}_{instance}_img']=[]
                        for resp in results:
                            b64 = self.display_screenshot(resp['_raw'],self.opts['urlscan_ssdisplay_width'][0],self.opts['urlscan_ssdisplay_height'][0],quiet=quiet)
                            self.ipy.user_ns[f'prev_{self.name_str}_{instance}_img'].append(b64)
                    else:
                        b64 = self.display_screenshot(content,self.opts['urlscan_ssdisplay_width'][0], self.opts['urlscan_ssdisplay_height'][0],quiet=quiet)
                        self.ipy.user_ns[f'prev_{self.name_str}_{instance}_img']=b64
                str_err = "Success - No Results"
            else: # ep was scan, result, search, or visual_search
                if batch:
                    mydf = pd.DataFrame(results)
                    str_err="Success"
                else: #single request
                    if ep=='result' and canDecode:
                        mydf = pd.DataFrame([json.loads(response_text)],index=index)
                        str_err = "Success"
                    elif canDecode:
                        mydf = pd.DataFrame(json.loads(response_text),index=index)
                        str_err = "Success"
                    else:
                        str_err = f"HTTP:{str(status_code)} - {response_text[:self.opts['urlscan_nodecode_error'][0]]}..."
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
