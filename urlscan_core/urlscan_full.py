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
    myopts['urlscan_resultready_wait_time']=[15, "Seconds between submission and result polling"]
    myopts['urlscan_resultready_wait_attempts']=[3, "How many times to poll results before giving up."]
    myopts['urlscan_ssdisplay_height'] = [800, "how many pixels for screenshots"]
    myopts['urlscan_ssdisplay_width'] = [500, "how many pixels for screenshots"]
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

    apis = {
            "scan": {'url':base_url,'path':"/scan/",'method':'POST','parsers':[],"switches":['-q','-b','-p']},
            "result": {
                'url':base_url,
                'path':"/result/",
                'method':'GET',
                'switches':['-b','-q'],
                ## column_name & column_value as jmespath valid string
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
            "screenshot":{'url':other_base_url,'path':'/screenshots/','method':'GET','switches':['-b','-d']},
            "dom":{'url':other_base_url,'path':"/dom/",'method':'GET','switches':['-b','-d']},
            "search": {'url':base_url,'path':"/search/?q=",'method':'GET','switches':['-q']}
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
        qexamples.append(["myinstance", "scan\nhttps://this.supershady.url/", "Run a urlscan query for iris-enrich"])
        qexamples.append(["","result\na353d4c9-2fa1-4b9b-8919-08ac1db9772a","Provide a UUID to retrieve results from URLScan for the submission associated to it."])
        qexamples.append(["","dom\na353d4c9-2fa1-4b9b-8919-08ac1db9772a","Provide a UUID to retrieve results from URLScan for the submission associated to it."])
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


    def fileDownload(self, response, uuid):
        if self.debug:
            print('fileDownload')
            print(response)
            print(uuid)
        status = -1
        if os.access('.', os.W_OK):
            f = open(f"dom_{uuid}.txt","wb")
            try:
                f.write(response.content)
            except Exception as e:
                print(f"An error has occured:\n{str(e)}")
                print(status=-2)
            finally:
                f.flush()
                f.close()
                status = 0
        else:
            print("Please check that you are in a writeable directory before making this request.") 
        return status 

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

    def _apiResultParser(self, scan_result, parsers):
        if self.debug:
            print('_apiResultParser')
            print(type(scan_result))
            print(parsers)
        parsed = {}
        for expression in parsers:
            parsed.update({expression[0]:[jmespath.search(expression[1],scan_result.json())]})
        return parsed

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
            api_url=f"{self.apis[ep.lower()]['url']}{self.apis[ep.lower()]['path']}{ep_data.strip()}"
            if ep.lower()=='screenshot':
                api_url=api_url+'.png'
            if ep.lower()=='result':
                api_url=api_url+'/'

        return method,api_url,post_data



    def execute_request(self, instance, ep, ep_data, download=False,polling=False):
        """
        Parameters
        ----------
        ep : str
            represents a user given command, maps to an endpoint
        ep_data : str|list
            data passed to 'cell' after line, ep
        download : bool, optional
            If True, for some endpoints, will download the target sample ot
            local directory
        polling : bool, optional
            If True, polls URLScan results after submission for X attempts by Y
            interval, as defined by myopts['urlscan_resultready_wait_attempts']
            and myopts['urlscan_resultready_wait_time'] respectively

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

        myres = self.instances[instance]['session'].request(method,api_url,json=post_data,verify=self.opts['urlscan_verify_ssl'][0])
        self.check_rate_limit(myres)

        if polling:
            endpoint = ""
            if ep == 'scan': #we are polling for a different endpoint 
                endpoint = 'result'
                input_data = myres.json().get('uuid')
            else:
                endpoint = ep
                input_data = ep_data

            if self.debug:
                print(f"Polling")
                print(f"Polling endpoint {ep}")
                print(f"Polling input data {input_data}")

            for i in range(0,self.opts['urlscan_resultready_wait_attempts'][0]):
                sleep(self.opts['urlscan_resultready_wait_time'][0])
                polled_response = self.execute_request(instance, endpoint,input_data) 
                if polled_response.ok:
                    break

            myres = polled_response

        if (ep=='screenshot' or ep=='dom' or ep=='result') and (myres.status_code==302 or myres.status_code==301):
            redirect_link = myres.headers.get('Location')
            result = re.search(r'\/[a-f0-9\-]{36}\/',redirect_link)
            if result:
                myres = self.execute_request(instance, ep, result.group(0))
            else:
                print("The resource has moved")
                print(redirect_link)
                
        if self.debug:
            print("Execution result")
            print(f"HTTP {str(myres.status_code)}\n{myres.content[0:100]}")

        return myres


    def execute_batch_request(self, instance, ep, data, download=False, polling=False):
        results = []
        raw_content = []
        dicts = [] 

        self.ipy.user_ns[f'prev_{self.name_str}_{instance}_dict']={}
        self.ipy.user_ns[f'prev_{self.name_str}_{instance}_raw']={}
        
        for post_data in data:
            if self.debug:
                print(f"Batch processing, running: {post_data}")
            myres = self.execute_request(instance, ep,post_data)
            self.check_rate_limit(myres)
            try:
                self.ipy.user_ns[f'prev_{self.name_str}_{instance}_dict'].update({post_data:myres.json()})
            except Exception as e:
                print(f"Error occured while parsing Response to 'dict' {str(e)}")
                self.ipy.user_ns[f'prev_{self.name_str}_{instance}_dict'].update({post_data:None})
                pass
            self.ipy.user_ns[f'prev_{self.name_str}_{instance}_raw'].update({post_data:myres.content})
            results.append(myres)
            sleep(self.opts['urlscan_batchsubmit_wait_time'][0])

        return results


    def check_rate_limit(self,myres):
        # Rate limit parsing (specific to URLScan)
        if 'X-Rate-Limit-Limit' in myres.headers.keys() and float(int(myres.headers.get('X-Rate-Limit-Remaining'))/int(myres.headers.get('X-Rate-Limit-Limit')))<0.11:
            print("!"*22) 
            print("! RATE LIMIT WARNING !")
            print("!"*22) 
            print(f"Rate Limiting:{myres.headers.get('X-Rate-Limit-Remaining')}")
            print(f"You have {myres.headers.get('X-Rate-Limit-Limit')} requests to your limit.")
            print(f"Rate Limit resets on {str(myres.headers.get('X-Rate-Limit-Reset'))}")
            print(f"Rate Limit resets in {str(myres.headers.get('X-Rate-Limit-Reset-After'))} seconds")
            print("If this request was a 'private' submission, you can switch to use 'unlisted' to work around this quota.")
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
        download=False
        quiet=False
        batch=False
        polling=False

        if ep == "help":
            self.call_help(ep_data, instance)
            return mydf, "Success - No Results"

        if "-q" in eps:
            quiet=True

        if "-d" in eps:
            download=True

        if "-b" in eps or len(ep_data)>1:
            batch=True

        if "-p" in eps:
            polling=True

        try:
            if batch:
                myres = self.execute_batch_request(instance, ep, ep_data, download=download,polling=polling) #returns an array of response objects 
            else:
                myres = self.execute_request(instance, ep, ep_data[0],download=download,polling=polling) #returns a response object
            
            if ep=='dom':
                mydf=None
                quiet = True
                print(f"""
                    DOM content put into variables: 
                    prev_{self.name_str}_{instance}_raw
                    prev_{self.name_str}_{instance}_dict
                """)
                str_err = "Success - No Results"
            elif ep=='screenshot':
                mydf=None
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
                    mydf = pd.DataFrame(myres)
                else:
                    mydf = pd.DataFrame(myres.json())
                str_err = "Success"
                if quiet:
                    str_err + " - No Results"
                else:
                    str_err + " - Results"

        except Exception as e:
            mydf = None
            str_err = str(e)
            print(str_err)

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
