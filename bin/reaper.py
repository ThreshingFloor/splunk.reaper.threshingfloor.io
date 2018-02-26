#!/usr/bin/env python

import sys, time, re
from splunklib.searchcommands import \
    dispatch, EventingCommand, Configuration, Option, validators
from libtf.logparsers import TFAuthLog, TFHttpLog, TFGenericLog
import ConfigParser
import os
import StringIO
import subprocess

@Configuration()
class ReaperReduceCommand(EventingCommand):
    """ Filters out noise from Splunk queries by leveraging the Threshing Floor
        API.
    ##Syntax
    .. code-block::
        reaper logtype=<http, auth, generic> <port=<int>:<'udp|tcp'>>
    ##Description
    The :code:`reaper` command filters network security noise from HTTP logs,
    ssh access logs, and generic log files.
    """

    BASE_URI = "https://api.threshingfloor.io"
    API_KEY = ""

    logtype = Option(
        doc='''**Syntax:** **type'=***<event-type>*
        **Description:** The type of events you wish to reduce. Can be `http`, `auth`, or `generic`.''',
        name='type',
        validate=validators.Set('http', 'auth', 'generic'))

    ports = Option()


    def get_config(self, conf_file_name, section):
        env = dict()
        env.update(os.environ)
        splunk_home = env.get('SPLUNK_HOME', '/Applications/Splunk')
        btool = os.path.join(splunk_home, "bin", "btool")
        tmp = subprocess.Popen([btool, conf_file_name, "list"],
                               stdout=subprocess.PIPE, env=env)
        (output, error) = tmp.communicate()

        f = StringIO.StringIO()
        f.write(output)
        f.seek(0)
        cfgparse = ConfigParser.RawConfigParser()
        cfgparse.readfp(f)

        cfg = dict()
        for opt in cfgparse.options(section):
            cfg[opt] = cfgparse.get(section, opt)
        return cfg

    def transform(self, events):
        # We have like, 3 copies of the events which is not optimal
        dictEvent = []
        rawEvents = []

        # Save off the events so they can be parsed by the library
        for event in events:
            dictEvent.append(event)
            rawEvents.append(event['_raw'])

        # Set to generic mode if ports are present and no type is specified
        if self.logtype == None and self.ports != None:
            self.logtype = 'generic'
        else:
            self.logtype = self.guessType(rawEvents)

        # Send an error if 
        if self.logtype == 'generic' and self.ports == None:
            raise Exception("Generic mode requires the port option.")

        # Get the ports of we have them
        if self.ports:
            ports = self.ports.split(";")

        # Initialize the correct log type
        if self.logtype == 'auth':
            analyzed = TFAuthLog(rawEvents, self.API_KEY, self.BASE_URI)
        elif self.logtype == 'http':
            analyzed = TFHttpLog(rawEvents, self.API_KEY, self.BASE_URI)
        elif self.logtype == 'generic':
            analyzed = TFGenericLog(rawEvents, ports, self.API_KEY, self.BASE_URI)
        else:
            raise TFException("Failed to parse the query.")

        reduced = analyzed.reduce()
        reducedItem = reduced.next()

        for i in range(0, len(dictEvent)):
            if dictEvent[i]['_raw'] == reducedItem:
                yield dictEvent[i]
                reducedItem = reduced.next()

        return

    def guessType(self, logfile, baseName=None):
        REGEX_HTTP = "^\[(?P<timestamp>.+)?\]\s\"(?P<request>.+?)\"\s(?P<responseCode>\d+)\s(?P<size>\d+)(?P<combinedFields>.*)"

        # If we can't do that, we will read 10 lines in, then try to match with a regular expression
        logline = logfile[min(10, len(logfile)-1)]

        try:

            # See if it's http
            splitLine = logline.split()
            m = re.search(REGEX_HTTP, " ".join(splitLine[3:]))
            if m:
                return 'http'

            # See if it's auth
            try:
                # Try and make a timestamp from the beginning of the line
                if int(time.mktime(time.strptime(" ".join(splitLine[0:3]) + " " + "2017", "%b %d %H:%M:%S %Y"))) > 0:
                    return 'auth'
            except Exception as e:
                pass

            # If we haven't returned by now, we can't figure out the type
            raise TFException("Unable to automatically identify the log type. Please specify a type with the -t flag.")
        except IOError as e:
            exit()

    def __init__(self):
        EventingCommand.__init__(self)

        conf = self.get_config('threshingfloor', 'api-config')
        self.BASE_URI = conf.get('base_uri', None)
        self.API_KEY = conf.get('api_key', None)

dispatch(ReaperCommand, sys.argv, sys.stdin, sys.stdout, __name__)
