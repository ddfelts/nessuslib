################################################
# Originally written by: averagesecurityguy
# Modified by Me
# Created it as a class
################################################

import requests
import json
import time
import sys

class nessuslib: 

      def __init__(self,url,user,passw):
          self.url = url
          self.username = user
          self.password = passw
          self.verify = False
          self.token = ''
          self.token = self.login(user,passw)

      def build_url(self,resource):
          return '{0}{1}'.format(url, resource)

      def connect(self,method, resource, data=None):
          """
          Send a request

          Send a request to Nessus based on the specified data. If the session token
          is available add it to the request. Specify the content type as JSON and
          convert the data to JSON format.
          """
          headers = {'X-Cookie': 'token={0}'.format(self.token),
                     'content-type': 'application/json'}

          data = json.dumps(data)

          if method == 'POST':
             r = requests.post(self.build_url(resource), data=data, headers=headers, verify=self.verify)
          elif method == 'PUT':
             r = requests.put(self.build_url(resource), data=data, headers=headers, verify=self.verify)
          elif method == 'DELETE':
             r = requests.delete(self.build_url(resource), data=data, headers=headers, verify=self.verify)
          else:
             r = requests.get(self.build_url(resource), params=data, headers=headers, verify=self.verify)

          # Exit if there is an error.
          if r.status_code != 200:
             e = r.json()
             print e['error']
             sys.exit()

          # When downloading a scan we need the raw contents not the JSON data. 
          if 'download' in resource:
              return r.content
          else:
              return r.json()

      def login(self,usr, pwd):
          """
          Login to nessus.
          """
          login = {'username': usr, 'password': pwd}
          data = self.connect('POST', '/session', data=login)
          return data['token']

      def logout(self):
          """
          Logout of nessus.
          """
          self.connect('DELETE', '/session')

      def get_policies(self):
          """
          Get scan policies
          Get all of the scan policies but return only the title and the uuid of
          each policy.
          """
          data = self.connect('GET', '/editor/policy/templates')
          return dict((p['title'], p['uuid']) for p in data['templates'])

      def get_history_ids(self,sid):
          """
          Get history ids
          Create a dictionary of scan uuids and history ids so we can lookup the
          history id by uuid.
          """
          data = self.connect('GET', '/scans/{0}'.format(sid))
          return dict((h['uuid'], h['history_id']) for h in data['history'])

      def get_scan_history(self,sid, hid):
          """
          Scan history details
          Get the details of a particular run of a scan.
          """
          params = {'history_id': hid}
          data = self.connect('GET', '/scans/{0}'.format(sid), params)
          return data['info']

      def add(self,name, desc, targets, pid):
          """
          Add a new scan
          Create a new scan using the policy_id, name, description and targets. The
          scan will be created in the default folder for the user. Return the id of
          the newly created scan.
          """
          scan = {'uuid': pid,
                  'settings': {
                         'name': name,
                         'description': desc,
                         'text_targets': targets}
                 }
          data = self.connect('POST', '/scans', data=scan)
          return data['scan']['id']


      def launch(self,sid):
          """
          Launch a scan
          Launch the scan specified by the sid.
          """
          data = self.connect('POST', '/scans/{0}/launch'.format(sid))
          return data['scan_uuid']


      def status(self,sid, hid):
          """
          Check the status of a scan run
          Get the historical information for the particular scan and hid. Return
          the status if available. If not return unknown.
          """ 
          d = self.get_scan_history(sid, hid)
          return d['status']


      def export_status(self,sid, fid):
          """
          Check export status
          Check to see if the export is ready for download.
          """
          data = self.connect('GET', '/scans/{0}/export/{1}/status'.format(sid, fid))
          return data['status'] == 'ready'


      def export(self,sid, hid):
          """
          Make an export request
          Request an export of the scan results for the specified scan and
          historical run. In this case the format is hard coded as nessus but the
          format can be any one of nessus, html, pdf, csv, or db. Once the request
          is made, we have to wait for the export to be ready.
          """
          data = {'history_id': hid,
                  'format': 'nessus'}
          data = self.connect('POST', '/scans/{0}/export'.format(sid), data=data)
          fid = data['file']
          while self.export_status(sid, fid) is False:
                time.sleep(5)
          return fid

      def download(self,sid, fid):
          """
          Download the scan results
          Download the scan results stored in the export file specified by fid for
          the scan specified by sid.
          """
          data = self.connect('GET', '/scans/{0}/export/{1}/download'.format(sid, fid))
          filename = 'nessus_{0}_{1}.nessus'.format(sid, fid)
          print('Saving scan results to {0}.'.format(filename))
          with open(filename, 'w') as f:
               f.write(data)

      def delete(self,sid):
          """
          Delete a scan
          This deletes a scan and all of its associated history. The scan is not
          moved to the trash folder, it is deleted.
          """
          self.connect('DELETE', '/scans/{0}'.format(scan_id))


      def history_delete(self,sid, hid):
          """
          Delete a historical scan.
          This deletes a particular run of the scan and not the scan itself. the
          scan run is defined by the history id.
          """
          self.connect('DELETE', '/scans/{0}/history/{1}'.format(sid, hid))


if __name__ == '__main__':
    url = "https://127.0.0.1:8834"
    user = "username" 
    passw = "password"
    print ("Logging in")
    nes = nessus(url,user,passw)
    print('Adding new scan.')
    policies = nes.get_policies()
    policy_id = policies['Basic Network Scan']
    scan_id = nes.add('Test Scan', 'Create a new scan with API', '192.168.1.105', policy_id)
    print('Launching new scan.')
    scan_uuid = nes.launch(scan_id)
    history_ids = nes.get_history_ids(scan_id)
    history_id = history_ids[scan_uuid]
    while nes.status(scan_id, history_id) != 'completed':
        time.sleep(5)
    print('Exporting the completed scan.')
    file_id = nes.export(scan_id, history_id)
    nes.download(scan_id, file_id)
    print('Deleting the scan.')
    nes.history_delete(scan_id, history_id)
    nes.delete(scan_id)
    print('Logout')
    nes.logout()
