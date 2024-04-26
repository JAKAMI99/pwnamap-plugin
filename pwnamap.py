import os
import logging
import requests
from datetime import datetime
from threading import Lock
from pwnagotchi.utils import StatusFile, remove_whitelisted
from pwnagotchi import plugins
from json.decoder import JSONDecodeError

class pwnamap(plugins.Plugin):
    __author__ = 'Original: adi1708, modified by JAKAMI99'
    __version__ = '1.0.0'
    __license__ = 'GPL3'
    __description__ = 'This plugin automatically uploads handshakes to /api/upload of your pwnamap instance'

    def __init__(self):
        self.ready = False
        self.lock = Lock()
        try:
            self.report = StatusFile('/root/.pwnamap_uploads', data_format='json')
        except JSONDecodeError:
            os.remove("/root/.pwnamap_uploads")
            self.report = StatusFile('/root/.pwnamap_uploads', data_format='json')
        self.options = dict()
        self.skip = list()

    def _upload_to_pwnamap(self, path, timeout=30):
        """
        Uploads the file to the specified endpoint.
        """
        # Modify the API URL to include the specific endpoint
        api_url = f"{self.options['api_url']}:{self.options['api_port']}/api/upload"

        headers = {
            'Authorization': f'Bearer {self.options.get("api_key")}'
        }

        with open(path, 'rb') as file_to_upload:
            payload = {'file': file_to_upload}

            try:
                result = requests.post(api_url, files=payload, headers=headers, timeout=timeout)

                if 'already submitted' in result.text:
                    logging.debug("%s was already submitted.", path)

            except requests.exceptions.RequestException as req_e:
                raise req_e

    def on_loaded(self):
        """
        This method is called when the plugin gets loaded.
        """

        if 'api_url' not in self.options or not self.options['api_url']:
            logging.error("pwnamap: API-URL isn't set. Can't upload, no endpoint configured.")
            return
        
        if 'api_port' not in self.options or not self.options['api_port']:
            logging.error("pwnamap: API-Port isn't set. Can't upload, no endpoint port configured.")
            return

        if 'api_key' not in self.options or not self.options['api_key']:
            logging.error("pwnamap: API-Key isn't set. Can't authenticate.")
            return
        
        if 'whitelist' not in self.options:
            self.options['whitelist'] = list()

        self.ready = True
        logging.info("pwnamap: plugin loaded")

    def on_internet_available(self, agent):
        """
        Called when there's internet connectivity in manual mode.
        """
        if not self.ready or self.lock.locked():
            return

        with self.lock:
            config = agent.config()
            display = agent.view()
            handshake_dir = config['bettercap']['handshakes']

            handshake_files = os.listdir(handshake_dir)

            handshake_paths = [os.path.join(handshake_dir, file) for file in handshake_files if file.endswith('.pcap')]
            handshake_paths = remove_whitelisted(handshake_paths, self.options['whitelist'])

            handshake_new = set(handshake_paths) - set(self.skip)

            if handshake_new:
                logging.info("pwnamap: Uploading new handshakes to %s", self.options.api_url)

                for idx, handshake in enumerate(handshake_new):
                    display.on_uploading(f"Uploading ({idx + 1}/{len(handshake_new)})")

                    try:
                        self._upload_to_pwnamap(handshake)
                        logging.debug("pwnamap: Successfully uploaded %s", handshake)

                    except requests.exceptions.RequestException as req_e:
                        self.skip.append(handshake)
                        logging.debug("pwnamap: %s", req_e)
                        continue

                    except OSError as os_e:
                        logging.debug("pwnamap: %s", os_e)
                        continue

                display.on_normal()
