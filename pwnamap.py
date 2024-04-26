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

    def _upload_to_pwnamap(self, file_path, timeout=30):
        """
        Uploads the file to the specified endpoint.
        """

        # Remove trailing slash if it exists
        api_url = self.options["api_url"].rstrip("/")
        
        # Construct the full API URL with port and endpoint
        full_api_url = f"{api_url}:{self.options['api_port']}/api/upload"

        headers = {
            "X-API-KEY": self.options.get("api_key")
        }

        with open(file_path, 'rb') as file_to_upload:
            payload = {'file': file_to_upload}

            try:
                result = requests.post(full_api_url, files=payload, headers=headers, timeout=timeout)

                if result.status_code == 200:
                    if 'already submitted' in result.text:
                        logging.info("%s was already submitted.", file_path)
                else:
                    logging.error("Upload failed with status: %s", result.status_code)
                    raise requests.exceptions.RequestException(f"Upload failed: {result.text}")

            except requests.exceptions.RequestException:
              raise



    def on_loaded(self):
        """
        Gets called when the plugin gets loaded
        """
        if 'api_key' not in self.options or ('api_key' in self.options and not self.options['api_key']):
            logging.error("pwnamap: API-KEY isn't set. Can't upload to pwnamap")
            return
        if 'api_port' not in self.options or not self.options['api_port']:
            logging.error("pwnamap: API-Port isn't set. Can't upload, no endpoint port configured.")
            return
        if 'api_url' not in self.options or ('api_url' in self.options and not self.options['api_url']):
            logging.error("pwnamap: API-URL isn't set. Can't upload, no endpoint configured.")
            return

        self.ready = True
        logging.info("pwnamap: plugin loaded")

    def on_webhook(self, path, request):
        from flask import make_response, redirect
        response = make_response(redirect(self.options['api_url'], code=302))
        response.set_cookie('key', self.options['api_key'])
        return response

    def on_internet_available(self, agent):
        """
        Called in manual mode when there's internet connectivity
        """
        if not self.ready or self.lock.locked():
            return

        with self.lock:
            config = agent.config()
            display = agent.view()
            reported = self.report.data_field_or('reported', default=list())
            handshake_dir = config['bettercap']['handshakes']
            handshake_filenames = os.listdir(handshake_dir)
            handshake_paths = [os.path.join(handshake_dir, filename) for filename in handshake_filenames if filename.endswith('.pcap')]
            handshake_paths = remove_whitelisted(handshake_paths, config['main']['whitelist'])
            handshake_new = set(handshake_paths) - set(reported) - set(self.skip)

            if handshake_new:
                logging.info("pwnamap: Internet connectivity detected. Uploading new handshakes to your pwnamap")
                for idx, handshake in enumerate(handshake_new):
                    display.on_uploading(f"pwnamap ({idx + 1}/{len(handshake_new)})")

                    try:
                        self._upload_to_pwnamap(handshake)
                        reported.append(handshake)
                        self.report.update(data={'reported': reported})
                        logging.debug("pwnamap: Successfully uploaded %s", handshake)
                    except requests.exceptions.RequestException as req_e:
                        self.skip.append(handshake)
                        logging.debug("pwnamap: %s", req_e)
                        continue
                    except OSError as os_e:
                        logging.debug("pwnamap: %s", os_e)
                        continue

                display.on_normal()

