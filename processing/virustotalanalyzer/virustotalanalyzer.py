import os
import time
from urlparse import urljoin
from urllib import urlopen

try:
    import virustotal
    HAVE_VIRUSTOTAL = True
except ImportError:
    HAVE_VIRUSTOTAL = False

from fame.common.utils import tempdir
from fame.common.exceptions import ModuleInitializationError, ModuleExecutionError
from fame.core.module import ProcessingModule


class VirusTotalAnalyzer(ProcessingModule):
    name = "VirusTotalAnalyzer"
    description = "Submits file to VirusTotal to get scan reports."

    config = [
        {
            'name': 'api_key',
            'type': 'str',
            'default': 'Meowmix',
            'description': "API Key for VirusTotal"
        }
    ]

    def initialize(self):
        # Check dependencies
        if not HAVE_VIRUSTOTAL:
            raise ModuleInitializationError(self, "Missing dependency: virustotal")

    def each(self, target):
        v = virustotal.VirusTotal(self.api_key)
        vt_report = v.scan(target)
        vt_report.join()
        assert vt_report.done is True
        self.report.sha256 = vt_report.sha256
        self.report.hit_ratio = vt_report.positives / vt_report.total
        self.report.vt_scan_uid = vt_report.scan
       	positive_avs = []
	negative_avs = []
	for antivirus, malware in report:
	    antivirus = map(lambda x: x.encode("ascii", "ignore")
			    if x is not None else None, antivirus)
	    details = {
		"av_name": antivirus[0],
		"version": antivirus[1]
	    }
	    if malware is not None:
		details["malware_name"] = malware.encode("ascii") 
		positive_avs.append(details)
	    else:
		negative_avs.append(details)
	report.avs_reporting_positive = positive_avs
        report.avs_reporting_negative = negative_avs
        return True
