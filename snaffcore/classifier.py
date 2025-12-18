import re
import toml
import os
import logging
# import pprint
import termcolor

from impacket.smbconnection import SessionError, SMBConnection
from .smb import *
from .file_handling import *

log = logging.getLogger('snafflepy.classifier')

# TODO


class Rules:

    def __init__(self) -> None:
        self.classifier_rules = []
        self.share_classifiers = []
        self.directory_classifiers = []
        self.file_classifiers = []
        self.contents_classifiers = []
        self.postmatch_classifiers = []

    def prepare_classifiers(self):
        share_path = "./snaffcore/DefaultRules/"

        for root, dirs, files in os.walk(share_path, topdown=False):
            for name in files:
                # print(os.path.join(root,name))
                with open(os.path.join(root, name), 'r') as tfile:
                    toml_loaded = toml.load(tfile)
                for dict_rule in toml_loaded['ClassifierRules']:
                    if dict_rule['EnumerationScope'] == "ShareEnumeration":
                        self.share_classifiers.append(dict_rule)
                    elif dict_rule['EnumerationScope'] == "FileEnumeration":
                        self.file_classifiers.append(dict_rule)
                    elif dict_rule['EnumerationScope'] == "DirectoryEnumeration":
                        self.directory_classifiers.append(dict_rule)
                    elif dict_rule['EnumerationScope'] == "PostMatch":
                        self.postmatch_classifiers.append(dict_rule)
                    elif dict_rule['EnumerationScope'] == "ContentsEnumeration":
                        self.contents_classifiers.append(dict_rule)
                    else:
                        log.warning(
                            f"{dict_rule['RuleName']} is invalid, please check your syntax!")

# TODO


def is_interest_file(file, smb_client, share, no_download: bool, json_output=False):
    backup_ext_list = [".bak", ".mdf", ".sqldump", ".sdf", ".dmp"]
    cred_list = ["creds", "password", "passw", "credentials", "login", "secret", "account", "pass",
                 ".kdb", ".psafe3", ".kwallet", ".keychain", ".agilekeychain", ".cred"]

    ssn_regex = str("^\d{{3}}-\d{{2}}-\d{{4}}$")
    is_interest = False

    # Non-file shares
    # if str(share).lower().find("ipc") or str(share).lower().find("print"):
    #     pass
    # else:

    # MVP Build only, check for SSN in files

    # MVP Build only, check for backup files
    for ext in backup_ext_list:
        if re.search(str(ext), str(file.name).lower()):
            is_interest = True
            file_triage = f"\\\\{file.target}\\{share}\\{file.name} <KeepBackupFiles>"
            
            result_entry = {
                "type": "backup_file",
                "target": file.target,
                "share": share,
                "filename": file.name,
                "size": file.size,
                "action": "backup_file_found"
            }
            
            # Add to global results list if JSON output is requested
            if json_output:
                json_results.append(result_entry)
                
            try:
                if not no_download:
                    file.get(smb_client)
                log.info(f"[File] {file_triage}")
            except FileRetrievalError as e:
                file.handle_download_error(file.name, e, False, False)

    # MVP Build only, check for files with possible passwords contained inside
    for cred in cred_list:
        if re.search(str(cred), str(file.name).lower()):
            is_interest = True

            file_triage = f"\\\\{file.target}\\{share}\\{file.name} <KeepFilesWithInterestName>"
            
            result_entry = {
                "type": "credential_file",
                "target": file.target,
                "share": share,
                "filename": file.name,
                "size": file.size,
                "action": "credential_file_found"
            }
            
            # Add to global results list if JSON output is requested
            if json_output:
                json_results.append(result_entry)
                
            try:
                if not no_download:
                    file.get(smb_client)
                log.info(f"[File] {file_triage}")
            except FileRetrievalError as e:
                file.handle_download_error(file.name, e, False, False)

    # Only check content when download is enabled
    if not no_download:
        file_data = ""
        try:
            file.get(smb_client)
            with open(str(file.tmp_filename), 'rb') as f:
                file_data = str(f.read(10000))
                if re.search(ssn_regex, file_data):
                    file_triage = f"\\\\{file.target}\\{share}\\{file.name} <SsnRegexFound>"
                    
                    result_entry = {
                        "type": "ssn_file",
                        "target": file.target,
                        "share": share,
                        "filename": file.name,
                        "size": file.size,
                        "action": "ssn_found"
                    }
                    
                    # Add to global results list if JSON output is requested
                    if json_output:
                        json_results.append(result_entry)
                        
                    log.info(f"[File] {file_triage}")
                elif not is_interest:
                    # print(file.name)
                    os.remove(f"./{file.tmp_filename}")
        except FileRetrievalError as e:
            os.remove(f"./{file.tmp_filename}")
            file.handle_download_error(file.name, e, False, False)
    else:
        # When no download is requested, we still want to log filename-based matches
        # but don't do content analysis since we can't read the file
        if not is_interest and json_output:
            # For files that aren't already marked as interesting by name,
            # add them to results when JSON output is enabled (even without download)
            result_entry = {
                "type": "file",
                "target": file.target,
                "share": share,
                "filename": file.name,
                "size": file.size,
                "action": "no_download_file"
            }
            json_results.append(result_entry)

    # If we're not in JSON mode, still do the logging for non-interest files
    if not json_output and not is_interest:
        pass  # This was already handled by the original logic
