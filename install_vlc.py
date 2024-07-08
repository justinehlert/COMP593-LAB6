import requests as req
import hashlib as hash
import os
import subprocess
import re

installerURL = 'https://download.videolan.org/pub/videolan/vlc/3.0.17.4/win64/vlc-3.0.17.4-win64.exe'

def main():

    
    # Get the expected SHA-256 hash value of the VLC installer
    expected_sha256 = get_expected_sha256()

    # Download (but don't save) the VLC installer from the VLC website
    installer_data = download_installer()

    # Verify the integrity of the downloaded VLC installer by comparing the
    # expected and computed SHA-256 hash values
    if installer_ok(installer_data, expected_sha256):

        # Save the downloaded VLC installer to disk
        installer_path = save_installer(installer_data)

        # Silently run the VLC installer
        run_installer(installer_path)

        # Delete the VLC installer from disk
        delete_installer(installer_path)

def get_expected_sha256():
    """Downloads the text file containing the expected SHA-256 value for the VLC installer file from the 
    videolan.org website and extracts the expected SHA-256 value from it.

    Returns:
        str: Expected SHA-256 hash value of VLC installer
    """
    #Step 1: Using the file URL to get a response message
    fileUrl = 'https://download.videolan.org/pub/videolan/vlc/3.0.17.4/win64/vlc-3.0.17.4-win64.exe.sha256'
    respMsg = req.get(fileUrl)
    #If a response is received from the site extract the SHA-256 from the file
    if checkResponseCode(respMsg):
        fileContent = respMsg.content
        pattern = r'\b([a-fA-F0-9]{64})\b'
        match = re.search(pattern, str(fileContent))
        shaHash = match.group(1)
    return shaHash

def download_installer():
    """Downloads, but does not save, the .exe VLC installer file for 64-bit Windows.

    Returns:
        bytes: VLC installer file binary data
    """
    #Step 2

    respMsg = req.get(installerURL)
    # If response is received download the VLC installer file
    if checkResponseCode(respMsg):
        fileContent = respMsg.content

    return fileContent

def installer_ok(installer_data, expected_sha256):
    """Verifies the integrity of the downloaded VLC installer file by calculating its SHA-256 hash value 
    and comparing it against the expected SHA-256 hash value. 

    Args:
        installer_data (bytes): VLC installer file binary data
        expected_sha256 (str): Expeced SHA-256 of the VLC installer

    Returns:
        bool: True if SHA-256 of VLC installer matches expected SHA-256. False if not.
    """    
    #Step 3: Calculating the has based off the installer data. Comparing that hash to the expected one
    #and returning the results as a boolean value

    installedHash = hash.sha256(installer_data).hexdigest()
    return True if installedHash == expected_sha256 else False

def save_installer(installer_data):
    """Saves the VLC installer to a local directory.

    Args:
        installer_data (bytes): VLC installer file binary data

    Returns:
        str: Full path of the saved VLC installer file
    """
    #Step 4: Save the installer to a Temp file path
    # TODO: Review if this works at the end
    filePath = r'C:\Windows\Temp\VLCinstaller.exe'
    with open(filePath, 'wb') as file:
        file.write(installer_data)
    return filePath

def run_installer(installer_path):
    """Silently runs the VLC installer.

    Args:
        installer_path (str): Full path of the VLC installer file
    """    
    # TODO: Step 5
    # Hint: See example code in lab instructions entitled "Running the VLC Installer"
    return
    
def delete_installer(installer_path):
    # TODO: Step 6
    # Hint: See example code in lab instructions entitled "Running the VLC Installer"
    """Deletes the VLC installer file.

    Args:
        installer_path (str): Full path of the VLC installer file
    """
    return

def checkResponseCode(respMsg):
    """Checks for a response code from the target URL
    
    Args:
        respMsg (Response): Response object from a get request
    """
    return True if respMsg.status_code == req.codes.ok else False


if __name__ == '__main__':
    main()