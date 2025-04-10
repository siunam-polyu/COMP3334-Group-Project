import requests
import os
# import pyotp
import hashlib
import json
from typing import Dict, List, Optional
import base64
import getpass

class Client:
    def __init__(self, server_url='http://localhost:5000'):
        self.server_url = server_url
        self.token = None
        self.logged_in = False
        self.temp_token = None
        self.mfa_secret = None
        self.file_hashes = {}
        self.chunk_size = 1024 * 1024  # 1MB chunks for efficient updates
    
    def register(self):
        username = input('Enter username: ')
        password = getpass.getpass('Enter password: ')
        
        try:
            response = requests.post(f'{self.server_url}/register', json={
                'username': username,
                'password': password
            })
            
            if response.status_code == 201:
                print('Success: User registered successfully')
            else:
                error_msg = response.json().get('error', 'Registration failed')
                print(f'Error: {error_msg}')
        except requests.exceptions.RequestException as e:
            print(f'Error: Could not connect to server - {str(e)}')
        except json.JSONDecodeError:
            print('Error: Invalid response from server')
    
    def setup_mfa(self):
        """Setup MFA for the user."""
        if not self.token:
            print("Please login first")
            return
        
        try:
            response = requests.post(
                f'{self.server_url}/setup-mfa',
                headers={'Authorization': self.token}
            )
            
            if response.status_code == 200:
                data = response.json()
                self.mfa_secret = data['secret']
                
                # Save QR code to file
                with open('mfa_qr.png', 'wb') as f:
                    f.write(base64.b64decode(data['qr_code']))
                
                print("\nMFA setup successful!")
                print("A QR code has been saved as 'mfa_qr.png'")
                print("Please scan this QR code with your authenticator app (like Google Authenticator)")
                print(f"Or manually enter this secret key: {self.mfa_secret}")
            else:
                print(f"Error: {response.json().get('error', 'MFA setup failed')}")
        except requests.exceptions.RequestException as e:
            print(f"Error: Connection failed - {e}")
        except json.JSONDecodeError:
            print("Error: Invalid response from server")
        except Exception as e:
            print(f"Error: {str(e)}")
    
    def verify_mfa(self, mfa_code):
        if not self.temp_token:
            return {'error': 'No pending MFA verification'}
        
        headers = {'Authorization': self.temp_token}
        response = requests.post(f'{self.server_url}/verify-mfa',
                               json={'mfa_code': mfa_code},
                               headers=headers)
        if response.status_code == 200:
            self.token = self.temp_token
            self.temp_token = None
            self.logged_in = True
        return response.json()
    
    def login(self):
        username = input('Enter username: ')
        password = getpass.getpass('Enter password: ')
        
        response = requests.post(f'{self.server_url}/login', json={
            'username': username,
            'password': password
        })
        
        if response.status_code == 200:
            data = response.json()
            if 'temp_token' in data:
                print('MFA is required. Please enter the code from your authenticator app.')
                mfa_code = input('Enter MFA code: ')
                self.verify_mfa(mfa_code)
            else:
                self.token = data['token']
                self.logged_in = True
                print('Success: Logged in successfully')
        else:
            print(f'Error: {response.json().get("error", "Login failed")}')
    
    def calculate_file_hash(self, filepath: str) -> str:
        """Calculate SHA-256 hash of a file."""
        sha256_hash = hashlib.sha256()
        with open(filepath, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    
    def upload_file(self):
        """Upload a file to the server."""
        filepath = input('Enter file path: ')
        
        if not os.path.exists(filepath):
            print('Error: File does not exist')
            return
        
        try:
            with open(filepath, 'rb') as f:
                files = {'file': f}
                headers = {'Authorization': self.token}
                response = requests.post(f'{self.server_url}/upload', files=files, headers=headers)
                
                if response.status_code == 201:
                    data = response.json()
                    print(f'Success: File uploaded successfully')
                    print(f'File ID: {data["file_id"]}')
                    print(f'Filename: {data["filename"]}')
                else:
                    print(f'Error: {response.text}')
        except requests.exceptions.RequestException as e:
            print(f'Error: Could not connect to server - {str(e)}')
        except Exception as e:
            print(f'Error: {str(e)}')
    
    def update_file_chunk(self, filepath, start_offset, chunk_data):
        """Update a specific chunk of a file."""
        if not self.token:
            print("Please login first")
            return

        try:
            response = requests.post(
                f"{self.server_url}/update-chunk",
                headers={'Authorization': self.token},
                json={
                    'filepath': filepath,
                    'start_offset': start_offset,
                    'chunk_data': base64.b64encode(chunk_data).decode()
                }
            )
            if response.status_code != 200:
                print("Error updating file chunk")
                return

            print("File chunk updated successfully")
            # Update local file hash
            self.calculate_file_hash(filepath)

        except Exception as e:
            print(f"Error: {str(e)}")
    
    def download_file(self):
        """Download a file from the server."""
        try:
            # First, get the list of available files
            headers = {'Authorization': self.token}
            response = requests.get(f'{self.server_url}/files', headers=headers)
            
            if response.status_code == 200:
                files = response.json()
                if not files:
                    print('No files available for download.')
                    return
                
                print('\nAvailable files:')
                print('ID | Filename | Created At')
                print('-' * 50)
                for file in files:
                    print(f"{file['id']} | {file['filename']} | {file['created_at']}")
                
                file_id = input('\nEnter file ID to download: ')
                try:
                    file_id = int(file_id)
                except ValueError:
                    print('Error: Please enter a valid file ID (number)')
                    return
                
                # Download the file
                response = requests.get(
                    f'{self.server_url}/download/{file_id}',
                    headers=headers,
                    stream=True
                )
                
                if response.status_code == 200:
                    # Get filename from Content-Disposition header or use a default
                    content_disposition = response.headers.get('content-disposition')
                    if content_disposition:
                        filename = content_disposition.split('filename=')[1].strip('"')
                    else:
                        filename = f'downloaded_file_{file_id}'
                    
                    # Save the file
                    with open(filename, 'wb') as f:
                        for chunk in response.iter_content(chunk_size=8192):
                            if chunk:
                                f.write(chunk)
                    
                    print(f'Success: File downloaded as {filename}')
                else:
                    print(f'Error: {response.text}')
            else:
                print(f'Error: {response.text}')
        except requests.exceptions.RequestException as e:
            print(f'Error: Could not connect to server - {str(e)}')
        except Exception as e:
            print(f'Error: {str(e)}')
    
    def share_file(self):
        file_id = input('Enter file ID: ')
        username = input('Enter username to share with: ')
        
        response = requests.post(
            f'{self.server_url}/share',
            headers={'Authorization': self.token},
            json={'file_id': file_id, 'username': username}
        )
        
        if response.status_code == 200:
            print('Success: File shared successfully')
        else:
            print(f'Error: {response.json().get("error", "Sharing failed")}')
    
    def reset_password(self):
        """Reset user's password."""
        new_password = getpass.getpass('Enter new password: ')
        
        try:
            response = requests.post(
                f'{self.server_url}/reset-password',
                headers={'Authorization': self.token},
                json={'new_password': new_password}
            )
            
            if response.status_code == 200:
                print('Success: Password reset successfully')
            else:
                print(f'Error: {response.json().get("error", "Password reset failed")}')
        except requests.exceptions.RequestException as e:
            print(f'Error: Connection failed - {e}')
        except json.JSONDecodeError:
            print('Error: Invalid response from server')

    def list_file_versions(self, filepath):
        """List all versions of a file."""
        if not self.token:
            print("Please login first")
            return

        try:
            # Get file ID first
            response = requests.get(
                f"{self.server_url}/files",
                headers={'Authorization': self.token}
            )
            if response.status_code != 200:
                print("Error getting file list")
                return

            files = response.json()
            file_id = None
            for file in files:
                if file['filename'] == filepath:
                    file_id = file['id']
                    break

            if not file_id:
                print("File not found")
                return

            # Get versions
            response = requests.get(
                f"{self.server_url}/file-versions/{file_id}",
                headers={'Authorization': self.token}
            )
            if response.status_code != 200:
                print("Error getting file versions")
                return

            versions = response.json()
            if not versions:
                print("No versions found")
                return

            print(f"\nVersions for {filepath}:")
            for version in versions:
                print(f"Version {version['id']} - Created at: {version['created_at']}")

        except Exception as e:
            print(f"Error: {str(e)}")

    def restore_file_version(self, filepath, version_id):
        """Restore a specific version of a file."""
        if not self.token:
            print("Please login first")
            return

        try:
            # Get file ID first
            response = requests.get(
                f"{self.server_url}/files",
                headers={'Authorization': self.token}
            )
            if response.status_code != 200:
                print("Error getting file list")
                return

            files = response.json()
            file_id = None
            for file in files:
                if file['filename'] == filepath:
                    file_id = file['id']
                    break

            if not file_id:
                print("File not found")
                return

            # Restore version
            response = requests.post(
                f"{self.server_url}/restore-version/{file_id}/{version_id}",
                headers={'Authorization': self.token}
            )
            if response.status_code != 200:
                print("Error restoring file version")
                return

            print("File version restored successfully")
            # Update local file hash
            self.calculate_file_hash(filepath)

        except Exception as e:
            print(f"Error: {str(e)}")

    def print_menu(self):
        """Print the menu with all available options."""
        print("\nSecure File Storage System")
        print("1. Register")
        print("2. Login")
        print("3. Setup MFA")
        print("4. Upload File")
        print("5. Download File")
        print("6. Share File")
        print("7. List Files")
        print("8. List File Versions")
        print("9. Restore File Version")
        print("10. Reset Password")
        print("11. Logout")
        print("0. Exit")

    def main(self):
        """Main client loop."""
        while True:
            self.print_menu()
            choice = input("\nEnter your choice: ")

            if choice == '1':
                self.register()
            elif choice == '2':
                self.login()
            elif choice == '3':
                if self.token:
                    result = self.setup_mfa()
                    if 'error' in result:
                        print("\nError:", result['error'])
                    else:
                        print("\nSuccess:", result.get('message', 'MFA setup successful'))
                else:
                    print("Please login first")
            elif choice == '4':
                self.upload_file()
            elif choice == '5':
                self.download_file()
            elif choice == '6':
                self.share_file()
            elif choice == '7':
                self.list_files()
            elif choice == '8':
                filepath = input("Enter file path: ")
                self.list_file_versions(filepath)
            elif choice == '9':
                filepath = input("Enter file path: ")
                version_id = int(input("Enter version ID to restore: "))
                self.restore_file_version(filepath, version_id)
            elif choice == '10':
                self.reset_password()
            elif choice == '11':
                self.logout()
            elif choice == '0':
                break
            else:
                print("Invalid choice")

def print_menu(is_logged_in):
    print("\n=== Secure File Storage System ===")
    if not is_logged_in:
        print("1. Register")
        print("2. Login")
        print("3. Exit")
    else:
        print("1. Upload File")
        print("2. Download File")
        print("3. Share File")
        print("4. Reset Password")
        print("5. Setup MFA")
        print("6. Logout")
        print("7. Exit")

def main():
    client = Client()
    
    while True:
        print_menu(client.logged_in)
        
        if not client.logged_in:
            choice = input("\nEnter your choice (1-3): ")
            
            if choice == '1':
                client.register()
            
            elif choice == '2':
                client.login()
            
            elif choice == '3':
                print("\nGoodbye!")
                break
            
            else:
                print("\nInvalid choice!")
        
        else:
            choice = input("\nEnter your choice (1-7): ")
            
            if choice == '1':
                client.upload_file()
            
            elif choice == '2':
                client.download_file()
            
            elif choice == '3':
                client.share_file()
            
            elif choice == '4':
                client.reset_password()
            
            elif choice == '5':
                client.setup_mfa()
            
            elif choice == '6':
                client.logged_in = False
                client.token = None
                print("\nSuccess: Logged out successfully!")
            
            elif choice == '7':
                print("\nGoodbye!")
                break
            
            else:
                print("\nError: Invalid choice!")

if __name__ == '__main__':
    main()