import requests
import xml.etree.ElementTree as ET
import urllib3
import getpass

# Disable SSL warnings for self-signed certs (common on firewalls)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class PaloAltoManager:
    def __init__(self, ip, username, password):
        self.ip = ip
        self.base_url = f"https://{ip}/api/"
        self.key = self._get_api_key(username, password)

    def _get_api_key(self, user, password):
        """Generates the API Key required for all other calls."""
        params = {
            "type": "keygen",
            "user": user,
            "password": password
        }
        try:
            response = requests.get(self.base_url, params=params, verify=False)
            response.raise_for_status()
            root = ET.fromstring(response.content)
            if root.get('status') == 'success':
                return root.find('.//key').text
            else:
                print("Error generating API Key: " + root.find('.//msg').text)
                exit()
        except Exception as e:
            print(f"Connection Failed: {e}")
            exit()

    def list_users(self):
        """Lists all admin users in the candidate config."""
        xpath = "/config/mgt-config/users"
        params = {
            "type": "config",
            "action": "get",
            "xpath": xpath,
            "key": self.key
        }
        response = requests.get(self.base_url, params=params, verify=False)
        root = ET.fromstring(response.content)
        
        print(f"\n--- Admin Users on {self.ip} ---")
        if root.get('status') == 'success':
            entries = root.findall('.//entry')
            if not entries:
                print("No users found (or insufficient permissions).")
            for entry in entries:
                name = entry.get('name')
                # Try to find permissions/role
                role = "Unknown"
                if entry.find('.//permissions/role-based/superuser') is not None:
                    role = "Superuser"
                print(f"- Username: {name} [{role}]")
        else:
            print("Error listing users.")

    def update_user_password(self, target_user, new_password):
        """Updates password. Also creates the user if they don't exist."""
        xpath = f"/config/mgt-config/users/entry[@name='{target_user}']"
        # We use action='edit' or 'set'. Set allows us to push the password element.
        # Note: Sending plain text password; Firewall will hash it upon commit.
        element = f"<password>{new_password}</password><permissions><role-based><superuser>yes</superuser></role-based></permissions>"
        
        params = {
            "type": "config",
            "action": "set",
            "xpath": xpath,
            "element": element,
            "key": self.key
        }
        
        response = requests.get(self.base_url, params=params, verify=False)
        root = ET.fromstring(response.content)
        if root.get('status') == 'success':
            print(f"\n[SUCCESS] User '{target_user}' password/permissions updated.")
            print("Note: This is a 'Candidate Config'. You must COMMIT for it to take effect.")
        else:
            msg = root.find('.//msg').text if root.find('.//msg') is not None else "Unknown error"
            print(f"\n[ERROR] Failed to update user: {msg}")

    def delete_user(self, target_user):
        """Deletes a specific admin user."""
        if target_user == 'admin':
            print("\n[WARNING] It is risky to delete the default 'admin' via script.")
            confirm = input("Are you sure? (y/n): ")
            if confirm.lower() != 'y': return

        xpath = f"/config/mgt-config/users/entry[@name='{target_user}']"
        params = {
            "type": "config",
            "action": "delete",
            "xpath": xpath,
            "key": self.key
        }
        
        response = requests.get(self.base_url, params=params, verify=False)
        root = ET.fromstring(response.content)
        if root.get('status') == 'success':
            print(f"\n[SUCCESS] User '{target_user}' marked for deletion.")
        else:
            msg = root.find('.//msg').text if root.find('.//msg') is not None else "Unknown error"
            print(f"\n[ERROR] Failed to delete: {msg}")

    def commit_changes(self):
        """Commits the candidate configuration to running configuration."""
        print("\nRequesting Commit (this may take a minute)...")
        params = {
            "type": "commit",
            "cmd": "<commit></commit>",
            "key": self.key
        }
        response = requests.get(self.base_url, params=params, verify=False)
        root = ET.fromstring(response.content)
        if root.get('status') == 'success':
            print("[SUCCESS] Commit job started. Changes are being applied.")
        else:
            print("[ERROR] Commit failed.")

# --- Main Interactive Menu ---
if __name__ == "__main__":
    fw_ip = input("Firewall IP: ")
    fw_user = input("Admin Username: ")
    fw_pass = getpass.getpass("Admin Password: ")

    pa = PaloAltoManager(fw_ip, fw_user, fw_pass)

    while True:
        print("\n--- Menu ---")
        print("1. List Users")
        print("2. Create/Update User Password")
        print("3. Delete User")
        print("4. Commit Changes")
        print("5. Exit")
        
        choice = input("Select an option: ")

        if choice == '1':
            pa.list_users()
        elif choice == '2':
            u = input("Enter username to update/create: ")
            p = getpass.getpass(f"Enter new password for {u}: ")
            pa.update_user_password(u, p)
        elif choice == '3':
            u = input("Enter username to DELETE: ")
            pa.delete_user(u)
        elif choice == '4':
            pa.commit_changes()
        elif choice == '5':
            break
