import requests
import json
import urllib3
import getpass

# Disable SSL warnings (FTD uses self-signed certs by default)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class FirepowerManager:
    def __init__(self, ip, username, password):
        self.ip = ip
        self.base_url = f"https://{ip}/api/fdm/latest"
        self.token = self._get_auth_token(username, password)

    def _get_auth_token(self, username, password):
        """Authenticates and retrieves the OAuth token."""
        url = f"{self.base_url}/fdm/token"
        payload = {
            "grant_type": "password",
            "username": username,
            "password": password
        }
        try:
            response = requests.post(url, json=payload, verify=False)
            response.raise_for_status()
            # FTD returns an access_token inside the response
            return response.json().get('access_token')
        except Exception as e:
            print(f"[FATAL] Login Failed: {e}")
            exit()

    def _get_headers(self):
        return {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json"
        }

    def list_users(self):
        """Lists all system users."""
        url = f"{self.base_url}/devicesettings/default/sysusers"
        response = requests.get(url, headers=self._get_headers(), verify=False)
        
        if response.status_code == 200:
            users = response.json().get('items', [])
            print(f"\n--- FTD System Users on {self.ip} ---")
            for user in users:
                print(f"- Name: {user['name']} | Role: {user['role']} | ID: {user['id']}")
            return users
        else:
            print(f"[ERROR] Could not list users: {response.text}")
            return []

    def create_user(self, username, password, role="READ_ONLY"):
        """Creates a new user. Role can be ADMIN, READ_ONLY, or READ_WRITE."""
        url = f"{self.base_url}/devicesettings/default/sysusers"
        payload = {
            "name": username,
            "password": password,
            "role": role,
            "type": "sysuser"
        }
        
        response = requests.post(url, headers=self._get_headers(), json=payload, verify=False)
        if response.status_code == 200:
            print(f"[SUCCESS] User '{username}' created successfully.")
        else:
            print(f"[ERROR] Creation failed: {response.text}")

    def change_password(self, username, new_password):
        """Updates the password for an existing user."""
        # 1. We must find the User ID (UUID) first
        all_users = self.list_users()
        target_user_obj = next((u for u in all_users if u['name'] == username), None)
        
        if not target_user_obj:
            print(f"[ERROR] User '{username}' not found.")
            return

        user_id = target_user_obj['id']
        current_role = target_user_obj['role']
        
        # 2. Perform the PUT request to update
        url = f"{self.base_url}/devicesettings/default/sysusers/{user_id}"
        
        # FTD API requires re-sending the existing properties (like name/role) along with the new password
        payload = {
            "id": user_id,
            "name": username,
            "password": new_password,
            "role": current_role,
            "type": "sysuser"
        }

        response = requests.put(url, headers=self._get_headers(), json=payload, verify=False)
        if response.status_code == 200:
            print(f"[SUCCESS] Password for '{username}' updated.")
        else:
            print(f"[ERROR] Update failed: {response.text}")

    def delete_user(self, username):
        """Deletes a user by name."""
        if username == 'admin':
            print("[STOP] You cannot delete the default 'admin' user.")
            return

        all_users = self.list_users()
        target_user_obj = next((u for u in all_users if u['name'] == username), None)
        
        if not target_user_obj:
            print(f"[ERROR] User '{username}' not found.")
            return

        user_id = target_user_obj['id']
        url = f"{self.base_url}/devicesettings/default/sysusers/{user_id}"
        
        response = requests.delete(url, headers=self._get_headers(), verify=False)
        if response.status_code == 204:
            print(f"[SUCCESS] User '{username}' deleted.")
        else:
            print(f"[ERROR] Delete failed: {response.text}")

    def deploy_changes(self):
        """Deploys the changes to the device (Commit)."""
        # Unlike PA, FTD requires a separate deployment job
        print("\nChecking for pending changes...")
        url = f"{self.base_url}/operational/deploy"
        response = requests.post(url, headers=self._get_headers(), json={}, verify=False)
        
        if response.status_code == 200:
            print("[SUCCESS] Deployment job started. Changes are being applied.")
        else:
            print(f"[ERROR] Deployment failed: {response.text}")


# --- Interactive Menu ---
if __name__ == "__main__":
    ftd_ip = input("FTD IP Address: ")
    ftd_user = input("Admin Username: ")
    ftd_pass = getpass.getpass("Admin Password: ")

    ftd = FirepowerManager(ftd_ip, ftd_user, ftd_pass)

    while True:
        print("\n--- Cisco FTD User Manager ---")
        print("1. List Users")
        print("2. Create New User")
        print("3. Change User Password")
        print("4. Delete User")
        print("5. Deploy Changes (Commit)")
        print("6. Exit")
        
        choice = input("Select: ")

        if choice == '1':
            ftd.list_users()
        elif choice == '2':
            u = input("New Username: ")
            p = getpass.getpass("New Password: ")
            r = input("Role (ADMIN, READ_ONLY, READ_WRITE): ").upper()
            ftd.create_user(u, p, r)
        elif choice == '3':
            u = input("Username to update: ")
            p = getpass.getpass("New Password: ")
            ftd.change_password(u, p)
        elif choice == '4':
            u = input("Username to DELETE: ")
            ftd.delete_user(u)
        elif choice == '5':
            ftd.deploy_changes()
        elif choice == '6':
            break
