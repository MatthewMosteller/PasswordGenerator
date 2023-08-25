import json
import getpass
import secrets
import click
from cryptography.fernet import Fernet
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64

# Function to generate a strong password
def _generate_password(length=16):
    alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_-+=<>?"
    password = ''.join(secrets.choice(alphabet) for i in range(length))
    return password

def _generate_fernet_key(passphrase:str, salt:str, iterations:int) -> str:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        iterations=iterations,
        salt=salt,
        length=32
    )
    key = base64.urlsafe_b64encode(kdf.derive(passphrase.encode('utf-8')))
    return key

@click.command()
def list_apps():
  try:
    with open(f"app_list.txt", "r") as user_file:
      print(user_file.read())
  except FileNotFoundError:
    print('No apps yet.')

@click.command()
@click.option('--user')
@click.option('--password')
def create_user(user, password):
  salt = b"saltysalt"  # Salt should be unique for each passphrase
  iterations = 100000  # Number of iterations for the PBKDF2 key derivation

  # Generate a Fernet key from the passphrase using PBKDF2
  key = _generate_fernet_key(password, salt, iterations)

  with open(f"{user}.key", "wb") as key_file:
    key_file.write(key)

def authenticate_user(user, passphrase):
  with open(f"{user}.key", "rb") as user_file:
    key = user_file.read()
    if _generate_fernet_key(passphrase, 'helloworld', 1000) == key:
       return key
  return None

@click.command()
def create_new_password():
  # Get user input
  app_name = input("Enter the app name: ")
  username = input("Enter the username: ")
  password_length = int(input("Enter the desired password length (default is 16): ") or 16)

  # Generate a strong password
  password = _generate_password(password_length)

  # Create a JSON object
  data = {
      "app_name": app_name,
      "username": username,
      "password": password
  }

  # Convert data to JSON format
  json_data = json.dumps(data, indent=4)

  # Encrypt the JSON data
  with open("app_list.txt", "a") as app_list_file, \
      open(f"{app_name}.bin", "wb") as data_file, \
      open("encryption.key", "a+") as read_key_file, \
      open("encryption.key", "wb") as write_key_file:
    encryption_password = read_key_file.read()
    if not encryption_password:
      encryption_password = Fernet.generate_key()
      write_key_file.write(encryption_password)

    cipher_suite = Fernet(encryption_password)
    encrypted_data = cipher_suite.encrypt(json_data.encode())
    app_list_file.write(app_name + "\n")
    data_file.write(encrypted_data)
  print(f"Data encrypted and saved: {json_data}.")

@click.command()
def get_password():
    print('App Names: \n')
    with open("app_list.txt", "r") as app_list_file:
      print(app_list_file.read())
    app_name = input("Enter the app name to retrieve information: ")
    try:
        with open("encryption.key", "rb") as key_file, open(f"{app_name}.bin", "rb") as data_file:
          encryption_key = key_file.read()
          cipher_suite = Fernet(encryption_key)
          encrypted_data = data_file.read()
          decrypted_data = cipher_suite.decrypt(encrypted_data).decode()
          app_data = json.loads(decrypted_data)
          
          print(app_data)

    except Exception as e:
        return None, None

@click.group()
def main():
    pass

main.add_command(create_user, name='create-user')
main.add_command(create_new_password, name='create')
main.add_command(list_apps, name='list-apps')
main.add_command(get_password, name='get')

if __name__ == "__main__":
    main()